#!/usr/bin/env python3
"""Run one image live through Porygon for one hour and record every test window.

  30 min learning (normal load + 2 restarts) -> baseline build + activate
  30 x 60 s test windows in a seeded order: 12 normal, 6 hard negative, 12 abnormal

Ground truth for every window is written to status.json before the test phase
starts. Every score, rule match and incident comes from Porygon's own API, and
every process event from Porygon's own database. Nothing is filled in: a window
that cannot be scored or detected is recorded as failed with its error.

Resumable: windows marked done in datasets/runtime/raw/<image>/status.json are
never redone or overwritten.

--batch records which collection batch the run belongs to (default "batch1", so
batch 1's records are unchanged). A batch other than batch1 labels its
containers "porygon.runtime=<batch>-<run_id>" and stores "batch" in status.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import queue
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rt_common  # noqa: E402
from drivers import make_driver, ping  # noqa: E402
from recipes import GO_SOURCE, RECIPES  # noqa: E402
from rt_common import (LABEL, PLATFORM, RAW_ROOT, RELAY_IMAGE, RUNTIME_ROOT, api_with_retry, docker, iso, log_event,  # noqa: E402
                       now, process_events, read_json, remove_container, remove_network, utc_now, write_json, db_json,
                       check_digest)
from scenarios import FALCO_PROBES, build_schedule, describe_commands, run_action  # noqa: E402

LEARN_MINUTES = 30
EXTEND_MINUTES = 10
TEST_WINDOWS = 30
WINDOW = 60
INGEST_LAG = 45  # seconds after a window ends before it is scored (Falco -> telemetry -> backend)
RESTART_AT_MINUTES = (10, 20)
ELEVATED_BANDS = {"elevated", "high", "extreme"}
APPROVER = "porygon-runtime-dataset"


class ImageFailed(RuntimeError):
    pass


class Run:
    def __init__(self, key: str, learn_minutes: int, windows: int, batch: str = "batch1"):
        self.key, self.recipe = key, RECIPES[key]
        self.learn_minutes, self.n_windows, self.batch = learn_minutes, windows, batch
        self.dir = RAW_ROOT / key
        self.status_path = self.dir / "status.json"
        self.lock = threading.Lock()
        self.status: dict[str, Any] = read_json(self.status_path, None) or {}
        self.name = f"porygon-rt-{key}"
        self.relay, self.net, self.sidecar = f"{self.name}-relay", f"{self.name}-net", f"{self.name}-db"
        self.driver = None
        self.port: int | None = None

    # ------------------------------------------------------------------ status
    def save(self) -> None:
        with self.lock:
            write_json(self.status_path, self.status)

    def set(self, **values: Any) -> None:
        with self.lock:
            self.status.update(values)
            write_json(self.status_path, self.status)

    # --------------------------------------------------------------- containers
    def label_value(self, run_id: str | None) -> str | None:
        """The porygon.runtime label value: the run id for batch 1, "<batch>-<run_id>" otherwise."""
        if not run_id:
            return None
        return run_id if self.batch == "batch1" else f"{self.batch}-{run_id}"

    def cleanup(self, run_id: str | None) -> dict[str, Any]:
        label = self.label_value(run_id)
        if not label:
            return {}
        out = {}
        for name in (self.relay, self.name, self.sidecar):
            try:
                out[name] = remove_container(name, label)
            except RuntimeError as exc:
                out[name] = {"removed": False, "error": str(exc)}
        try:
            out[self.net] = remove_network(self.net, label)
        except RuntimeError as exc:
            out[self.net] = {"removed": False, "error": str(exc)}
        return out

    def _health(self, name: str) -> str:
        return docker("inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.Status}}",
                      name).stdout.strip()

    def _wait_healthy(self, name: str, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        state = ""
        while time.monotonic() < deadline:
            state = self._health(name)
            if state.startswith("healthy"):
                return
            if state.endswith(("exited", "dead")) or not state:
                break
            time.sleep(2)
        logs = docker("logs", "--tail", "30", name).stderr[-1500:] + docker("logs", "--tail", "30", name).stdout[-1500:]
        raise ImageFailed(f"{name} not healthy within {timeout}s (state {state!r}); last logs: {logs}")

    def _start_once(self, run_id: str) -> dict[str, Any]:
        r = self.recipe
        label = f"{LABEL}={self.label_value(run_id)}"
        res = docker("network", "create", "--internal", "--label", label, self.net)
        if res.returncode != 0:
            raise ImageFailed(f"network create failed: {res.stderr.strip()}")
        record: dict[str, Any] = {"network": {"name": self.net, "internal": True}}
        if "sidecar" in r:
            sc = r["sidecar"]
            args = ["run", "-d", "--name", self.sidecar, "--label", label, "--platform", PLATFORM,
                    "--network", self.net, "--network-alias", sc["alias"], "--memory", "1g", "--pids-limit", "512",
                    "--health-cmd", sc["health"], "--health-interval", "10s", "--health-timeout", "5s",
                    "--health-retries", "3", "--health-start-period", "90s"]
            for k, v in sc.get("env", {}).items():
                args += ["-e", f"{k}={v}"]
            res = docker(*args, sc["tag"])
            if res.returncode != 0:
                raise ImageFailed(f"sidecar start failed: {res.stderr.strip()}")
            self._wait_healthy(self.sidecar, 240)
            record["sidecar"] = {"name": self.sidecar, "tag": sc["tag"], "args": args}
        args = ["run", "-d", "--name", self.name, "--label", label, "--platform", PLATFORM,
                "--network", self.net, "--network-alias", self.name, "--memory", "1g", "--pids-limit", "512",
                "--health-cmd", r["health"], "--health-interval", "10s", "--health-timeout", "5s",
                "--health-retries", "3", "--health-start-period", f"{r.get('start_period', 30)}s"]
        for k, v in r.get("env", {}).items():
            args += ["-e", f"{k}={v}"]
        if r.get("mount_go_source"):
            src = self.dir / "go-src"
            src.mkdir(parents=True, exist_ok=True)
            (src / "main.go").write_text(GO_SOURCE, encoding="utf-8")
            args += ["-v", f"{src}:/src:ro"]
        args += [r["tag"], *r.get("cmd", [])]
        res = docker(*args)
        if res.returncode != 0:
            raise ImageFailed(f"container start failed: {res.stderr.strip()}")
        record["container"] = {"name": self.name, "id": res.stdout.strip(), "args": args}
        # Loopback relay: Docker publishes no ports for containers on an --internal network.
        self.dir.mkdir(parents=True, exist_ok=True)
        conf = self.dir / "relay-nginx.conf"
        conf.write_text("worker_processes 1;\npid /tmp/nginx.pid;\nerror_log /dev/stderr warn;\nevents {}\n"
                        f"stream {{\n  server {{\n    listen 8080;\n    proxy_pass {self.name}:{r['port']};\n"
                        "    proxy_timeout 900s;\n  }\n}\n", encoding="utf-8")
        res = docker("create", "--name", self.relay, "--label", label, "-p", "127.0.0.1::8080", "--memory", "64m",
                     "-v", f"{conf}:/etc/nginx/nginx.conf:ro", RELAY_IMAGE)
        if res.returncode != 0:
            raise ImageFailed(f"relay create failed: {res.stderr.strip()}")
        for step in (("network", "connect", self.net, self.relay), ("start", self.relay)):
            res = docker(*step)
            if res.returncode != 0:
                raise ImageFailed(f"relay {' '.join(step[:2])} failed: {res.stderr.strip()}")
        self._wait_healthy(self.name, r.get("start_period", 30) + 180)
        port_out = docker("port", self.relay, "8080").stdout.strip().splitlines()
        if not port_out:
            raise ImageFailed("relay published no port")
        self.port = int(port_out[0].rsplit(":", 1)[1])
        deadline = time.monotonic() + 90
        while not ping(r, self.port):
            if time.monotonic() > deadline:
                raise ImageFailed(f"service did not answer through relay port {self.port}")
            time.sleep(3)
        inspect = json.loads(docker("inspect", self.name).stdout)[0]
        record |= {"relay": {"name": self.relay, "image": RELAY_IMAGE, "host_port": self.port},
                   "image_id": inspect["Image"], "started_at": utc_now(),
                   "user": inspect["Config"].get("User") or "", "healthcheck": r["health"]}
        return record

    def start(self, run_id: str) -> dict[str, Any]:
        try:
            return self._start_once(run_id)
        except ImageFailed as exc:
            log_event(f"start:{self.key}", str(exc)[:1500], "removed the containers (exact name + label) and retried once", "pending")
            self.cleanup(run_id)
            time.sleep(5)
            try:
                record = self._start_once(run_id)
                log_event(f"start:{self.key}", "first start failed", "fresh container", "ok")
                return record
            except ImageFailed as exc2:
                log_event(f"start:{self.key}", str(exc2)[:1500], "second start failed", "image marked failed")
                raise

    def restart(self) -> dict[str, Any]:
        started = utc_now()
        res = docker("restart", "-t", "10", self.name, timeout=180)
        step = {"argv": ["docker", "restart", "-t", "10", self.name], "returncode": res.returncode,
                "started_at": started}
        try:
            self._wait_healthy(self.name, self.recipe.get("start_period", 30) + 180)
            if not ping(self.recipe, self.port):
                docker("restart", self.relay)  # the relay resolves the target once at start
                time.sleep(3)
                step["relay_restarted"] = True
            step["healthy_at"] = utc_now()
        except ImageFailed as exc:
            step["error"] = str(exc)[:1000]
        return step

    # ------------------------------------------------------------------ digest
    def resolve_digest(self, container_id: str) -> str:
        expected = None
        for name in ("prefetch.json", "prefetch-batch2.json"):
            prefetch = read_json(RUNTIME_ROOT / name, {}) or {}
            expected = expected or (prefetch.get("images", {}).get(self.recipe["tag"], {}) or {}).get("repo_digest")
        rows = db_json("select coalesce(json_agg(distinct image_digest), '[]'::json) from process_exec_events "
                       f"where container_id = '{container_id}' and image_digest is not null") or []
        if rows:
            if expected and rows != [expected]:
                log_event(f"digest:{self.key}", f"prefetch digest {expected} differs from Porygon's {rows}",
                          "used the digest Porygon recorded", "ok")
            return check_digest(rows[0])
        if expected:
            return check_digest(expected)
        raise ImageFailed("no image digest available from Porygon or prefetch")

    # ---------------------------------------------------------------- learning
    def build_baseline(self, start: datetime, end: datetime) -> tuple[dict | None, list[str]]:
        payload = {"image_digest": self.status["image_digest"], "training_start": iso(start), "training_end": iso(end),
                   "window_seconds": WINDOW, "minimum_process_events": 20, "minimum_nonempty_windows": 3,
                   "approved_by": APPROVER, "approval_reference": self.status["run_id"],
                   "notes": f"runtime dataset learning phase for {self.recipe['tag']}"}
        return api_with_retry("POST", "/internal/v1/baselines/build", payload, step=f"baseline:{self.key}")

    def learning(self) -> None:
        st = self.status
        start = datetime.fromisoformat(st["training_start"])
        end = start + timedelta(minutes=self.learn_minutes)
        restarts = st.setdefault("learning_restarts", [])
        for minute in RESTART_AT_MINUTES:
            if minute >= self.learn_minutes:
                continue
            at = start + timedelta(minutes=minute)
            if len(restarts) < RESTART_AT_MINUTES.index(minute) + 1:
                sleep_until(at)
                restarts.append(self.restart())
                self.save()
        sleep_until(end + timedelta(seconds=INGEST_LAG))
        attempts = st.setdefault("baseline_attempts", [])
        profile, errors = self.build_baseline(start, end)
        attempts.append({"training_end": iso(end), "profile": profile, "errors": errors})
        self.save()
        if profile is None or not (profile.get("quality") or {}).get("passed"):
            end = end + timedelta(minutes=EXTEND_MINUTES)
            log_event(f"baseline:{self.key}", f"baseline insufficient: {json.dumps((profile or {}).get('quality'))[:600]} {errors}",
                      f"extended learning by {EXTEND_MINUTES} min", "pending")
            sleep_until(end + timedelta(seconds=INGEST_LAG))
            profile, errors = self.build_baseline(start, end)
            attempts.append({"training_end": iso(end), "profile": profile, "errors": errors})
            self.save()
            if profile is None or not (profile.get("quality") or {}).get("passed"):
                raise ImageFailed(f"baseline insufficient after extension: {errors or profile.get('quality')}")
        activated, errors = api_with_retry("POST", f"/internal/v1/baselines/{profile['profile_id']}/activate",
                                           step=f"baseline:{self.key}")
        if activated is None:
            raise ImageFailed(f"baseline activation failed: {errors}")
        write_json(self.dir / "baseline.json", activated)
        self.set(training_end=iso(end), baseline_id=profile["profile_id"], baseline_activated_at=utc_now(),
                 phase="test")

    # -------------------------------------------------------------------- test
    def score_window(self, idx: int) -> None:
        w = self.status["windows"][str(idx)]
        ws = datetime.fromisoformat(w["window_start"])
        we = ws + timedelta(seconds=WINDOW)
        sleep_until(we + timedelta(seconds=INGEST_LAG))
        wdir = self.dir / "windows"
        result: dict[str, Any] = {"scored_at": utc_now()}
        score, errors = api_with_retry("POST", "/internal/v1/anomaly-scores/compute",
                                       {"image_digest": self.status["image_digest"], "window_start": iso(ws)},
                                       step=f"score:{self.key}:w{idx}")
        if score is None:
            result |= {"state": "failed", "error": f"score: {errors}"}
        else:
            write_json(wdir / f"w{idx:02d}-score.json", score)
            detection, derrors = api_with_retry("POST", "/internal/v1/detections/run",
                                                {"anomaly_score_id": score["score_id"]},
                                                step=f"detect:{self.key}:w{idx}")
            if detection is None:
                result |= {"state": "failed", "error": f"detection: {derrors}", "score_id": score["score_id"]}
            else:
                write_json(wdir / f"w{idx:02d}-detection.json", detection)
                result |= {"state": "done", "score_id": score["score_id"], "detection_run_id": detection["run"]["run_id"],
                           "incident_id": (detection.get("incident") or {}).get("incident_id")}
        try:
            events = process_events(self.status["image_digest"], ws, we)
            write_json(wdir / f"w{idx:02d}-events.json", events)
            result["events_read"] = len(events)
            result["action_seen_by_falco"] = seen_by_falco(w, events, self.recipe, self.status["container"]["name"])
        except Exception as exc:  # noqa: BLE001 - recorded, never filled in
            result |= {"events_error": str(exc)[:500], "action_seen_by_falco": None}
            if result.get("state") == "done":
                result["state"] = "failed"
        with self.lock:
            self.status["windows"][str(idx)].update(result)
            write_json(self.status_path, self.status)
        print(f"[{self.key}] w{idx:02d} {w['scenario_id']:22} gt={w['ground_truth']:8} "
              f"score={score.get('total_score') if score else None} band={score.get('score_band') if score else None} "
              f"state={result['state']} incident={bool(result.get('incident_id'))}", flush=True)

    def test(self) -> None:
        st = self.status
        windows = st["windows"]
        jobs: queue.Queue[int | None] = queue.Queue()

        def scorer() -> None:
            while (idx := jobs.get()) is not None:
                try:
                    self.score_window(idx)
                except Exception as exc:  # noqa: BLE001
                    log_event(f"score:{self.key}:w{idx}", repr(exc)[:800], "window recorded as failed", "failed")
                    with self.lock:
                        self.status["windows"][str(idx)].update({"state": "failed", "error": repr(exc)[:800]})
                        write_json(self.status_path, self.status)

        threading.Thread(target=scorer, daemon=True).start()
        # Windows that ran but were never scored (interrupted) are scored now; done ones are untouched.
        for idx in range(self.n_windows):
            w = windows[str(idx)]
            if w.get("action") is not None and w.get("state") in (None, "action_done"):
                jobs.put(idx)
        next_start = next_minute(now() + timedelta(seconds=5))
        for idx in range(self.n_windows):
            w = windows[str(idx)]
            if w.get("action") is not None:
                continue
            ws = next_start
            we = ws + timedelta(seconds=WINDOW)
            with self.lock:
                w.update({"window_start": iso(ws), "window_end": iso(we), "state": "running"})
                write_json(self.status_path, self.status)
            sleep_until(ws + timedelta(seconds=5))
            deadline = time.monotonic() + max(5.0, (we - now()).total_seconds() - 5)
            try:
                action = run_action(w, self.name, self.recipe, st["run_id"], deadline, self.restart)
            except Exception as exc:  # noqa: BLE001
                action = {"error": repr(exc)[:800], "returncode": None, "steps": []}
                log_event(f"action:{self.key}:w{idx}", repr(exc)[:800], "action recorded as failed", "failed")
            with self.lock:
                w.update({"action": action, "state": "action_done"})
                write_json(self.status_path, self.status)
            if now() > we:
                log_event(f"action:{self.key}:w{idx}", f"action overran its window by {(now() - we).total_seconds():.1f}s",
                          "recorded as is; next window starts at the next minute", "noted")
            sleep_until(we)
            jobs.put(idx)
            next_start = we if now() < we + timedelta(seconds=2) else next_minute(now())
        jobs.put(None)
        while any(windows[str(i)].get("state") in ("running", "action_done") for i in range(self.n_windows)):
            time.sleep(5)

    # --------------------------------------------------------------------- run
    def execute(self) -> int:
        RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
        st = self.status
        if st.get("phase") in ("complete", "failed"):
            print(f"[{self.key}] already {st['phase']}; nothing to do")
            return 0
        responder = docker("ps", "--filter", "name=^porygon-responder-1$", "--format", "{{.Names}}").stdout.strip()
        if responder:
            raise SystemExit("porygon-responder-1 is running; the protocol keeps it off. Stopping instead.")
        if st.get("phase") == "learning":
            log_event(f"resume:{self.key}", "learning phase was interrupted", "learning restarts from scratch with a new run id",
                      "pending")
            self.cleanup(st.get("run_id"))
            st.clear()
        resumed_test = st.get("phase") == "test"
        if resumed_test:
            self.cleanup(st.get("run_id"))
            log_event(f"resume:{self.key}", "test phase was interrupted",
                      "fresh container for the remaining windows; finished windows kept", "pending")
        run_id = st.get("run_id") or f"{self.key}-{now().strftime('%Y%m%dT%H%M%SZ')}"
        seed = int(hashlib.sha256(f"porygon-runtime:{self.key}".encode()).hexdigest()[:8], 16)
        if not st:
            st.update({"image_key": self.key, "tag": self.recipe["tag"], "platform": PLATFORM, "run_id": run_id,
                       "batch": self.batch, "container_label": f"{LABEL}={self.label_value(run_id)}",
                       "recipe": self.recipe, "seed": seed, "phase": "starting", "created_at": utc_now(),
                       "protocol": {"learn_minutes": self.learn_minutes, "test_windows": self.n_windows,
                                    "window_seconds": WINDOW, "ingest_lag_seconds": INGEST_LAG,
                                    "restarts_at_minutes": list(RESTART_AT_MINUTES)}})
            self.save()
        try:
            record = self.start(run_id)
            starts = st.setdefault("container_starts", [])
            starts.append(record)
            st["container"] = record["container"]
            self.save()
            self.driver = make_driver(self.recipe, self.port, seed)
            self.driver.start()
            if not resumed_test:
                self.set(phase="learning", training_start=iso(now()))
                time.sleep(20)
                self.set(image_digest=self.resolve_digest(record["container"]["id"]))
                self.learning()
                schedule = build_schedule(seed)
                with self.lock:
                    st["schedule_recorded_at"] = utc_now()
                    st["windows"] = {str(w["window_index"]): w | {"ground_truth_recorded_at": st["schedule_recorded_at"],
                                                                 "commands": describe_commands(w, self.recipe)}
                                     for w in schedule[: self.n_windows]}
                    write_json(self.status_path, st)
            self.test()
            self.set(phase="complete", finished_at=utc_now())
        except ImageFailed as exc:
            self.set(phase="failed", error=str(exc)[:2000], finished_at=utc_now())
            print(f"[{self.key}] FAILED: {exc}", flush=True)
        finally:
            if self.driver:
                self.driver.stop()
                with self.lock:
                    st.setdefault("driver_runs", []).append(self.driver.summary())
            if st.get("training_start") and st.get("training_end") and st.get("image_digest"):
                try:
                    events = process_events(st["image_digest"], datetime.fromisoformat(st["training_start"]),
                                            datetime.fromisoformat(st["training_end"]))
                    write_json(self.dir / "learning-events.json", events)
                except Exception as exc:  # noqa: BLE001
                    log_event(f"export:{self.key}", repr(exc)[:500], "learning events not exported", "failed")
            st["cleanup"] = self.cleanup(run_id)
            self.save()
        return 0 if st.get("phase") == "complete" else 1


def seen_by_falco(window: dict[str, Any], events: list[dict[str, Any]], recipe: dict[str, Any], container: str) -> Any:
    sid = window["scenario_id"]
    if sid in ("RT-NORMAL", "RT-NORMAL-RESTART"):
        return None
    if sid == "RT-HN-LOGS" and recipe.get("log") == "docker_logs":
        return None  # no process inside the container by design
    if sid == "RT-HN-ADMIN":
        probes = [Path(recipe["admin"][0]).name]
        fields = ("process_name", "executable", "command_line")
    else:
        probes = FALCO_PROBES.get(sid, [])
        fields = ("command_line", "parent_command_line")
    for event in events:
        if event.get("container_name") not in (None, container):
            continue
        for field in fields:
            if any(p in (event.get(field) or "") for p in probes):
                return True
    return False


def next_minute(moment: datetime) -> datetime:
    floor = moment.replace(second=0, microsecond=0)
    return floor if floor == moment else floor + timedelta(minutes=1)


def sleep_until(moment: datetime) -> None:
    while (remaining := (moment - now()).total_seconds()) > 0:
        time.sleep(min(remaining, 30))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image", choices=sorted(RECIPES))
    parser.add_argument("--learn-minutes", type=int, default=LEARN_MINUTES)
    parser.add_argument("--windows", type=int, default=TEST_WINDOWS)
    parser.add_argument("--batch", default="batch1", help="collection batch recorded with the run")
    args = parser.parse_args()
    rt_common.BATCH = args.batch
    return Run(args.image, args.learn_minutes, args.windows, args.batch).execute()


if __name__ == "__main__":
    raise SystemExit(main())
