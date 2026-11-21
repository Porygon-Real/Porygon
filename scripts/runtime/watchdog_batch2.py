#!/usr/bin/env python3
"""Watch the Falco -> telemetry -> backend path while batch 2 collects, and repair it.

In batch 1 telemetry rotated /var/log/porygon/falco-events.jsonl, Falco could not
reopen it, and process events stopped for 2h46m; eight runs had to be discarded.

Detection does not rely on the monitored containers being busy (a quiet web
server legitimately spawns no processes). Instead the watchdog keeps its own
throwaway container, execs a harmless command in it every cycle, and checks that
Porygon's database stores the resulting event. That never touches a monitored
container, so it cannot alter the data being collected.

Two consecutive failures mean the sensor is down. The repair is the one already
approved in batch 1: remove the output file if it exists and is empty and Falco
logged that it could not open it, otherwise restart falco and then telemetry.
Runs whose learning or test overlapped the gap are moved, unchanged, to
raw-invalid/<key>-sensor-gap-<date>/ and left for the queue to run again.

After three failed repairs it writes NEEDS_ATTENTION.md and the stop file that
stops the batch from starting new images; it never waits for anybody.
"""
from __future__ import annotations

import argparse
import atexit
import json
import shutil
import signal
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rt_common import (LABEL, PLATFORM, RAW_ROOT, RELAY_IMAGE, RUNTIME_ROOT, db_json, docker, iso, log_event,  # noqa: E402
                       now, read_json, remove_container, remove_network, sh, utc_now, write_json)

PROBE_NAME = "porygon-rt-watchdog-probe"
PROBE_LABEL = "batch2-watchdog"
GAPS_PATH = RUNTIME_ROOT / "batch2-sensor-gaps.json"
STOP_FILE = RUNTIME_ROOT / "batch2-stop"
INVALID_ROOT = RUNTIME_ROOT / "raw-invalid"
FALCO_EVENTS = "/var/log/porygon/falco-events.jsonl"
CYCLE_SECONDS = 120
EVENT_WAIT_SECONDS = 75
MAX_REPAIRS = 3


def ensure_probe() -> str | None:
    """A long-lived throwaway container of the relay image, used only for liveness execs."""
    running = docker("ps", "--filter", f"name=^{PROBE_NAME}$", "--format", "{{.ID}}").stdout.strip()
    if running:
        return docker("inspect", "--format", "{{.Id}}", PROBE_NAME).stdout.strip()
    docker("rm", "--force", PROBE_NAME)
    result = docker("run", "-d", "--name", PROBE_NAME, "--label", f"{LABEL}={PROBE_LABEL}", "--platform", PLATFORM,
                    "--memory", "64m", "--entrypoint", "sleep", RELAY_IMAGE, "86400")
    if result.returncode != 0:
        log_event("watchdog", f"probe container would not start: {result.stderr.strip()[:300]}",
                  "liveness check skipped this cycle", "pending", batch="batch2")
        return None
    return result.stdout.strip()


def remove_probe() -> None:
    """The probe container is the watchdog's own; it is removed by exact name and label."""
    try:
        remove_container(PROBE_NAME, PROBE_LABEL)
    except RuntimeError as exc:
        log_event("watchdog", f"probe cleanup refused: {exc}", "left for the final cleanup", "pending",
                  batch="batch2")


def sensor_alive() -> tuple[bool, str]:
    """Exec in the watchdog's own container and wait for Porygon to store the event."""
    container_id = ensure_probe()
    if not container_id:
        return False, "no probe container"
    before = db_json("select count(*) from process_exec_events where container_id like "
                     f"'{container_id[:12]}%'") or 0
    result = docker("exec", PROBE_NAME, "/bin/sh", "-c", "id; uname -n")
    if result.returncode != 0:
        return False, f"probe exec returned {result.returncode}: {result.stderr.strip()[:200]}"
    deadline = time.monotonic() + EVENT_WAIT_SECONDS
    while time.monotonic() < deadline:
        after = db_json("select count(*) from process_exec_events where container_id like "
                        f"'{container_id[:12]}%'") or 0
        if after > before:
            return True, f"{after - before} new event(s)"
        time.sleep(5)
    return False, f"no new process_exec_events row within {EVENT_WAIT_SECONDS}s of a real exec"


def falco_logged_open_failure() -> bool:
    logs = docker("compose", "logs", "--tail", "200", "falco")
    return "failed to open output file" in (logs.stdout + logs.stderr).lower()


def repair() -> dict[str, object]:
    """The repair approved in batch 1, in order; the stack is never torn down."""
    steps: list[dict[str, object]] = []
    stat = docker("compose", "exec", "-T", "falco", "stat", "-c", "%s", FALCO_EVENTS)
    size = int(stat.stdout.split()[0]) if stat.returncode == 0 and stat.stdout.split() else None
    open_failure = falco_logged_open_failure()
    steps.append({"step": "inspect", "size_bytes": size, "falco_logged_open_failure": open_failure})
    if size == 0 and open_failure:
        removed = docker("compose", "exec", "-T", "falco", "rm", "-f", FALCO_EVENTS)
        steps.append({"step": "remove empty output file", "returncode": removed.returncode,
                      "stderr": removed.stderr.strip()[:300]})
    else:
        for service in ("falco", "telemetry"):
            result = docker("compose", "restart", service, timeout=300)
            steps.append({"step": f"restart {service}", "returncode": result.returncode,
                          "stderr": result.stderr.strip()[:300]})
    time.sleep(20)
    ok, detail = sensor_alive()
    steps.append({"step": "confirm", "events_flowing": ok, "detail": detail})
    return {"repaired": ok, "steps": steps}


def overlaps(run_start: str | None, run_end: str | None, gap_start: datetime, gap_end: datetime) -> bool:
    if not run_start:
        return False
    start = datetime.fromisoformat(run_start)
    end = datetime.fromisoformat(run_end) if run_end else gap_end
    return start < gap_end and gap_start < end


def quarantine(gap_start: datetime, gap_end: datetime) -> list[str]:
    """Move every batch 2 run that overlapped the gap to raw-invalid, unchanged."""
    moved: list[str] = []
    for status_path in sorted(RAW_ROOT.glob("*/status.json")):
        st = read_json(status_path, {}) or {}
        if st.get("batch") != "batch2" or st.get("phase") == "failed":
            continue
        key = st.get("image_key") or status_path.parent.name
        windows = st.get("windows") or {}
        ends = [w.get("window_end") for w in windows.values() if w.get("window_end")]
        run_start = st.get("training_start") or st.get("created_at")
        run_end = max(ends) if ends else st.get("finished_at")
        if not overlaps(run_start, run_end, gap_start, gap_end):
            continue
        pattern = f"run_image.py {key} --batch"
        pids = [p for p in sh(["pgrep", "-f", pattern]).stdout.split() if p.isdigit()]
        for pid in pids:
            sh(["kill", "-TERM", pid])
        if pids:
            time.sleep(5)
        label = (st.get("container_label") or "").split("=", 1)[-1]
        removals = {}
        if label:
            name = f"porygon-rt-{key}"
            for container in (f"{name}-relay", name, f"{name}-db"):
                try:
                    removals[container] = remove_container(container, label)
                except RuntimeError as exc:
                    removals[container] = {"removed": False, "error": str(exc)}
            try:
                removals[f"{name}-net"] = remove_network(f"{name}-net", label)
            except RuntimeError as exc:
                removals[f"{name}-net"] = {"removed": False, "error": str(exc)}
        destination = INVALID_ROOT / f"{key}-sensor-gap-{now().strftime('%Y%m%d')}"
        suffix = 1
        while destination.exists():
            suffix += 1
            destination = INVALID_ROOT / f"{key}-sensor-gap-{now().strftime('%Y%m%d')}-{suffix}"
        INVALID_ROOT.mkdir(parents=True, exist_ok=True)
        shutil.move(str(status_path.parent), str(destination))
        moved.append(key)
        log_event("watchdog", f"{key}: learning or test overlapped the sensor gap "
                              f"{iso(gap_start)}..{iso(gap_end)}",
                  f"stopped the run (pids {pids or 'none'}), removed its containers and moved its raw folder, "
                  f"unchanged, to raw-invalid/{destination.name}",
                  "marked invalid-sensor-gap; the queue runs it again from scratch",
                  batch="batch2", removals=removals)
    return moved


def record_gap(gap: dict[str, object]) -> None:
    record = read_json(GAPS_PATH, None) or {"batch": "batch2", "gaps": []}
    record["gaps"].append(gap)
    record["updated_at"] = utc_now()
    write_json(GAPS_PATH, record)


def escalate(reason: str) -> None:
    note = (f"\n## Sensor watchdog could not repair the Falco path ({utc_now()})\n\n### What happened\n\n{reason}\n\n"
            f"### What was tried\n\n{MAX_REPAIRS} repair attempts: remove the empty {FALCO_EVENTS} when Falco had "
            "logged that it could not open it, otherwise restart falco and then telemetry, each followed by a real "
            "exec in a throwaway container and a check that Porygon stored the event.\n\n### What is affected\n\n"
            "The batch stopped starting new images. Runs that overlapped a gap were moved, unchanged, to "
            f"raw-invalid/. Collected data is still exported and validated. Details in {GAPS_PATH.name} and "
            "run-log.jsonl.\n\n### Proposed command(s)\n\n```bash\ndocker compose ps\n"
            "docker compose logs --tail 100 falco telemetry\n"
            f"rm {STOP_FILE}  # once events flow again, then rerun scripts/runtime/run_batch2.sh\n```\n")
    path = RUNTIME_ROOT / "NEEDS_ATTENTION.md"
    header = "" if path.is_file() else "# Needs attention\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(header + note)
    STOP_FILE.write_text(f"{utc_now()} sensor watchdog: {reason}\n", encoding="utf-8")
    log_event("watchdog", reason, f"wrote NEEDS_ATTENTION.md and {STOP_FILE.name}",
              "batch stops starting new images; collected data is still exported", batch="batch2")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cycle-seconds", type=int, default=CYCLE_SECONDS)
    parser.add_argument("--once", action="store_true", help="one liveness check, then exit")
    args = parser.parse_args()
    atexit.register(remove_probe)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: sys.exit(0))
    failures, repairs = 0, 0
    last_ok = now()
    log_event("watchdog", "n/a", f"started; liveness check every {args.cycle_seconds}s", "running", batch="batch2")
    while True:
        ok, detail = sensor_alive()
        if ok:
            if failures:
                log_event("watchdog", f"{failures} failed liveness check(s): {detail}",
                          "events are flowing again without a repair", "recovered", batch="batch2")
            failures, last_ok = 0, now()
        else:
            failures += 1
            log_event("watchdog", detail, f"liveness check {failures} of 2 before a repair", "pending",
                      batch="batch2")
            if failures >= 2:
                gap_start, repairs = last_ok, repairs + 1
                print(f"{utc_now()} sensor down since {iso(gap_start)}; repair attempt {repairs}", flush=True)
                outcome = repair()
                gap_end = now()
                moved = quarantine(gap_start, gap_end) if outcome["repaired"] else []
                record_gap({"detected_at": utc_now(), "last_event_seen_at": iso(gap_start),
                            "gap_ended_at": iso(gap_end),
                            "gap_minutes": round((gap_end - gap_start).total_seconds() / 60, 1),
                            "repair_attempt": repairs, "repaired": outcome["repaired"],
                            "steps": outcome["steps"], "runs_invalidated": moved})
                log_event("watchdog", f"sensor down since {iso(gap_start)}: {detail}",
                          json.dumps(outcome["steps"], default=str)[:1200],
                          "repaired" if outcome["repaired"] else f"repair {repairs} failed", batch="batch2")
                if outcome["repaired"]:
                    failures, last_ok = 0, now()
                elif repairs >= MAX_REPAIRS:
                    escalate(f"Porygon stored no process event for a real exec after {repairs} repair attempts; "
                             f"the last gap began at {iso(gap_start)}.")
                    return 1
        if args.once:
            return 0 if ok else 1
        time.sleep(args.cycle_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
