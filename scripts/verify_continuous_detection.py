#!/usr/bin/env python3
"""Exercise an owned canary through the real unattended assessment worker.

Uses private backend transport. Creates only a labelled disposable container,
starts/stops only its own standalone worker process, and disables only targets
created by this run. It never calls score-compute or detection-run endpoints.
"""

from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
from uuid import uuid4
from private_api import open_backend
from porygon_scan import _load_env

ROOT = Path(__file__).resolve().parents[1]


def docker(*args):
    return subprocess.check_output(
        ["docker", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
    ).strip()


def now():
    return datetime.now(timezone.utc)


def wait_for(check, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(1)
    raise RuntimeError("Timed out waiting for controlled assessment evidence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="alpine:3.21")
    parser.add_argument("--operator-token-file", type=Path)
    parser.add_argument("--sensor-token-file", type=Path)
    parser.add_argument("--sensor-instance", default="local-falco-adapter-01")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts/local/continuous-detection/acceptance.json",
    )
    args = parser.parse_args()
    _load_env()
    operator = (
        args.operator_token_file.read_text().strip()
        if args.operator_token_file
        else os.environ.get("PORYGON_OPERATOR_API_TOKEN", "")
    )
    sensor = (
        args.sensor_token_file.read_text().strip()
        if args.sensor_token_file
        else os.environ.get("PORYGON_INTERNAL_API_TOKEN", "")
    )
    if not operator or not sensor:
        parser.error(
            "Provision operator and telemetry credential files or local compatibility credentials"
        )
    target_ids = []
    container = None
    process = None
    worker_pid = None
    run_id = uuid4().hex

    def api(method, path, payload=None, service=False):
        if "/anomaly-scores/compute" in path or "/detections/run" in path:
            raise AssertionError(
                "Manual assessment endpoints are forbidden in this verifier"
            )
        request = urllib.request.Request(
            "http://127.0.0.1:8000" + path,
            method=method,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={
                "Content-Type": "application/json",
                "X-Porygon-Internal-Token"
                if service
                else "X-Porygon-Operator-Token": sensor if service else operator,
            },
        )
        with open_backend(request, timeout=60) as response:
            return json.load(response)

    def start_worker():
        nonlocal process, worker_pid
        process = subprocess.Popen(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "backend",
                "sh",
                "-c",
                "echo $$; exec python -m porygon_api.window_worker --owner verify-"
                + run_id,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        worker_pid = int(process.stdout.readline().strip())

    def stop_worker():
        nonlocal process, worker_pid
        if worker_pid:
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "backend",
                    "sh",
                    "-c",
                    "kill -TERM " + str(worker_pid),
                ],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            worker_pid = None
        if process:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=10)
            process = None

    def jobs(target):
        return api("GET", "/api/v1/assessment-jobs?target_id=" + target + "&limit=500")

    def generate_benign():
        for _ in range(12):
            docker("exec", container, "/bin/true")
            time.sleep(0.6)

    try:
        assert api("GET", "/api/v1/response-policy")["execution_mode"] == "disabled"
        assert not api("GET", "/api/v1/assessment-worker/status")["enabled_in_api"], (
            "Use standalone verification with API worker disabled"
        )
        assert not any(
            item["enabled"]
            for item in api("GET", "/api/v1/assessment-targets?limit=500")
        ), "Use an isolated acceptance stack without other enabled targets"
        container = docker(
            "run",
            "--detach",
            "--name",
            "porygon-assessment-" + run_id,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--label",
            "com.porygon.test=continuous-detection",
            "--label",
            "com.porygon.verification=" + run_id,
            args.image,
            "sleep",
            "900",
        )
        inventory = wait_for(
            lambda: next(
                (
                    row
                    for row in api("GET", "/api/v1/containers?limit=500")
                    if row["container_id"] == container and row.get("image_digest")
                ),
                None,
            )
        )
        host = inventory["docker_host_id"]
        digest = inventory["image_digest"]
        training_start = now()
        generate_benign()
        training_end = now()
        time.sleep(2)
        shadow_start = now()
        generate_benign()
        shadow_end = now()
        wait_for(
            lambda: (
                len(
                    api(
                        "GET",
                        "/api/v1/process-events?container_id="
                        + container
                        + "&limit=500",
                    )
                )
                >= 24
            )
        )
        target = api(
            "POST",
            "/operator/v1/assessment-targets",
            {
                "docker_host_id": host,
                "container_id": container,
                "image_digest": digest,
                "start_at": now().isoformat(),
                "window_seconds": 5,
                "allowed_lateness_seconds": 2,
            },
        )
        target_id = target["target_id"]
        target_ids.append(target_id)
        candidate = api(
            "POST",
            f"/operator/v1/assessment-targets/{target_id}/profiles",
            {
                "reference": "controlled canary " + run_id,
                "intervals": [
                    {
                        "name": "benign-training",
                        "label": "benign",
                        "start_at": training_start.isoformat(),
                        "end_at": training_end.isoformat(),
                    }
                ],
            },
        )
        enrollment_id = candidate["enrollment"]["enrollment_id"]
        assert candidate["quality"]["passed"]
        root = f"/operator/v1/assessment-targets/{target_id}/profiles/{enrollment_id}"
        api(
            "POST",
            root + "/shadow",
            {
                "name": "disjoint-shadow",
                "label": "benign",
                "start_at": shadow_start.isoformat(),
                "end_at": shadow_end.isoformat(),
            },
        )
        api("POST", root + "/activate", {})
        start_worker()
        generate_benign()
        baseline = wait_for(
            lambda: next(
                (
                    row
                    for row in jobs(target_id)
                    if row["state"] == "completed"
                    and row["score_id"]
                    and row["coverage"]["state"] == "degraded"
                ),
                None,
            )
        )
        stop_worker()
        # Work accumulates while only this verifier's process is absent.
        outage_start = now()
        docker("exec", container, "/bin/sh", "-c", "id; cat /etc/passwd")
        time.sleep(9)
        assert not any(
            datetime.fromisoformat(row["window_start"]) >= outage_start
            and row["state"] == "completed"
            for row in jobs(target_id)
        )
        start_worker()
        anomalous = wait_for(
            lambda: next(
                (
                    row
                    for row in jobs(target_id)
                    if row["detection_run_id"]
                    and api(
                        "GET", "/api/v1/detection-runs/" + row["detection_run_id"]
                    ).get("incident")
                ),
                None,
            )
        )
        original_count = len(jobs(target_id))
        time.sleep(2)
        records = jobs(target_id)
        assert len({row["assessment_key"] for row in records}) == len(records)
        # Explicitly injected late evidence is labelled verification data and
        # scoped to this canary; it does not pretend to be a captured syscall.
        occurred = datetime.fromisoformat(baseline["window_start"]) + timedelta(
            seconds=1
        )
        event_id = hashlib.sha256((run_id + "late").encode()).hexdigest()
        late = {
            "event_id": event_id,
            "sensor_instance_id": args.sensor_instance,
            "source": "falco",
            "rule_name": "controlled late verification fixture",
            "priority": "Notice",
            "occurred_at": occurred.isoformat(),
            "time_nano": int(occurred.timestamp() * 1e9),
            "event_type": "execve",
            "reported_docker_host_id": host,
            "reported_container_id": container,
            "process_pid": 999999,
            "process_name": "sh",
            "executable": "/bin/sh",
            "command_line": "sh -c controlled-late-evidence",
            "user_uid": 0,
            "raw_event": {"verification_run": run_id, "synthetic": True},
        }
        api(
            "POST",
            "/internal/v1/process-events/batch",
            {"events": [late]},
            service=True,
        )
        revision_payload = {
            "window_start": baseline["window_start"],
            "revision": 1,
            "reason": "controlled late verification evidence",
        }
        revised = api(
            "POST",
            f"/operator/v1/assessment-targets/{target_id}/reprocess",
            revision_payload,
        )
        replay = api(
            "POST",
            f"/operator/v1/assessment-targets/{target_id}/reprocess",
            revision_payload,
        )
        assert (
            revised["job_id"] == replay["job_id"]
            and revised["assessment_key"] != baseline["assessment_key"]
        )
        wait_for(
            lambda: any(
                row["job_id"] == revised["job_id"] and row["state"] == "completed"
                for row in jobs(target_id)
            )
        )
        # A second context target without a profile is explicitly unprofiled.
        api("POST", f"/operator/v1/assessment-targets/{target_id}/disable", {})
        # Same immutable identity is idempotent, so make an owned second canary
        # assessment target by using a new security context is inappropriate.
        # Instead an unprofiled canary is enrolled as a separate owned container.
        stop_worker()
        unprofiled_container = docker(
            "run",
            "--detach",
            "--name",
            "porygon-unprofiled-" + run_id,
            "--cap-drop",
            "ALL",
            "--label",
            "com.porygon.test=continuous-detection",
            "--label",
            "com.porygon.verification=" + run_id,
            args.image,
            "sleep",
            "120",
        )
        try:
            identity = wait_for(
                lambda: next(
                    (
                        row
                        for row in api("GET", "/api/v1/containers?limit=500")
                        if row["container_id"] == unprofiled_container
                        and row.get("image_digest")
                    ),
                    None,
                )
            )
            unprofiled = api(
                "POST",
                "/operator/v1/assessment-targets",
                {
                    "docker_host_id": identity["docker_host_id"],
                    "container_id": unprofiled_container,
                    "image_digest": identity["image_digest"],
                    "start_at": (now() - timedelta(seconds=10)).isoformat(),
                    "window_seconds": 5,
                    "allowed_lateness_seconds": 0,
                },
            )
            target_ids.append(unprofiled["target_id"])
            start_worker()
            unknown = wait_for(
                lambda: next(
                    (
                        row
                        for row in jobs(unprofiled["target_id"])
                        if row["state"] == "completed"
                    ),
                    None,
                )
            )
            assert (
                unknown["coverage"]["state"] == "unprofiled"
                and unknown["score_id"] is None
            )
        finally:
            docker("rm", "--force", unprofiled_container)
        evidence = {
            "run_id": run_id,
            "manual_compute_or_detection_calls": 0,
            "unattended_incident": True,
            "incident_assessment_job_id": anomalous["job_id"],
            "worker_outage_recovered": True,
            "assessment_keys_unique": True,
            "revision_replay_idempotent": True,
            "late_revision_job_id": revised["job_id"],
            "coverage_completeness": baseline["coverage"]["completeness"],
            "degraded_explicit": baseline["coverage"]["state"] == "degraded",
            "unprofiled_explicit": True,
            "original_assessment_count": original_count,
            "target_ids": target_ids,
        }
        assert evidence["coverage_completeness"] == "unknown"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence, indent=2))
        return 0
    finally:
        stop_worker()
        for identifier in target_ids:
            try:
                api("POST", f"/operator/v1/assessment-targets/{identifier}/disable", {})
            except Exception:
                pass
        if container:
            docker("rm", "--force", container)


if __name__ == "__main__":
    raise SystemExit(main())
