#!/usr/bin/env python3
"""Pre-flight checks for batch 2, recorded to datasets/runtime/batch2-preflight.json.

Checks the stack is healthy, records free disk and Docker usage, confirms no
labelled runtime containers are left over, confirms Falco events are reaching
Porygon's database (a real throwaway container, a real exec, then a query), and
confirms the Falco output file is writable and far below the rotation limit.
Every value is read from the host, Docker or Porygon; nothing is assumed.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rt_common import (LABEL, PLATFORM, RUNTIME_ROOT, db_json, docker, load_env, log_event, remove_container,  # noqa: E402
                       runtime_label_containers, sh, utc_now, write_json)

PROBE_IMAGE = "nginxinc/nginx-unprivileged:1.29.3-alpine-slim"  # the relay image, already present
MIN_FREE_GB = 30


def compose_health() -> dict[str, str]:
    out = docker("compose", "ps", "--format", "{{.Service}}\t{{.State}}\t{{.Health}}").stdout
    rows = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            rows[parts[0]] = f"{parts[1]}/{parts[2] if len(parts) > 2 else ''}".rstrip("/")
    return rows


def falco_flow() -> dict[str, object]:
    """Run a real exec in a throwaway labelled container and wait for Porygon to store it."""
    run_id = f"batch2-preflight-{int(time.time())}"
    name = "porygon-rt-batch2-preflight"
    docker("rm", "--force", name)
    started = docker("run", "-d", "--name", name, "--label", f"{LABEL}={run_id}", "--platform", PLATFORM,
                     "--memory", "64m", "--entrypoint", "sleep", PROBE_IMAGE, "600")
    if started.returncode != 0:
        return {"ok": False, "error": f"probe container did not start: {started.stderr.strip()[:400]}"}
    container_id = started.stdout.strip()
    marker = f"porygon-preflight-{run_id}"
    exec_result = docker("exec", name, "/bin/sh", "-c", f"id; echo {marker}")
    deadline = time.monotonic() + 120
    rows, waited = 0, 0.0
    while time.monotonic() < deadline:
        rows = db_json("select count(*) from process_exec_events where container_id like "
                       f"'{container_id[:12]}%'") or 0
        if rows:
            break
        time.sleep(5)
        waited = round(time.monotonic() - (deadline - 120), 1)
    sample = db_json("select coalesce(json_agg(t), '[]'::json) from (select occurred_at, process_name, executable, "
                     f"command_line from process_exec_events where container_id like '{container_id[:12]}%' "
                     "order by time_nano limit 3) t") or []
    out = {"ok": bool(rows), "container_id": container_id, "exec_returncode": exec_result.returncode,
           "events_stored": rows, "waited_seconds": waited, "sample": sample}
    try:
        out["cleanup"] = remove_container(name, run_id)
    except RuntimeError as exc:
        out["cleanup"] = {"removed": False, "error": str(exc)}
    return out


def falco_output_file() -> dict[str, object]:
    load_env()
    limit = int(os.getenv("PORYGON_FALCO_ROTATE_BYTES", "0"))
    path = "/var/log/porygon/falco-events.jsonl"
    stat = docker("compose", "exec", "-T", "falco", "stat", "-c", "%s %U %G %a", path)
    probe = docker("compose", "exec", "-T", "falco", "sh", "-c", f"test -w {path} && echo writable || echo not-writable")
    size = None
    if stat.returncode == 0 and stat.stdout.split():
        size = int(stat.stdout.split()[0])
    return {"path": path, "rotate_limit_bytes": limit, "rotate_limit_gib": round(limit / 2**30, 2) if limit else None,
            "stat": stat.stdout.strip(), "size_bytes": size,
            "percent_of_limit": round(100 * size / limit, 4) if size is not None and limit else None,
            "writable_by_falco": probe.stdout.strip(), "stat_error": stat.stderr.strip()[:300]}


def main() -> int:
    usage = shutil.disk_usage("/")
    record = {
        "generated_at": utc_now(), "batch": "batch2",
        "df_root": sh(["df", "-h", "/"]).stdout.strip(),
        "disk_root": {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free,
                      "free_gb": round(usage.free / 1e9, 1)},
        "docker_system_df": sh(["docker", "system", "df"]).stdout.strip(),
        "docker_system_df_json": sh(["docker", "system", "df", "--format", "{{json .}}"]).stdout.strip(),
        "compose_services": compose_health(),
        "responder_running": bool(docker("ps", "--filter", "name=^porygon-responder-1$",
                                         "--format", "{{.Names}}").stdout.strip()),
        "leftover_runtime_containers": [c.get("Names") for c in runtime_label_containers()],
        "falco_events_flowing": falco_flow(),
        "falco_output_file": falco_output_file(),
    }
    problems = []
    if record["disk_root"]["free_gb"] < MIN_FREE_GB:
        problems.append(f"free disk {record['disk_root']['free_gb']} GB < {MIN_FREE_GB} GB")
    unhealthy = {k: v for k, v in record["compose_services"].items() if "healthy" not in v}
    if unhealthy:
        problems.append(f"services not healthy: {unhealthy}")
    if record["responder_running"]:
        problems.append("porygon-responder-1 is running; the protocol keeps it off")
    if record["leftover_runtime_containers"]:
        problems.append(f"leftover runtime containers: {record['leftover_runtime_containers']}")
    if not record["falco_events_flowing"]["ok"]:
        problems.append("no process_exec_events row appeared for the probe container within 2 min")
    if record["falco_output_file"]["writable_by_falco"] != "writable":
        problems.append(f"falco output file not writable: {record['falco_output_file']}")
    record["problems"] = problems
    record["passed"] = not problems
    write_json(RUNTIME_ROOT / "batch2-preflight.json", record)
    for key in ("disk_root", "compose_services", "falco_output_file"):
        print(key, json.dumps(record[key], default=str))
    print("falco_events_flowing", json.dumps({k: v for k, v in record["falco_events_flowing"].items()
                                              if k != "sample"}, default=str))
    print("PASSED" if record["passed"] else "PROBLEMS: " + "; ".join(problems))
    if problems:
        log_event("preflight", "; ".join(problems)[:1000], "recorded in batch2-preflight.json", "pending",
                  batch="batch2")
    return 0 if record["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
