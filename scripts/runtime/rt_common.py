"""Shared helpers for the runtime monitoring dataset (scripts/runtime/).

Builds on scripts/dataset/common.py. Nothing here creates data values: helpers
only run real containers, call Porygon's own API, and read Porygon's database.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dataset"))
from common import ROOT, ApiError, load_env, psql, read_json, sha256_file, utc_now, write_json  # noqa: E402,F401

RUNTIME_ROOT = ROOT / "datasets" / "runtime"
# Which collection batch this process belongs to; every run-log line records it.
BATCH = os.environ.get("PORYGON_RT_BATCH") or "batch1"
RAW_ROOT = Path(os.environ.get("PORYGON_RT_RAW_ROOT") or RUNTIME_ROOT / "raw")  # override only for smoke tests
# Override only for smoke tests and recipe checks, whose output stays outside datasets/.
RUN_LOG = Path(os.environ.get("PORYGON_RT_RUN_LOG") or RUNTIME_ROOT / "run-log.jsonl")
BASE_URL = "http://127.0.0.1:8000"
LABEL = "porygon.runtime"
PLATFORM = "linux/arm64"
RELAY_IMAGE = "nginxinc/nginx-unprivileged:1.29.3-alpine-slim"
DIGEST_RE = re.compile(r"^[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def log_event(step: str, failed: str, action: str, result: str, **extra: Any) -> None:
    RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {"time": utc_now(), "step": step, "failed": failed, "action": action, "result": result,
              "batch": BATCH, **extra}
    with RUN_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")


def sh(command: list[str], *, timeout: int = 120, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, input=input_text, check=False)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(command, 124, exc.stdout or "", f"timeout after {timeout}s")


def docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return sh(["docker", *args], timeout=timeout)


def internal_api(method: str, path: str, payload: dict[str, Any] | None = None, *, timeout: int = 120) -> Any:
    load_env()
    token = os.getenv("PORYGON_INTERNAL_API_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("PORYGON_INTERNAL_API_TOKEN is missing from .env")
    headers = {"Accept": "application/json", "X-Porygon-Internal-Token": token}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise ApiError(exc.code, f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:800]}") from exc
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        raise ApiError(None, f"Could not reach Porygon API: {getattr(exc, 'reason', exc)}") from exc


def api_with_retry(method: str, path: str, payload: dict[str, Any] | None = None, *, attempts: int = 4,
                   step: str = "api") -> tuple[Any | None, list[str]]:
    """First try plus 3 retries. Returns (result or None, list of error strings)."""
    errors: list[str] = []
    for attempt in range(attempts):
        try:
            result = internal_api(method, path, payload)
            if errors:
                log_event(step, f"{method} {path}: {errors[-1]}", f"retried (attempt {attempt + 1})", "ok")
            return result, errors
        except ApiError as exc:
            errors.append(str(exc))
            if exc.status is not None and 400 <= exc.status < 500 and exc.status not in (408, 409, 429):
                break
            time.sleep(5 * (attempt + 1))
    log_event(step, f"{method} {path}: {errors[-1]}", f"tried {len(errors)} times", "recorded as failed")
    return None, errors


def check_digest(value: str) -> str:
    if not DIGEST_RE.match(value):
        raise ValueError(f"unexpected image digest: {value!r}")
    return value


def db_json(sql: str, *, timeout: int = 600) -> Any:
    out = psql(sql, timeout=timeout).strip()
    return json.loads(out) if out else None


EVENT_COLUMNS = ("event_id, occurred_at, time_nano, container_id, container_name, image_digest, process_pid, "
                 "process_ppid, process_name, executable, command_line, parent_name, parent_executable, "
                 "parent_command_line, user_uid, user_name, rule_name, correlation_status")


def process_events(image_digest: str, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """Porygon's stored process events for one digest in [start, end)."""
    digest = check_digest(image_digest)
    sql = (f"select coalesce(json_agg(t order by t.time_nano), '[]'::json) from (select {EVENT_COLUMNS} "
           f"from process_exec_events where image_digest = '{digest}' and occurred_at >= '{iso(start)}' "
           f"and occurred_at < '{iso(end)}') t")
    return db_json(sql) or []


def runtime_label_containers() -> list[dict[str, str]]:
    out = docker("ps", "-a", "--filter", f"label={LABEL}", "--format", "{{json .}}").stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def labels_of(kind: str, name: str) -> dict[str, str]:
    fmt = "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}"
    out = docker(kind, "inspect", "--format", fmt, name).stdout.strip()
    try:
        return json.loads(out) or {} if out and out != "null" else {}
    except json.JSONDecodeError:
        return {}


def remove_container(name: str, run_id: str) -> dict[str, Any]:
    """Remove one container only when its exact name and runtime label both match."""
    names = [n for n in docker("ps", "-a", "--filter", f"name=^{re.escape(name)}$", "--format", "{{.Names}}")
             .stdout.splitlines() if n]
    if not names:
        return {"removed": False, "reason": "absent"}
    if names != [name]:
        raise RuntimeError(f"refusing ambiguous cleanup target: {names}")
    if labels_of("container", name).get(LABEL) != run_id:
        raise RuntimeError(f"refusing to remove container without matching {LABEL} label: {name}")
    result = docker("rm", "--force", name)
    return {"removed": result.returncode == 0, "name": name, "stderr": result.stderr.strip()}


def remove_network(name: str, run_id: str) -> dict[str, Any]:
    names = [n for n in docker("network", "ls", "--filter", f"name=^{re.escape(name)}$", "--format", "{{.Name}}")
             .stdout.splitlines() if n]
    if not names:
        return {"removed": False, "reason": "absent"}
    if names != [name] or labels_of("network", name).get(LABEL) != run_id:
        raise RuntimeError(f"refusing to remove network {name}")
    result = docker("network", "rm", name)
    return {"removed": result.returncode == 0, "name": name, "stderr": result.stderr.strip()}
