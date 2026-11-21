"""Shared helpers for the daily vulnerability dataset scripts.

Standard library only. Nothing here creates or alters data values: helpers only
read from Docker, the Porygon API, and files written by earlier steps.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PANEL_PATH = Path(__file__).resolve().parent / "panel.json"
DATASET_ROOT = ROOT / "datasets" / "vuln-daily"
DEFAULT_BASE_URL = "http://127.0.0.1:8000"

# Reuse the backend's own CVSS selection and CVE-ID rule so the dataset and
# Porygon's stored findings agree by construction. The module is stdlib-only.
sys.path.insert(0, str(ROOT / "backend" / "src"))
from porygon_api.vulnerability import CVE_PATTERN, _cvss, sha256_document  # noqa: E402,F401


class ApiError(RuntimeError):
    def __init__(self, status: int | None, message: str):
        super().__init__(message)
        self.status = status


def load_env() -> None:
    env_file = ROOT / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def api(method: str, url: str, *, operator: bool = False, payload: dict[str, Any] | None = None, timeout: int = 120) -> Any:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if operator:
        load_env()
        token = os.getenv("PORYGON_OPERATOR_API_TOKEN", "")
        if len(token) < 32:
            raise SystemExit("PORYGON_OPERATOR_API_TOKEN is missing from .env")
        headers["X-Porygon-Operator-Token"] = token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ApiError(exc.code, f"HTTP {exc.code}: {detail[:500]}") from exc
    except urllib.error.URLError as exc:
        raise ApiError(None, f"Could not reach Porygon API: {exc.reason}") from exc


def run(command: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def psql(sql: str, *, timeout: int = 600) -> str:
    """Read-only query against Porygon's own PostgreSQL store.

    Used where the API's per-scan detail endpoint is too large to pass through the
    gateway (it returns every finding with full text; ~200 MB for large images).
    """
    load_env()
    result = run(
        ["docker", "compose", "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-q",
         "-U", os.environ["POSTGRES_USER"], "-d", os.environ["POSTGRES_DB"], "-tA", "-c", sql],
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"psql failed: {result.stderr.strip()[:500]}")
    return result.stdout


def scan_record(base: str, scan_id: str, image_digest: str) -> dict:
    """Small scan summary from the list endpoint (avoids the oversized detail endpoint)."""
    from urllib.parse import urlencode
    rows = api("GET", f"{base}/api/v1/image-scans?{urlencode({'image_digest': image_digest, 'limit': 500})}")
    for row in rows:
        if row["scan_id"] == scan_id:
            return row
    raise RuntimeError(f"scan {scan_id} not found in scan list")


def backend_finding_count(scan_id: str) -> int:
    if not all(c in "0123456789abcdef-" for c in scan_id):
        raise ValueError("unexpected scan id")
    return int(psql(f"select count(*) from vulnerability_findings where scan_id = '{scan_id}'").strip())


def stored_document(table: str, scan_id: str) -> dict[str, Any]:
    """Read a Trivy report / SBOM exactly as Porygon stored it, and verify it against
    the SHA-256 Porygon recorded at ingest. Reports for large images (50+ MB) exceed
    the gateway's 16 MB proxy buffer, so they are read from the database instead."""
    if table not in ("vulnerability_report_artifacts", "sbom_artifacts"):
        raise ValueError(table)
    if not all(c in "0123456789abcdef-" for c in scan_id):
        raise ValueError("unexpected scan id")
    text = psql(f"select document_sha256 || E'\\t' || document::text from {table} where scan_id = '{scan_id}'")
    if not text.strip():
        raise RuntimeError(f"no {table} row for scan {scan_id}")
    stored_sha, body = text.rstrip("\n").split("\t", 1)
    document = json.loads(body)
    if sha256_document(document) != stored_sha:
        raise RuntimeError(f"{table} for {scan_id} does not match Porygon's stored checksum")
    return document


def load_panel() -> dict[str, Any]:
    return json.loads(PANEL_PATH.read_text(encoding="utf-8"))


def day_number(panel: dict[str, Any], on: date) -> int:
    return (on - date.fromisoformat(panel["start_date"])).days + 1


def images_for_day(panel: dict[str, Any], on: date) -> list[dict[str, str]]:
    """Fixed images (after any recorded substitutions) plus that day's rotating images."""
    fixed = list(panel["fixed"])
    for sub in panel.get("substitutions", []):
        if on >= date.fromisoformat(sub["effective_date"]):
            fixed = [sub["replacement"] if tag == sub["replaced"] else tag for tag in fixed]
    rotating = panel["rotating"].get(str(day_number(panel, on)), [])
    return [{"tag": t, "panel": "fixed"} for t in fixed] + [{"tag": t, "panel": "rotating"} for t in rotating]


def day_dir(on: date) -> Path:
    return DATASET_ROOT / on.isoformat()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Unique temp name per write, so two writers can never remove each other's temp file.
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def parse_date(value: str | None) -> date:
    return date.fromisoformat(value) if value else date.today()
