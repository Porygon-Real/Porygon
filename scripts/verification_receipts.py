"""Write and validate private, source-bound receipts for local verification runs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

try:
    from scripts.source_identity import source_identity
except ModuleNotFoundError:
    from source_identity import source_identity


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "porygon.ingestion-receipt"
MAX_AGE_SECONDS = 24 * 60 * 60
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
STAGE_FIELDS = {
    "saturation": {
        "configured_event_limit",
        "observed_outbox_count",
        "current_run_canary_count",
        "overflow_before",
        "overflow_after",
        "overflow_delta",
        "docker_api_event_count",
        "requested_exec_operations",
        "initial_queue_depth",
    },
    "persistence": {
        "api_event_count",
        "postgres_row_count",
        "replay_count_before",
        "replay_count_after",
        "replay_row_growth",
        "final_queue_depth",
        "final_queue_observed_at_ns",
    },
}


def _safe_run_id(value: str) -> str:
    if not RUN_ID_RE.fullmatch(value) or ".." in value:
        raise ValueError("invalid run identifier")
    return value


def _evidence_directory(root: Path, run_id: str, directory: Path) -> Path:
    root = root.resolve()
    artifacts = root / "artifacts"
    local = artifacts / "local"
    expected = local / f"ingest-{_safe_run_id(run_id)}"
    candidate = Path(directory)
    if candidate.absolute() != expected.absolute():
        raise ValueError("receipt directory is not confined to this run")
    if any(path.is_symlink() for path in (artifacts, local, expected)):
        raise ValueError("receipt path cannot traverse symlinks")
    return expected


def _source_binding(root: Path) -> tuple[str, str, str]:
    identity = source_identity(root)
    verifier_hash = hashlib.sha256(
        (root / "scripts" / "verify_event_ingestion.sh").read_bytes()
    ).hexdigest()
    return identity["commit"], identity["tree_sha256"], verifier_hash


def _numeric_fields(stage: str, values: dict[str, str | int]) -> dict[str, int]:
    if stage not in STAGE_FIELDS or set(values) != STAGE_FIELDS[stage]:
        raise ValueError("receipt fields do not match the stage contract")
    result: dict[str, int] = {}
    for name, value in values.items():
        if type(value) is int:
            number = value
        elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
            number = int(value)
        else:
            raise ValueError("receipt counters must be unsigned integers")
        result[name] = number

    if stage == "saturation":
        if (
            result["configured_event_limit"] != 100
            or result["observed_outbox_count"] != 100
            or result["current_run_canary_count"] <= 0
            or result["current_run_canary_count"] > result["configured_event_limit"]
            or result["overflow_after"] - result["overflow_before"]
            != result["overflow_delta"]
            or result["overflow_delta"] <= 0
            or result["docker_api_event_count"] <= 100
            or result["requested_exec_operations"] <= 0
            or result["initial_queue_depth"] != 0
        ):
            raise ValueError("saturation evidence did not meet its acceptance contract")
    else:
        if (
            result["api_event_count"] <= 0
            or result["postgres_row_count"] != result["api_event_count"]
            or result["replay_count_before"] != result["api_event_count"]
            or result["replay_count_after"] != result["api_event_count"]
            or result["replay_count_before"] != result["replay_count_after"]
            or result["replay_row_growth"] != 0
            or result["final_queue_depth"] != 0
            or result["final_queue_observed_at_ns"] <= 0
        ):
            raise ValueError("persistence evidence did not meet its acceptance contract")
    return result


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    payload = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # A run identifier is not reusable evidence: refuse to replace an earlier
        # receipt even if a verifier is restarted with the same identifier.
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_replace(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    payload = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _status_document(results_path: Path) -> list[dict[str, object]]:
    entries = []
    for line in results_path.read_text(encoding="utf-8").splitlines():
        name, status, duration, command = line.split("\t", 3)
        if status not in {"passed", "failed"} or not duration.isdigit():
            raise ValueError("invalid verification stage result")
        if not re.fullmatch(r"[a-z0-9-]+", name) or not re.fullmatch(
            r"[a-z0-9][a-z0-9 -]{0,127}", command
        ):
            raise ValueError("verification result labels must be sanitized")
        entries.append(
            {
                "name": name,
                "status": status,
                "duration_seconds": int(duration),
                "command": command,
            }
        )
    return entries


def write_status(
    *,
    run_id: str,
    results_path: Path,
    status: str,
    completed: bool,
    root: Path = ROOT,
) -> Path:
    run_id = _safe_run_id(run_id)
    if status not in {"running", "passed", "failed", "interrupted"}:
        raise ValueError("invalid aggregate status")
    if completed != (status in {"passed", "failed"}):
        raise ValueError("completion flag and aggregate status disagree")
    script_hash = hashlib.sha256((root / "scripts" / "verify_all.sh").read_bytes()).hexdigest()
    target = root / "artifacts" / "local" / "verification-runs" / run_id / "stages.json"
    document: dict[str, object] = {
        "schema_version": "porygon.verification-stages",
        "run_id": run_id,
        "status": status,
        "completed": completed,
        "verify_all_sha256": script_hash,
        "stages": _status_document(results_path),
    }
    _atomic_replace(target, document)
    return target


def write_receipt(
    *,
    stage: str,
    run_id: str,
    host_id: str,
    directory: Path,
    values: dict[str, str | int],
    root: Path = ROOT,
    now_epoch: float | None = None,
) -> Path:
    run_id = _safe_run_id(run_id)
    if not host_id or len(host_id) > 256 or any(ord(char) < 32 for char in host_id):
        raise ValueError("invalid source host identifier")
    numeric_values = _numeric_fields(stage, values)
    target = _evidence_directory(root, run_id, directory) / f"{stage}.json"
    commit, tree_hash, verifier_hash = _source_binding(root)
    timestamp = time.time() if now_epoch is None else now_epoch
    document: dict[str, object] = {
        "schema_version": SCHEMA,
        "stage": stage,
        "status": "passed",
        "run_id": run_id,
        "source_host_id": host_id,
        "source_commit": commit,
        "source_tree_sha256": tree_hash,
        "verifier_sha256": verifier_hash,
        "created_at_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "created_at_epoch": timestamp,
        "counters": numeric_values,
    }
    _atomic_json(target, document)
    return target


def _read_receipt(
    *,
    stage: str,
    run_id: str,
    host_id: str,
    directory: Path,
    root: Path,
    now_epoch: float,
    max_age_seconds: int,
) -> dict[str, object]:
    path = _evidence_directory(root, run_id, directory) / f"{stage}.json"
    if path.parent.stat().st_mode & 0o077:
        raise ValueError("receipt directory permissions are unsafe")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("receipt file permissions or type are unsafe")
    if info.st_size <= 0 or info.st_size > 64 * 1024:
        raise ValueError("receipt is empty or oversized")
    document = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
    )
    if not isinstance(document, dict):
        raise ValueError("receipt document must be an object")
    commit, tree_hash, verifier_hash = _source_binding(root)
    if (
        document.get("schema_version") != SCHEMA
        or document.get("stage") != stage
        or document.get("status") != "passed"
        or document.get("run_id") != run_id
        or document.get("source_host_id") != host_id
        or document.get("source_commit") != commit
        or document.get("source_tree_sha256") != tree_hash
        or document.get("verifier_sha256") != verifier_hash
    ):
        raise ValueError("receipt binding mismatch")
    created = document.get("created_at_epoch")
    if (
        type(created) not in (int, float)
        or not math.isfinite(created)
        or created > now_epoch
        or now_epoch - created > max_age_seconds
    ):
        raise ValueError("receipt is stale or has an invalid timestamp")
    created_utc = document.get("created_at_utc")
    try:
        parsed_created = datetime.fromisoformat(created_utc)
    except (TypeError, ValueError) as exc:
        raise ValueError("receipt UTC timestamp is invalid") from exc
    if (
        parsed_created.tzinfo is None
        or abs(parsed_created.timestamp() - created) > 1.0
    ):
        raise ValueError("receipt timestamps disagree")
    counters = document.get("counters")
    if not isinstance(counters, dict):
        raise ValueError("receipt counters are missing")
    validated = _numeric_fields(stage, counters)
    if validated != counters:
        raise ValueError("receipt counters are malformed")
    return document


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate receipt field")
        result[key] = value
    return result


def validate_receipts(
    *,
    run_id: str,
    host_id: str,
    directory: Path,
    root: Path = ROOT,
    now_epoch: float | None = None,
    max_age_seconds: int = MAX_AGE_SECONDS,
) -> tuple[dict[str, object], dict[str, object]]:
    run_id = _safe_run_id(run_id)
    if not host_id or len(host_id) > 256 or any(ord(char) < 32 for char in host_id):
        raise ValueError("invalid source host identifier")
    timestamp = time.time() if now_epoch is None else now_epoch
    saturation = _read_receipt(
        stage="saturation",
        run_id=run_id,
        host_id=host_id,
        directory=directory,
        root=root,
        now_epoch=timestamp,
        max_age_seconds=max_age_seconds,
    )
    persistence = _read_receipt(
        stage="persistence",
        run_id=run_id,
        host_id=host_id,
        directory=directory,
        root=root,
        now_epoch=timestamp,
        max_age_seconds=max_age_seconds,
    )
    sat_counters = saturation["counters"]
    persist_counters = persistence["counters"]
    if (
        saturation["created_at_epoch"] > persistence["created_at_epoch"]
        or sat_counters["docker_api_event_count"] != persist_counters["api_event_count"]
        or sat_counters["docker_api_event_count"] != persist_counters["postgres_row_count"]
        or sat_counters["current_run_canary_count"] > sat_counters["observed_outbox_count"]
    ):
        raise ValueError("receipt stages are inconsistent")
    return saturation, persistence


def _parse_fields(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key or key in result:
            raise ValueError("invalid receipt field")
        result[key] = item
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    write_parser = subparsers.add_parser("write")
    write_parser.add_argument("--stage", choices=tuple(STAGE_FIELDS), required=True)
    write_parser.add_argument("--run-id", required=True)
    write_parser.add_argument("--host-id", required=True)
    write_parser.add_argument("--directory", type=Path, required=True)
    write_parser.add_argument("--field", action="append", default=[])
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--run-id", required=True)
    validate_parser.add_argument("--host-id", required=True)
    validate_parser.add_argument("--directory", type=Path, required=True)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--run-id", required=True)
    status_parser.add_argument("--results", type=Path, required=True)
    status_parser.add_argument("--status", choices=("running", "passed", "failed", "interrupted"), required=True)
    status_parser.add_argument("--completed", choices=("true", "false"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "write":
            write_receipt(
                stage=args.stage,
                run_id=args.run_id,
                host_id=args.host_id,
                directory=args.directory,
                values=_parse_fields(args.field),
                root=ROOT,
            )
            print(f"{args.stage} receipt persisted")
        elif args.action == "validate":
            validate_receipts(
                run_id=args.run_id,
                host_id=args.host_id,
                directory=args.directory,
                root=ROOT,
            )
            print("saturation and persistence receipts validated")
        else:
            write_status(
                run_id=args.run_id,
                results_path=args.results,
                status=args.status,
                completed=args.completed == "true",
                root=ROOT,
            )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print("verification receipt rejected", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
