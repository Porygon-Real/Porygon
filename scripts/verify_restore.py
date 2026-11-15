"""Back up a selected Compose database and prove restore into a new private volume.

No backend/responder is started. Restored credentials and unresolved response
intents remain offline; promotion to a running installation requires operator review.
"""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import sqlite3
import subprocess
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
RUN_DEADLINE = None
REQUIRED_TABLES = frozenset(
    {
        "alembic_version",
        "service_heartbeats",
        "runtime_events",
        "process_exec_events",
        "incidents",
        "response_executions",
    }
)


def remaining():
    budget = 60 if RUN_DEADLINE is None else RUN_DEADLINE - time.monotonic()
    if budget <= 0:
        raise TimeoutError("Restore drill deadline exceeded")
    return min(60, budget)


def run(args, **kwargs):
    if "timeout" not in kwargs:
        kwargs["timeout"] = remaining()
    return subprocess.run(args, **kwargs)


def read_snapshot_identifier(stream, timeout):
    """Read a bounded ASCII line without blocking on a partial psql response."""
    deadline = time.monotonic() + timeout
    buffer = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while b"\n" not in buffer:
            budget = deadline - time.monotonic()
            if budget <= 0 or not selector.select(timeout=budget):
                raise TimeoutError("Exported snapshot readiness deadline exceeded")
            chunk = os.read(stream.fileno(), 1024 - len(buffer))
            if not chunk:
                raise RuntimeError("Snapshot holder closed before readiness")
            buffer.extend(chunk)
            if len(buffer) >= 1024 and b"\n" not in buffer:
                raise ValueError("Snapshot identifier exceeds bounded size")
    return bytes(buffer).split(b"\n", 1)[0].decode("ascii").strip()


def command(args, **kwargs):
    return run(args, check=True, capture_output=True, **kwargs).stdout


def sql(container, statement, snapshot_id=None):
    # PostgreSQL password stays inside the container environment, never argv/output.
    if snapshot_id:
        if not re.fullmatch(r"[A-Fa-f0-9-]+", snapshot_id):
            raise ValueError("Invalid exported snapshot")
        statement = (
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '"
            + snapshot_id
            + "'; "
            + statement
            + " COMMIT;"
        )
    return command(
        [
            "docker",
            "exec",
            "-i",
            container,
            "sh",
            "-c",
            'exec psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -qAt',
        ],
        input=statement.encode(),
    ).decode()


def expected_migration_head():
    """Resolve the sole Alembic head from the repository without importing it."""
    revisions = {}
    referenced = set()
    version_dir = ROOT / "backend" / "alembic" / "versions"
    for path in sorted(version_dir.glob("*.py")):
        try:
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            raise ValueError("Cannot read the repository migration graph") from exc
        constants = {}
        for node in module.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in {
                        "revision",
                        "down_revision",
                    }:
                        try:
                            constants[target.id] = ast.literal_eval(node.value)
                        except (ValueError, TypeError):
                            raise ValueError("Migration identifiers must be literals")
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.target.id in {"revision", "down_revision"}:
                    try:
                        constants[node.target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        raise ValueError("Migration identifiers must be literals")
        revision = constants.get("revision")
        parents = constants.get("down_revision")
        if not isinstance(revision, str) or not revision:
            continue
        if revision in revisions:
            raise ValueError("Duplicate Alembic revision identifier")
        if parents is None:
            parent_ids = ()
        elif isinstance(parents, str):
            parent_ids = (parents,)
        elif isinstance(parents, (tuple, list)) and all(
            isinstance(parent, str) for parent in parents
        ):
            parent_ids = tuple(parents)
        else:
            raise ValueError("Unsupported Alembic down-revision declaration")
        revisions[revision] = parent_ids
        referenced.update(parent_ids)
    if not revisions or not referenced.issubset(revisions):
        raise ValueError("Repository Alembic migration graph is incomplete")
    heads = set(revisions) - referenced
    if len(heads) != 1:
        raise ValueError("Restore requires exactly one repository Alembic head")
    return next(iter(heads))


def snapshot(container, snapshot_id=None, expected_head=None):
    tables = sql(
        container,
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;",
        snapshot_id,
    ).splitlines()
    if not REQUIRED_TABLES.issubset(tables):
        raise ValueError("Source database is not initialized to the required schema")
    if not expected_head:
        raise ValueError("Repository Alembic head is required for restore")
    heads = sql(container, "SELECT version_num FROM alembic_version;", snapshot_id).splitlines()
    if heads != [expected_head]:
        raise ValueError("Source database is not at the repository Alembic head")
    heartbeat_count = sql(
        container, "SELECT count(*) FROM service_heartbeats;", snapshot_id
    ).strip()
    if not heartbeat_count.isdigit() or int(heartbeat_count) < 1:
        raise ValueError("Source database contains no restorable heartbeat evidence")
    result = {}
    for table in tables:
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", table):
            raise ValueError("Unexpected database identifier")
        # Hash each full row server-side, then hash the sorted digests. No values leave PostgreSQL.
        rows = sql(
            container,
            f'SELECT md5(row_to_json(t)::text) FROM "{table}" t ORDER BY 1;',
            snapshot_id,
        ).splitlines()
        result[table] = {
            "rows": len(rows),
            "row_digest_sha256": hashlib.sha256("\n".join(rows).encode()).hexdigest(),
        }
    return result


def verify(
    output, destination_project=None, *, rpo_target_seconds=3600, rto_target_seconds=600
):
    global RUN_DEADLINE
    RUN_DEADLINE = time.monotonic() + rto_target_seconds
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("Use a new private output directory")
    output.mkdir(mode=0o700, parents=True)
    source = (
        command(["docker", "compose", "ps", "-q", "postgres"], cwd=ROOT)
        .decode()
        .strip()
    )
    if not re.fullmatch(r"[a-f0-9]{12,64}", source):
        raise ValueError("Exactly one active source database is required")
    source_info = json.loads(command(["docker", "inspect", source]))[0]
    active_project = (
        source_info.get("Config", {})
        .get("Labels", {})
        .get("com.docker.compose.project")
    )
    project = destination_project or "porygon-restore-" + uuid4().hex[:12]
    if (
        not re.fullmatch(r"porygon-restore-[a-z0-9-]{6,40}", project)
        or project == active_project
    ):
        raise ValueError("Restore requires a fresh porygon-restore-* project")
    volume = project + "-database"
    container = project + "-postgres"
    active_volumes = {
        item.get("Name")
        for item in source_info.get("Mounts", [])
        if item.get("Type") == "volume"
    }
    if volume in active_volumes:
        raise ValueError("Active volume cannot be a restore destination")
    migration_head = expected_migration_head()
    # Refuse every pre-existing destination, including a previous failed drill.
    for kind, name in (("volume", volume), ("container", container)):
        exists = (
            run(["docker", kind, "inspect", name], capture_output=True).returncode == 0
        )
        if exists:
            raise ValueError("Restore destination already exists")
    started = time.monotonic()
    created_at = datetime.now(timezone.utc).isoformat()
    snapshot_time = datetime.now(timezone.utc)
    holder = subprocess.Popen(
        [
            "docker",
            "exec",
            "-i",
            source,
            "sh",
            "-c",
            'exec psql -X -qAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        idle_ms = max(1000, int((RUN_DEADLINE - time.monotonic()) * 1000))
        statement = (
            f"SET statement_timeout='30000ms'; SET idle_in_transaction_session_timeout='{idle_ms}ms'; "
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT pg_export_snapshot();\n"
        )
        holder.stdin.write(statement.encode())
        holder.stdin.flush()
        snapshot_id = read_snapshot_identifier(holder.stdout, min(10, remaining()))
        if not re.fullmatch(r"[A-Fa-f0-9-]+", snapshot_id):
            raise RuntimeError("Could not export read-only database snapshot")
        before = snapshot(source, snapshot_id, migration_head)
        dump = output / "database.dump"
        descriptor = os.open(dump, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            run(
                [
                    "docker",
                    "exec",
                    source,
                    "sh",
                    "-c",
                    'PGOPTIONS="-c statement_timeout=60000 -c lock_timeout=5000" exec pg_dump -Fc --lock-wait-timeout=5000 --snapshot "$1" -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                    "restore-snapshot",
                    snapshot_id,
                ],
                stdout=handle,
                stderr=subprocess.PIPE,
                check=True,
            )
    finally:
        if holder.stdin:
            try:
                holder.stdin.write(b"ROLLBACK;\n")
                holder.stdin.flush()
            except BrokenPipeError:
                pass
            holder.stdin.close()
        try:
            holder.wait(timeout=10)
        except subprocess.TimeoutExpired:
            holder.kill()
            holder.wait()
    responder = (
        command(["docker", "compose", "ps", "-q", "responder"], cwd=ROOT)
        .decode()
        .strip()
    )
    if not re.fullmatch(r"[a-f0-9]{12,64}", responder):
        raise ValueError("Active responder receipt store is required")
    receipt_backup = output / "response-receipts.sqlite"
    descriptor = os.open(receipt_backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        run(
            [
                "docker",
                "exec",
                responder,
                "python",
                "-c",
                'import os,sqlite3,tempfile,sys,time; started=time.monotonic(); source=sqlite3.connect("file:"+os.environ.get("PORYGON_COMPLETION_STORE_PATH","/var/lib/porygon/completions.sqlite")+"?mode=ro",uri=True); '
                "fd,path=tempfile.mkstemp(); os.close(fd); target=sqlite3.connect(path); "
                "progress=lambda status,remaining,total: (_ for _ in ()).throw(TimeoutError()) if time.monotonic()-started>30 else None; "
                "source.backup(target,pages=128,progress=progress,sleep=0.1); target.close(); source.close(); "
                'sys.stdout.buffer.write(open(path,"rb").read()); os.unlink(path)',
            ],
            stdout=handle,
            stderr=subprocess.PIPE,
            check=True,
        )
    with sqlite3.connect(
        "file:" + str(receipt_backup) + "?mode=ro", uri=True
    ) as receipts:
        if receipts.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Response receipt backup integrity failed")
    receipt_hash = hashlib.sha256(receipt_backup.read_bytes()).hexdigest()
    label = "com.porygon.restore-drill=" + project
    created_volume = False
    created_container = False
    try:
        command(["docker", "volume", "create", "--label", label, volume])
        volume_info = json.loads(command(["docker", "volume", "inspect", volume]))[0]
        if volume_info.get("Labels", {}).get("com.porygon.restore-drill") != project:
            raise ValueError("Destination volume ownership changed")
        created_volume = True
        with tempfile.NamedTemporaryFile(
            "w", dir=output, prefix=".restore-env-", delete=False
        ) as handle:
            private_env = Path(handle.name)
            os.chmod(private_env, 0o600)
            handle.write(
                "POSTGRES_USER=porygon_restore\nPOSTGRES_DB=porygon_restore\nPOSTGRES_PASSWORD="
                + secrets.token_urlsafe(48)
                + "\n"
            )
        try:
            command(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    container,
                    "--label",
                    label,
                    "--network",
                    "none",
                    "--env-file",
                    str(private_env),
                    "--mount",
                    f"type=volume,src={volume},dst=/var/lib/postgresql/data",
                    source_info["Image"],
                ]
            )
            created_container = True
        finally:
            private_env.unlink(missing_ok=True)
        deadline = time.monotonic() + 90
        while True:
            ready = (
                run(
                    [
                        "docker",
                        "exec",
                        container,
                        "pg_isready",
                        "-U",
                        "porygon_restore",
                        "-d",
                        "porygon_restore",
                    ],
                    capture_output=True,
                ).returncode
                == 0
            )
            if ready:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Disposable database readiness deadline exceeded")
            time.sleep(1)
        with dump.open("rb") as handle:
            run(
                [
                    "docker",
                    "exec",
                    "-i",
                    "-e",
                    "PGOPTIONS=-c statement_timeout=60000 -c lock_timeout=5000",
                    container,
                    "pg_restore",
                    "--exit-on-error",
                    "--no-owner",
                    "--no-privileges",
                    "-U",
                    "porygon_restore",
                    "-d",
                    "porygon_restore",
                ],
                stdin=handle,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
            )
        restored = snapshot(container, expected_head=migration_head)
        source_after = json.loads(command(["docker", "inspect", source]))[0]
        preserved = source_after["Id"] == source_info["Id"] and source_after.get(
            "Mounts"
        ) == source_info.get("Mounts")
        snapshot_age = (datetime.now(timezone.utc) - snapshot_time).total_seconds()
        report = {
            "contract": "porygon.restore-drill",
            "alembic_head": migration_head,
            "started_at": created_at,
            "source_project": active_project,
            "destination_project": project,
            "destination_network": "none",
            "source_image_id": source_info["Image"],
            "dump_sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
            "source_before": before,
            "restored": restored,
            "restore_matches_snapshot": before == restored,
            "source_objects_preserved": preserved,
            "source_access": "read-only-exported-snapshot",
            "snapshot_at": snapshot_time.isoformat(),
            "snapshot_age_seconds": snapshot_age,
            "rpo_target_seconds": rpo_target_seconds,
            "rto_target_seconds": rto_target_seconds,
            "elapsed_seconds": time.monotonic() - started,
            "response_intents": "offline-operator-review-required",
            "receipt_recovery": {
                "sha256": receipt_hash,
                "integrity": "ok",
                "state": "offline-operator-review-required",
            },
            "passed": before == restored
            and preserved
            and snapshot_age <= rpo_target_seconds
            and time.monotonic() - started <= rto_target_seconds,
        }
        descriptor = os.open(
            output / "report.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "w") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
        return report
    finally:
        # Only remove exact objects created in this invocation and carrying its label.
        if created_container:
            info = json.loads(command(["docker", "inspect", container], timeout=15))[0]
            if info["Config"]["Labels"].get("com.porygon.restore-drill") == project:
                command(["docker", "rm", "-f", container], timeout=15)
        if created_volume:
            info = json.loads(
                command(["docker", "volume", "inspect", volume], timeout=15)
            )[0]
            if info["Labels"].get("com.porygon.restore-drill") == project:
                command(["docker", "volume", "rm", volume], timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--destination-project")
    parser.add_argument("--rpo-target-seconds", type=int, default=3600)
    parser.add_argument("--rto-target-seconds", type=int, default=600)
    args = parser.parse_args()
    if args.rpo_target_seconds <= 0 or args.rto_target_seconds <= 0:
        parser.error("Recovery targets must be positive")
    try:
        report = verify(
            args.output,
            args.destination_project,
            rpo_target_seconds=args.rpo_target_seconds,
            rto_target_seconds=args.rto_target_seconds,
        )
    except (ValueError, OSError, subprocess.SubprocessError, RuntimeError) as exc:
        failure = {"passed": False, "error_category": type(exc).__name__}
        if args.output.is_dir():
            descriptor = os.open(
                args.output / "failure.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "w") as handle:
                json.dump(failure, handle)
        print(json.dumps(failure))
        return 1
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "passed",
                    "elapsed_seconds",
                    "restore_matches_snapshot",
                    "source_objects_preserved",
                )
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
