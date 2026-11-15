"""Disposable restore ownership and deadline failures never authorize source writes."""

import os
from types import SimpleNamespace
import pytest
from scripts import verify_restore as restore


def test_every_subprocess_uses_remaining_deadline_and_expiry_prevents_launch(
    monkeypatch,
):
    calls = []
    monkeypatch.setattr(restore.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(restore, "RUN_DEADLINE", 12.0)
    monkeypatch.setattr(
        restore.subprocess,
        "run",
        lambda args, **kwargs: (
            calls.append((args, kwargs)) or SimpleNamespace(stdout=b"ok")
        ),
    )
    assert restore.command(["docker", "inspect", "owned"]) == b"ok"
    assert calls[0][1]["timeout"] == 2.0
    monkeypatch.setattr(restore, "RUN_DEADLINE", 9.0)
    with pytest.raises(TimeoutError):
        restore.command(["docker", "exec", "source", "pg_dump"])
    assert len(calls) == 1


def test_cleanup_can_remain_bounded_after_main_deadline(monkeypatch):
    calls = []
    monkeypatch.setattr(restore, "RUN_DEADLINE", 0)
    monkeypatch.setattr(
        restore.subprocess,
        "run",
        lambda args, **kwargs: calls.append(kwargs) or SimpleNamespace(stdout=b""),
    )
    restore.command(["docker", "rm", "exact-owned-id"], timeout=15)
    assert calls[0]["timeout"] == 15


def test_sql_attaches_stdin_to_docker_exec(monkeypatch):
    calls = []

    def fake_command(args, **kwargs):
        calls.append((args, kwargs))
        return b"result"

    monkeypatch.setattr(restore, "command", fake_command)
    assert restore.sql("source-id", "SELECT 1;") == "result"
    assert calls[0][0][:3] == ["docker", "exec", "-i"]
    assert calls[0][1]["input"] == b"SELECT 1;"


def test_partial_snapshot_line_times_out_without_blocking():
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"partial-without-newline")
        with os.fdopen(read_fd, "rb", buffering=0) as stream:
            with pytest.raises(TimeoutError):
                restore.read_snapshot_identifier(stream, 0.02)
    finally:
        os.close(write_fd)


def test_snapshot_reader_has_size_bound_and_accepts_complete_line():
    for value, expected in (
        (b"00000003-0000001B-1\n", "00000003-0000001B-1"),
        (b"x" * 1024, None),
    ):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, value)
            with os.fdopen(read_fd, "rb", buffering=0) as stream:
                if expected:
                    assert restore.read_snapshot_identifier(stream, 1) == expected
                else:
                    with pytest.raises(ValueError):
                        restore.read_snapshot_identifier(stream, 1)
        finally:
            os.close(write_fd)


def test_repository_migration_graph_resolves_one_head():
    assert restore.expected_migration_head()


def test_active_restore_project_is_refused_before_dump_or_target_mutation(
    monkeypatch, tmp_path
):
    calls = []
    source = {
        "Id": "a" * 64,
        "Config": {"Labels": {"com.docker.compose.project": "porygon-restore-active"}},
        "Mounts": [],
    }

    def fake_command(args, **kwargs):
        calls.append(args)
        if args == ["docker", "compose", "ps", "-q", "postgres"]:
            return ("a" * 64).encode()
        if args == ["docker", "inspect", "a" * 64]:
            import json

            return json.dumps([source]).encode()
        raise AssertionError("No dump/restore/volume mutation should be reached")

    monkeypatch.setattr(restore, "command", fake_command)
    with pytest.raises(ValueError):
        restore.verify(tmp_path / "private-output", "porygon-restore-active")
    assert all(
        "pg_dump" not in str(args) and "create" not in args and "run" not in args
        for args in calls
    )


@pytest.mark.parametrize(
    ("tables", "head_rows", "heartbeat_count"),
    [
        ((), ("expected-head",), "1"),
        (tuple(restore.REQUIRED_TABLES), ("wrong-head",), "1"),
        (tuple(restore.REQUIRED_TABLES), (), "1"),
        (tuple(restore.REQUIRED_TABLES - {"incidents"}), ("expected-head",), "1"),
        (tuple(restore.REQUIRED_TABLES), ("expected-head",), "0"),
    ],
    ids=("empty-schema", "wrong-head", "missing-head", "missing-table", "empty-heartbeats"),
)
def test_uninitialized_or_inconsistent_source_refuses_before_target_creation(
    monkeypatch, tmp_path, tables, head_rows, heartbeat_count
):
    import json

    source_id = "a" * 64
    source_info = {
        "Id": source_id,
        "Config": {"Labels": {"com.docker.compose.project": "porygon-service-trust"}},
        "Mounts": [],
    }
    mutations = []
    row_hash_queries = []

    def fake_command(args, **kwargs):
        mutations.append(args)
        if args == ["docker", "compose", "ps", "-q", "postgres"]:
            return source_id.encode()
        if args == ["docker", "inspect", source_id]:
            return json.dumps([source_info]).encode()
        raise AssertionError(f"Unexpected command before source validation: {args}")

    def fake_run(args, **kwargs):
        mutations.append(args)
        assert args[:3] in (
            ["docker", "volume", "inspect"],
            ["docker", "container", "inspect"],
        )
        return SimpleNamespace(returncode=1, stdout=b"")

    class FakeStdin:
        def write(self, _data):
            return None

        def flush(self):
            return None

        def close(self):
            return None

    class FakeHolder:
        stdin = FakeStdin()
        stdout = object()

        def wait(self, timeout):
            return 0

    def fake_sql(_container, statement, _snapshot_id=None):
        if "SELECT tablename FROM pg_tables" in statement:
            return "\n".join(tables)
        if statement == "SELECT version_num FROM alembic_version;":
            return "\n".join(head_rows)
        if statement == "SELECT count(*) FROM service_heartbeats;":
            return heartbeat_count
        if statement.startswith("SELECT md5(row_to_json(t)::text)"):
            row_hash_queries.append(statement)
            return "row-digest"
        raise AssertionError(f"Unexpected source query: {statement}")

    monkeypatch.setattr(restore, "command", fake_command)
    monkeypatch.setattr(restore, "run", fake_run)
    monkeypatch.setattr(restore, "sql", fake_sql)
    monkeypatch.setattr(restore, "expected_migration_head", lambda: "expected-head")
    monkeypatch.setattr(restore.subprocess, "Popen", lambda *args, **kwargs: FakeHolder())
    monkeypatch.setattr(
        restore,
        "read_snapshot_identifier",
        lambda *_args: "00000001-00000001-1",
    )

    with pytest.raises(ValueError):
        restore.verify(tmp_path / "private-output", "porygon-restore-test-target")

    assert row_hash_queries == []
    assert not any(
        args[:3] == ["docker", "volume", "create"]
        or args[:2] == ["docker", "run"]
        or args[:3] == ["docker", "rm", "-f"]
        for args in mutations
    )
