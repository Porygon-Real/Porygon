from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from porygon_api.main import _find_parent_event_id
from porygon_api.models import ProcessExecEvent


def _event(event_id: str, occurred_at: datetime, pid: int) -> ProcessExecEvent:
    return ProcessExecEvent(
        event_id=event_id,
        sensor_instance_id="sensor-1",
        sensor_hostname="host",
        source="falco",
        rule_name="Porygon Container Process Execution",
        priority="Notice",
        occurred_at=occurred_at,
        time_nano=int(occurred_at.timestamp() * 1_000_000_000),
        event_number=1,
        event_type="execve",
        reported_docker_host_id="host-1",
        reported_container_id="c1",
        docker_host_id="host-1",
        container_id="c1",
        container_name="probe",
        image_id="sha256:image",
        image_ref="example/app:latest",
        image_digest="example/app@sha256:" + "a" * 64,
        correlation_status="resolved",
        process_pid=pid,
        process_ppid=1,
        process_vpid=pid,
        process_name="parent",
        executable="/usr/bin/parent",
        command_line="parent",
        working_directory="/",
        tty=0,
        parent_name="init",
        parent_executable="/sbin/init",
        parent_command_line="init",
        parent_event_id=None,
        user_uid=1000,
        user_name="user",
        group_gid=1000,
        group_name="user",
        tags=[],
        output=None,
        output_fields={},
        raw_event={},
        received_at=occurred_at,
    )


def test_parent_lookup_rejects_stale_pid_reuse() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    ProcessExecEvent.__table__.create(engine)
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)

    with Session(engine) as db:
        db.add(_event("a" * 64, now - timedelta(hours=2), 42))
        db.commit()

        result = _find_parent_event_id(
            db,
            sensor_instance_id="sensor-1",
            docker_host_id="host-1",
            container_id="c1",
            process_ppid=42,
            occurred_at=now,
            time_nano=int(now.timestamp() * 1_000_000_000),
        )
        assert result is None

        recent = _event("b" * 64, now - timedelta(seconds=30), 42)
        db.add(recent)
        db.commit()
        result = _find_parent_event_id(
            db,
            sensor_instance_id="sensor-1",
            docker_host_id="host-1",
            container_id="c1",
            process_ppid=42,
            occurred_at=now,
            time_nano=int(now.timestamp() * 1_000_000_000),
        )
        assert result == recent.event_id


def test_unresolved_container_never_uses_host_pid_fallback() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    ProcessExecEvent.__table__.create(engine)
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    with Session(engine) as db:
        db.add(_event("a" * 64, now - timedelta(seconds=1), 42))
        db.commit()
        for host in (None, "host-1"):
            assert (
                _find_parent_event_id(
                    db,
                    sensor_instance_id="sensor-1",
                    docker_host_id=host,
                    container_id=None,
                    process_ppid=42,
                    occurred_at=now,
                    time_nano=int(now.timestamp() * 1_000_000_000),
                )
                is None
            )


def test_parent_lookup_isolated_by_container_and_sensor_when_host_missing() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    ProcessExecEvent.__table__.create(engine)
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    with Session(engine) as db:
        parent = _event("a" * 64, now - timedelta(seconds=1), 42)
        db.add(parent)
        db.commit()
        for container, sensor in (("other", "sensor-1"), ("c1", "other-sensor")):
            assert (
                _find_parent_event_id(
                    db,
                    sensor_instance_id=sensor,
                    docker_host_id=None,
                    container_id=container,
                    process_ppid=42,
                    occurred_at=now,
                    time_nano=int(now.timestamp() * 1_000_000_000),
                )
                is None
            )


def test_late_parent_repairs_only_same_container_without_starvation() -> None:
    from porygon_api.main import _reconcile_process_parents

    engine = create_engine("sqlite+pysqlite:///:memory:")
    ProcessExecEvent.__table__.create(engine)
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    with Session(engine) as db:
        missing = _event("a" * 64, now - timedelta(seconds=4), 88)
        missing.process_ppid = 999
        child = _event("b" * 64, now, 50)
        child.process_ppid = 42
        db.add_all([missing, child])
        db.commit()
        assert _reconcile_process_parents(db, limit=1) == 0
        parent = _event("c" * 64, now - timedelta(seconds=1), 42)
        unrelated = _event("d" * 64, now, 60)
        unrelated.container_id = "other-container"
        unrelated.process_ppid = 42
        db.add_all([parent, unrelated])
        db.commit()
        assert _reconcile_process_parents(db, limit=1) == 1
        assert child.parent_event_id == parent.event_id
        assert missing.parent_event_id is None
        assert unrelated.parent_event_id is None
