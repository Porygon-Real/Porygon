"""Typed evidence isolation, replay and durable identity repair regressions."""
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
import sqlite3

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from porygon_api.kernel_events import ingest_kernel_events, reconcile_kernel_identities
from porygon_api.models import KernelRuntimeEvent, ProcessExecEvent, RuntimeEvent
from porygon_api.reconciliation import IdentityReconciliationWorker
from porygon_api.retention import apply_retention
from porygon_api.schemas import KernelRuntimeEventIn, KernelRuntimeBatchIn
from test_identity_reconciliation import identity
from test_incident_grouping import engine as _disposable_engine

engine = _disposable_engine

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)


def payload(**changes):
    values = dict(event_id="a" * 64, sensor_instance_id="sensor", source="falco",
                  rule_name="Porygon Container Outbound Connection", priority="Notice",
                  occurred_at=NOW, time_nano=int(NOW.timestamp() * 1e9),
                  event_type="connect", runtime_action="net_outbound", return_value=0,
                  reported_container_id="abcdef123456", process_pid=123,
                  remote_address="192.0.2.10", remote_port=443, raw_event={})
    values.update(changes)
    return KernelRuntimeEventIn(**values)


@pytest.fixture
def db(engine):
    with Session(engine) as session:
        yield session


@pytest.mark.parametrize("changes", [
    {"event_type": "execve"}, {"runtime_action": "file_write"},
    {"remote_address": "127.0.0.2"}, {"remote_address": "::ffff:127.0.0.1"},
    {"remote_address": "::"}, {"remote_port": None}, {"return_value": -111},
    {"reported_container_id": "%" * 12}, {"occurred_at": NOW.replace(tzinfo=None)},
    {"runtime_action": "file_write", "event_type": "write", "file_path": "/etc/test", "return_value": 0},
])
def test_rejects_mismatched_or_invalid_evidence(changes):
    with pytest.raises(ValidationError):
        payload(**changes)


def request():
    worker = Mock()
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(identity_reconciliation=worker)))


def test_replay_is_idempotent_and_cannot_pollute_legacy_tables(db):
    batch = KernelRuntimeBatchIn(events=[payload(), payload()])
    req = request()
    first = ingest_kernel_events(batch, req, db)
    second = ingest_kernel_events(batch, req, db)
    assert (first["inserted"], first["duplicates"], second["inserted"]) == (1, 1, 0)
    assert db.scalar(select(func.count()).select_from(KernelRuntimeEvent)) == 1
    for model in (ProcessExecEvent, RuntimeEvent):
        assert db.scalar(select(func.count()).select_from(model)) == 0
    assert req.app.state.identity_reconciliation.notify.call_count == 2


def test_host_ambiguity_and_late_lifecycle_repair(db):
    ingest_kernel_events(KernelRuntimeBatchIn(events=[payload()]), request(), db)
    db.add_all([identity(), identity("host-2")])
    db.commit()
    assert reconcile_kernel_identities(db) == 0
    event = db.get(KernelRuntimeEvent, "a" * 64)
    assert event.container_id is None
    event.reported_docker_host_id = "host-2"
    db.commit()
    assert reconcile_kernel_identities(db) == 1
    db.commit()
    assert event.docker_host_id == "host-2"
    assert event.container_id == "abcdef123456" + "a" * 52
    assert reconcile_kernel_identities(db) == 0


def test_local_image_identity_repairs_without_registry_digest(db):
    ingest_kernel_events(KernelRuntimeBatchIn(events=[payload()]), request(), db)
    local = identity()
    local.image_digest = None
    local.image_digest_status = "missing"
    db.add(local)
    db.commit()
    assert reconcile_kernel_identities(db) == 1
    db.commit()
    event = db.get(KernelRuntimeEvent, "a" * 64)
    assert event.image_id == local.image_id and event.image_digest is None
    assert reconcile_kernel_identities(db) == 0
    local.image_digest = "example@sha256:" + "b" * 64
    db.commit()
    assert reconcile_kernel_identities(db) == 1
    db.commit()
    assert event.image_digest == local.image_digest


def test_worker_retries_from_committed_rows_after_restart(db, monkeypatch):
    from uuid import uuid4
    monkeypatch.setattr("porygon_api.reconciliation.LOCK_ID", uuid4().int % (2**63 - 1))
    ingest_kernel_events(KernelRuntimeBatchIn(events=[payload()]), request(), db)
    db.add(identity())
    db.commit()
    # A new worker has no wake hint: durable rows still define outstanding work.
    class BorrowSession:
        def __enter__(self):
            return db
        def __exit__(self, *args):
            if args[0]:
                db.rollback()
    worker = IdentityReconciliationWorker(BorrowSession, lambda session, limit: 0,
        lambda session, limit: reconcile_kernel_identities(session, limit), batch_size=1)
    assert worker.run_once()
    assert worker.snapshot()["kernel_repaired"] == 1
    assert worker.run_once()
    assert worker.snapshot()["kernel_repaired"] == 1


def test_retention_production_batch_under_low_bind_limit(db):
    if db.bind.dialect.name != "sqlite":
        pytest.skip("SQLite bind-limit regression")
    from datetime import timedelta
    from test_retention import _process_event, _runtime_event
    old = NOW - timedelta(days=90)
    for model, factory in ((ProcessExecEvent, _process_event), (RuntimeEvent, _runtime_event)):
        template = factory("template", old)
        values = {c.name: getattr(template, c.name) for c in model.__table__.columns}
        db.execute(model.__table__.insert(), [dict(values, event_id=f"old-{i}") for i in range(50001)])
    kernel = payload(occurred_at=old).model_dump()
    kernel.update(correlation_status="unresolved", received_at=old)
    db.add(KernelRuntimeEvent(**kernel))
    db.commit()
    connection = db.connection().connection.driver_connection
    connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
    dry = apply_retention(db, retention_days=30, max_delete_batch=50000, dry_run=True, now=NOW)
    assert dry.kernel_runtime_events_deleted == 1
    assert db.scalar(select(func.count()).select_from(ProcessExecEvent)) == 50001
    result = apply_retention(db, retention_days=30, max_delete_batch=50000, dry_run=False, now=NOW)
    db.commit()
    assert result.process_exec_events_deleted == result.runtime_events_deleted == 50000
    assert result.kernel_runtime_events_deleted == 1
    assert db.scalar(select(func.count()).select_from(ProcessExecEvent)) == 1
    assert db.scalar(select(func.count()).select_from(RuntimeEvent)) == 1


def test_failed_batch_rolls_back_all_evidence(db):
    from sqlalchemy import event
    from sqlalchemy.exc import OperationalError
    from fastapi import HTTPException
    calls = 0
    def fail_second(conn, cursor, statement, parameters, context, executemany):
        nonlocal calls
        if statement.startswith("INSERT INTO kernel_runtime_events"):
            calls += 1
            if calls == 2:
                raise OperationalError("redacted", {}, Exception("unavailable"))
    event.listen(db.bind, "before_cursor_execute", fail_second)
    try:
        with pytest.raises(HTTPException) as exc:
            ingest_kernel_events(KernelRuntimeBatchIn(events=[payload(), payload(event_id="b" * 64)]), request(), db)
        assert exc.value.status_code == 503
        assert db.scalar(select(func.count()).select_from(KernelRuntimeEvent)) == 0
    finally:
        event.remove(db.bind, "before_cursor_execute", fail_second)


def test_worker_skips_when_another_postgres_replica_owns_the_lock():
    session = Mock()
    session.get_bind.return_value.dialect.name = "postgresql"
    session.scalar.return_value = False
    context = Mock()
    context.__enter__ = Mock(return_value=session)
    context.__exit__ = Mock(return_value=False)
    repair = Mock()
    worker = IdentityReconciliationWorker(lambda: context, repair, repair)
    assert worker.run_once() is False
    session.rollback.assert_called_once()
    repair.assert_not_called()
    session.commit.assert_not_called()


def test_worker_survives_failure_recovers_periodically_and_stops(tmp_path):
    from threading import Event
    from sqlalchemy.orm import sessionmaker
    engine = create_engine('sqlite:///' + str(tmp_path / 'repair.db'))
    recovered = Event()
    attempts = []
    def repair(session, limit):
        attempts.append(limit)
        if len(attempts) == 1:
            raise RuntimeError('controlled failure')
        recovered.set()
        return 1
    worker = IdentityReconciliationWorker(sessionmaker(engine), repair, lambda db, limit: 0,
        interval=0.02, batch_size=7)
    worker.start()
    try:
        assert recovered.wait(3)
    finally:
        worker.stop()
        engine.dispose()
    state = worker.snapshot()
    assert attempts[:2] == [7, 7]
    assert state['last_error'] is None and state['last_success_at']
    assert state['process_repaired'] >= 1 and state['running'] is False
    assert not worker.thread.is_alive()


def test_legacy_postgres_acknowledgements_and_no_inline_repair(db, monkeypatch):
    if db.bind.dialect.name != 'postgresql':
        pytest.skip('PostgreSQL named upsert constraints')
    from porygon_api import main
    from porygon_api.schemas import RuntimeEventBatchIn, RuntimeEventIn, ProcessExecEventBatchIn, ProcessExecEventIn
    from test_retention import _process_event, _runtime_event
    repair = Mock(side_effect=AssertionError('Repair ran inside ingestion request'))
    monkeypatch.setattr(main, '_reconcile_process_identities', repair)
    notify = Mock()
    monkeypatch.setattr(main.app.state, 'identity_reconciliation', notify, raising=False)
    cases = [
        (main.ingest_runtime_events, RuntimeEventBatchIn,
         RuntimeEventIn.model_validate(_runtime_event('b' * 64, NOW), from_attributes=True)),
        (main.ingest_process_events, ProcessExecEventBatchIn,
         ProcessExecEventIn.model_validate(_process_event('c' * 64, NOW), from_attributes=True)),
    ]
    for ingest, batch_type, event in cases:
        first = ingest(batch_type(events=[event]), db)
        replay = ingest(batch_type(events=[event]), db)
        assert (first.inserted, first.duplicates) == (1, 0)
        assert (replay.inserted, replay.duplicates) == (0, 1)
    repair.assert_not_called()
    assert notify.notify.call_count == 4
