from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from porygon_api.config import Settings
from porygon_api.maintenance import RetentionWorker
from porygon_api.retention import RetentionResult


def settings():
    return Settings(
        db_password="test-password",
        internal_api_token="x" * 32,
        operator_api_token="o" * 32,
    )


def test_retention_is_opt_in_and_stops_without_opening_a_session():
    config = settings()
    assert config.retention_scheduler_enabled is False
    factory = MagicMock()
    worker = RetentionWorker(config, factory)
    worker.start()
    worker.stop()
    factory.assert_not_called()
    assert not worker.thread.is_alive()


@pytest.mark.parametrize("owns_lock", [False, True])
def test_retention_tick_owns_transaction_and_cross_worker_lock(monkeypatch, owns_lock):
    factory = MagicMock()
    db = factory.return_value.__enter__.return_value
    db.scalar.return_value = owns_lock
    apply = MagicMock(
        return_value=RetentionResult(datetime.now(timezone.utc), 3, 4, False)
    )
    monkeypatch.setattr("porygon_api.maintenance.apply_retention", apply)
    worker = RetentionWorker(settings(), factory)
    assert worker.run_once() is owns_lock
    if owns_lock:
        apply.assert_called_once_with(
            db, retention_days=30, max_delete_batch=50000, dry_run=False
        )
        db.commit.assert_called_once()
    else:
        apply.assert_not_called()
        db.rollback.assert_called_once()
    factory.return_value.__exit__.assert_called_once()


def test_retention_errors_close_session_and_leave_retry_to_next_tick(monkeypatch):
    factory = MagicMock()
    db = factory.return_value.__enter__.return_value
    db.scalar.return_value = True
    monkeypatch.setattr(
        "porygon_api.maintenance.apply_retention",
        MagicMock(side_effect=RuntimeError("database outage")),
    )
    worker = RetentionWorker(settings(), factory)
    with pytest.raises(RuntimeError):
        worker.run_once()
    db.commit.assert_not_called()
    factory.return_value.__exit__.assert_called_once()
