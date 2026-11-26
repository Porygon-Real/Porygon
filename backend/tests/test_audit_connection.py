from datetime import datetime, timedelta, timezone
from threading import BoundedSemaphore

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import QueuePool

from porygon_api import main
from porygon_api.db import Base
from porygon_api.models import AnomalyScore
from porygon_api.schemas import AiAuditIn
from test_identity_reconciliation import identity


@pytest.fixture
def audit_db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=QueuePool,
        pool_size=1,
        max_overflow=0,
        pool_timeout=0.1,
    )
    Base.metadata.create_all(engine)
    container = identity()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        db.add(container)
        db.add(
            AnomalyScore(
                score_id="score",
                observation_key="o" * 64,
                profile_id="profile",
                image_digest=container.image_digest,
                profile_version=1,
                profile_model_hash="m" * 64,
                algorithm_version="porygon.distance.v1",
                status="scored",
                score_band="elevated",
                total_score=0.3,
                window_start=now - timedelta(seconds=30),
                window_end=now,
                window_seconds=30,
                process_event_count=1,
                runtime_event_count=0,
                container_count=1,
                components={},
                explanation={},
                observation_manifest={},
                scoring_config={},
                created_at=now,
            )
        )
        db.commit()
    with Session(engine) as db:
        yield db, engine
    engine.dispose()


def test_external_audit_does_not_reserve_database_connection(audit_db, monkeypatch):
    db, engine = audit_db

    def provider(**context):
        assert engine.pool.checkedout() == 0
        # With a single-connection pool, ingestion can still acquire a session.
        with engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT 1").scalar() == 1
        assert context["porygon_drift_score"] == 0.3
        return {"verified": True}

    monkeypatch.setattr(main, "perform_container_audit", provider)
    result = main.audit_container(
        AiAuditIn(container_id="abcdef123456", api_key="test-key"),
        db=db,
        x_porygon_ai_key=None,
        x_porygon_ai_provider=None,
    )
    assert result == {"verified": True}


def test_busy_audits_fail_fast_and_provider_failure_releases_capacity(
    audit_db, monkeypatch
):
    db, engine = audit_db
    slots = BoundedSemaphore(1)
    monkeypatch.setattr(main, "audit_slots", slots)
    payload = AiAuditIn(container_id="abcdef123456", api_key="test-key")
    slots.acquire()
    with pytest.raises(HTTPException) as busy:
        main.audit_container(
            payload, db=db, x_porygon_ai_key=None, x_porygon_ai_provider=None
        )
    assert busy.value.status_code == 503
    assert engine.pool.checkedout() == 0
    slots.release()

    def failed_provider(**_context):
        assert engine.pool.checkedout() == 0
        raise ValueError("provider unavailable")

    monkeypatch.setattr(main, "perform_container_audit", failed_provider)
    with pytest.raises(HTTPException) as failure:
        main.audit_container(
            payload, db=db, x_porygon_ai_key=None, x_porygon_ai_provider=None
        )
    assert failure.value.status_code == 502
    assert slots.acquire(blocking=False)
    slots.release()
