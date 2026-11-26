"""Durable windows, crash recovery, fencing and explicit coverage states."""

from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import os
import pytest
from test_assessment_service import (
    engine as engine,
    assessment_engine as assessment_engine,
)
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from porygon_api.config import get_settings
from porygon_api.models import (
    AssessmentTarget,
    AssessmentJob,
    AnomalyScore,
    DetectionRun,
)
from porygon_api.window_worker import AssessmentWorker, LeaseLost, reprocess, RevisionIn
from test_assessment_service import (
    setup_target,
    event,
    START,
    NOW,
    DIGEST,
)


def worker(engine, owner="worker-a"):
    settings = get_settings().model_copy(update={"assessment_jobs_per_tick": 1})
    return AssessmentWorker(settings, lambda: Session(engine), owner)


def test_worker_recovers_expired_generation_and_completes_once(assessment_engine):
    with Session(assessment_engine) as db:
        target_id, _ = setup_target(db)
        event(db, START + timedelta(seconds=1))
        db.commit()
    a = worker(assessment_engine)
    b = worker(assessment_engine, "worker-b")
    assert a.schedule() == 1
    assert a.schedule() == 1  # different fixed window, not a duplicate
    claim = a.claim()
    assert claim is not None
    with Session(assessment_engine) as db:
        job = db.get(AssessmentJob, claim[0])
        job.lease_expires_at = NOW - timedelta(seconds=1)
        db.commit()
    recovered = b.claim()
    assert recovered[0] == claim[0] and recovered[1] > claim[1]
    with pytest.raises(LeaseLost):
        a.assess(*claim)
    b.renew(*recovered)
    b.assess(*recovered)
    with pytest.raises(LeaseLost):
        b.assess(*recovered)
    with Session(assessment_engine) as db:
        job = db.get(AssessmentJob, claim[0])
        assert job.state == "completed"
        assert job.coverage["completeness"] == "unknown"
        assert (
            db.scalar(
                select(func.count())
                .select_from(AnomalyScore)
                .where(AnomalyScore.image_digest == DIGEST)
            )
            == 1
        )
        event(db, START + timedelta(seconds=3), name="bash", command="bash -c anomaly")
        db.commit()
        revision = reprocess(
            target_id,
            RevisionIn(window_start=START, revision=1, reason="late event review"),
            db,
        )
        replay = reprocess(
            target_id, RevisionIn(window_start=START, revision=1, reason="retry"), db
        )
        assert revision.job_id == replay.job_id
        assert revision.assessment_key != job.assessment_key
        with pytest.raises(Exception):
            reprocess(
                target_id,
                RevisionIn(
                    window_start=START - timedelta(days=1),
                    revision=1,
                    reason="never scheduled",
                ),
                db,
            )


def test_unprofiled_changed_identity_and_retention_are_explicit(assessment_engine):
    with Session(assessment_engine) as db:
        target_id, _ = setup_target(db, activate=False)
    runner = worker(assessment_engine)
    runner.run_once()
    with Session(assessment_engine) as db:
        job = db.scalar(select(AssessmentJob))
        assert job.coverage["state"] == "unprofiled"
        assert job.score_id is None
        target = db.get(AssessmentTarget, target_id)
        target.next_window_start = NOW - timedelta(days=90)
        db.commit()
    runner.run_once()
    with Session(assessment_engine) as db:
        assert any(
            job.coverage["state"] == "unavailable"
            for job in db.scalars(select(AssessmentJob)).all()
        )


def test_failure_rolls_back_score_and_detection_before_retry(
    assessment_engine, monkeypatch
):
    import porygon_api.window_worker as module

    with Session(assessment_engine) as db:
        setup_target(db)
        event(db, START + timedelta(seconds=1))
        db.commit()
    original = module.run_detection

    def crash(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("controlled worker crash")

    monkeypatch.setattr(module, "run_detection", crash)
    worker(assessment_engine).run_once()
    with Session(assessment_engine) as db:
        job = db.scalar(select(AssessmentJob))
        assert job.state == "pending" and job.error_category == "assessment_error"
        assert (
            db.scalar(
                select(func.count())
                .select_from(AnomalyScore)
                .where(AnomalyScore.image_digest == DIGEST)
            )
            == 0
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(DetectionRun)
                .where(DetectionRun.image_digest == DIGEST)
            )
            == 0
        )


@pytest.mark.skipif(
    os.environ.get("PORYGON_TEST_POSTGRES") != "1",
    reason="PostgreSQL SKIP LOCKED required",
)
def test_two_workers_claim_only_one_generation(assessment_engine):
    with Session(assessment_engine) as db:
        setup_target(db)
    a = worker(assessment_engine)
    b = worker(assessment_engine, "worker-b")
    a.schedule()
    barrier = Barrier(2)

    def claim(runner):
        barrier.wait()
        return runner.claim()

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim, [a, b]))
    assert sum(item is not None for item in claims) == 1


def test_config_change_between_validation_and_evaluation_is_atomic(
    assessment_engine, monkeypatch
):
    import porygon_api.window_worker as module
    from porygon_api.models import DetectionAllowlist, Incident
    from uuid import uuid4

    with Session(assessment_engine) as db:
        setup_target(db)
        event(
            db, START + timedelta(seconds=1), name="bash", command="bash -c controlled"
        )
        db.commit()
    original = module.configuration
    calls = 0

    def racing_configuration(*args, **kwargs):
        nonlocal calls
        snapshot = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            # A second session commits after the worker validated its frozen
            # configuration but before the detection service queries rules.
            with Session(assessment_engine) as other:
                other.add(
                    DetectionAllowlist(
                        allowlist_id=str(uuid4()),
                        matcher_hash="r" * 64,
                        image_digest=DIGEST,
                        rule_id="POR-DET-002",
                        executable="/bin/never-matches",
                        reason="concurrent reviewed configuration",
                        approved_by="human:operator",
                        active=True,
                        created_at=NOW,
                    )
                )
                other.commit()
        return snapshot

    monkeypatch.setattr(module, "configuration", racing_configuration)
    worker(assessment_engine).run_once()
    with Session(assessment_engine) as db:
        row = db.scalar(select(AssessmentJob))
        assert (
            row.state == "unavailable" and row.error_category == "configuration_changed"
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(AnomalyScore)
                .where(AnomalyScore.image_digest == DIGEST)
            )
            == 0
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(DetectionRun)
                .where(DetectionRun.image_digest == DIGEST)
            )
            == 0
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(Incident.image_digest == DIGEST)
            )
            == 0
        )
        assert db.scalar(select(func.count()).select_from(DetectionAllowlist)) == 1
