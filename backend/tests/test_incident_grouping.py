"""Episode integrity tests; set PORYGON_TEST_POSTGRES=1 for real row-lock races.

PostgreSQL runs create and drop only a uniquely named disposable schema.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from porygon_api.db import Base
from porygon_api import main
from porygon_api.incident_grouping import attach_incident, grouping_key
from porygon_api.models import (
    AnomalyScore,
    BehaviorProfile,
    DetectionRun,
    DetectionIncidentLink,
    Incident,
    IncidentEvidence,
    ResponseExecution,
    ResponseRecommendation,
)
from porygon_api.schemas import (
    IncidentStatusUpdateIn,
    ResponseExecutionCompleteIn,
    ResponseRecommendationApproveIn,
)

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)
CID = "a" * 64
DIGEST = "example@sha256:" + "b" * 64
EVENTS = [SimpleNamespace(container_id=CID, docker_host_id="host")]


@pytest.fixture
def engine(tmp_path):
    if os.environ.get("PORYGON_TEST_POSTGRES") == "1":
        from porygon_api.config import get_settings

        url = get_settings().database_url
        admin = create_engine(url)
        schema = "test_incidents_" + uuid4().hex
        with admin.begin() as connection:
            connection.execute(text(f"CREATE SCHEMA {schema}"))
        engine = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    else:
        admin = None
        engine = create_engine("sqlite:///" + str(tmp_path / "incidents.db"))
    try:
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            db.add(
                BehaviorProfile(
                    profile_id="profile",
                    image_digest=DIGEST,
                    profile_version=1,
                    status="active",
                    feature_schema_version="test",
                    model_hash="m" * 64,
                    training_start=NOW,
                    training_end=NOW,
                    window_seconds=30,
                    approved_by="test",
                    process_event_count=1,
                    runtime_event_count=0,
                    container_count=1,
                    window_count=1,
                    quality={},
                    training_manifest={},
                    features={},
                    created_at=NOW,
                )
            )
            db.commit()
        yield engine
    finally:
        engine.dispose()
        if admin is not None:
            with admin.begin() as connection:
                connection.execute(text(f"DROP SCHEMA {schema} CASCADE"))
            admin.dispose()


def window(db, index):
    end = NOW + timedelta(seconds=index * 30)
    score = AnomalyScore(
        score_id=f"score-{index}",
        observation_key=str(index).zfill(64),
        profile_id="profile",
        image_digest=DIGEST,
        profile_version=1,
        profile_model_hash="m" * 64,
        algorithm_version="test",
        status="scored",
        score_band="high",
        total_score=0.8,
        window_start=end - timedelta(seconds=30),
        window_end=end,
        window_seconds=30,
        process_event_count=1,
        runtime_event_count=0,
        container_count=1,
        components={},
        explanation={},
        observation_manifest={},
        scoring_config={},
        created_at=end,
    )
    run = DetectionRun(
        run_id=f"run-{index}",
        run_key=str(index).zfill(64),
        score_id=score.score_id,
        ruleset_version="test",
        ruleset_hash="r" * 64,
        allowlist_set_hash="a" * 64,
        custom_ruleset_hash="c" * 64,
        applied_allowlist_ids=[],
        image_digest=DIGEST,
        window_start=score.window_start,
        window_end=end,
        status="incident_created",
        matches_count=1,
        incident_created=True,
        result={},
        created_at=end,
    )
    db.add(score)
    db.flush()
    db.add(run)
    db.flush()
    result = dict(
        incident_eligible=True,
        anomaly_score=0.8,
        severity_score=0.8,
        severity_level="high",
        confidence_score=0.8,
        confidence_level="high",
        summary="Observed evidence",
        matches=[
            dict(
                incident_eligible=True,
                occurred_at=end.isoformat(),
                container_id=CID,
                severity_weight=0.8,
                confidence_weight=0.8,
                rule_id="POR-DET-002",
                name="Shell",
                source_type="process_exec",
                source_id=f"event-{index}",
                category="shell",
                summary="Observed shell",
                details={},
            )
        ],
    )
    run.result = result
    incident, timeline = attach_incident(db, run, score, result, EVENTS, [], end)
    db.commit()
    return incident.incident_id, run.run_id, timeline


def test_windows_group_without_losing_links_and_closed_episode_stays_closed(engine):
    with Session(engine) as db:
        first, _, _ = window(db, 1)
        second, _, _ = window(db, 2)
        assert first == second
        assert db.get(DetectionRun, "run-2").status == "incident_updated"
        assert db.scalar(select(func.count()).select_from(DetectionIncidentLink)) == 2
        assert db.get(Incident, first).latest_detection_run_id == "run-2"
        # A late window cannot replace the newer assessment.
        window(db, 0)
        assert db.get(Incident, first).latest_detection_run_id == "run-2"
        main.update_incident_status(
            first, IncidentStatusUpdateIn(status="resolved", actor="test"), db
        )
        third, _, _ = window(db, 3)
        assert third != first
        assert db.get(Incident, first).status == "resolved"
        sequences = db.scalars(
            select(IncidentEvidence.sequence_no)
            .where(IncidentEvidence.incident_id == first)
            .order_by(IncidentEvidence.sequence_no)
        ).all()
        assert sequences == list(range(1, len(sequences) + 1))


def test_unknown_or_ambiguous_host_identity_is_not_grouped():
    score = SimpleNamespace(image_digest=DIGEST, profile_id="profile")
    assert grouping_key(score, ["short-id"], EVENTS, []) is None
    assert grouping_key(score, [CID], [], []) is None
    assert (
        grouping_key(
            score,
            [CID],
            EVENTS + [SimpleNamespace(container_id=CID, docker_host_id="other")],
            [],
        )
        is None
    )
    key = grouping_key(score, [CID], EVENTS, [], ["configuration"])
    assert key != grouping_key(score, [CID], EVENTS, [], ["different"])
    short_cid = "123456abcdef"
    short_events = [SimpleNamespace(container_id=short_cid, docker_host_id=None)]
    short_key = grouping_key(score, [short_cid], short_events, [])
    assert short_key is not None
    assert len(short_key) == 64



def recommendation(db, incident_id, run_id):
    record = ResponseRecommendation(
        recommendation_id="recommendation",
        recommendation_key="k" * 64,
        incident_id=incident_id,
        evidence_run_id=run_id,
        target_container_id=CID,
        policy_version="test",
        policy_hash="p" * 64,
        recommended_action="pause_container",
        allowed_actions=["observe_only", "pause_container"],
        rationale="Observed evidence",
        risk_notes=[],
        status="proposed",
        created_at=NOW,
    )
    db.add(record)
    db.commit()
    return record


def test_new_window_invalidates_unapproved_recommendation(engine):
    with Session(engine) as db:
        incident_id, run_id, _ = window(db, 1)
        recommendation(db, incident_id, run_id)
        window(db, 2)
        with pytest.raises(HTTPException) as error:
            main.approve_response_recommendation(
                "recommendation",
                ResponseRecommendationApproveIn(
                    actor="test",
                    note="reviewed",
                    action_type="pause_container",
                    acknowledge_disruption=True,
                ),
                db,
            )
        assert error.value.status_code == 409
        assert "evidence changed" in error.value.detail


def test_completion_identity_prevents_old_ack_from_overwriting_rollback(engine):
    with Session(engine) as db:
        incident_id, run_id, _ = window(db, 1)
        recommendation(db, incident_id, run_id)
        record = ResponseExecution(
            execution_id="execution",
            recommendation_id="recommendation",
            incident_id=incident_id,
            target_container_id=CID,
            action_type="pause_container",
            status="pending",
            idempotency_key="i" * 64,
            attempt_count=1,
            pre_state={},
            post_state={},
            result={},
            created_at=NOW,
            started_at=NOW,
        )
        db.add(record)
        db.commit()
        payload = ResponseExecutionCompleteIn(
            executor_instance_id="worker",
            success=True,
            operation="execute",
            operation_started_at=NOW,
            result={"paused": True},
        )
        main.complete_response_execution("execution", payload, db)
        record.status = "rollback_claimed"
        record.rollback_started_at = NOW + timedelta(seconds=5)
        record.executor_instance_id = "worker"
        db.commit()
        assert (
            main.complete_response_execution("execution", payload, db).status
            == "rollback_claimed"
        )
        bad = payload.model_copy(
            update={"operation_started_at": NOW + timedelta(seconds=1)}
        )
        with pytest.raises(HTTPException) as error:
            main.complete_response_execution("execution", bad, db)
        assert error.value.status_code == 409


def test_postgres_concurrent_windows_and_status_updates(engine):
    if engine.dialect.name != "postgresql":
        pytest.skip("Requires PostgreSQL row and advisory locks")
    barrier = Barrier(2)

    def detect(index):
        with Session(engine) as db:
            barrier.wait(timeout=10)
            return window(db, index)[0]

    with ThreadPoolExecutor(2) as pool:
        ids = list(pool.map(detect, [1, 2]))
    assert ids[0] == ids[1]
    barrier = Barrier(2)

    def acknowledge(index):
        with Session(engine) as db:
            barrier.wait(timeout=10)
            main.update_incident_status(
                ids[0],
                IncidentStatusUpdateIn(
                    status="acknowledged", actor=f"operator-{index}"
                ),
                db,
            )

    with ThreadPoolExecutor(2) as pool:
        list(pool.map(acknowledge, [1, 2]))
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Incident)) == 1
        numbers = db.scalars(
            select(IncidentEvidence.sequence_no).order_by(IncidentEvidence.sequence_no)
        ).all()
        assert numbers == [1, 2, 3, 4, 5]
        assert db.scalar(select(func.count()).select_from(DetectionIncidentLink)) == 2


def test_legacy_recommendation_key_is_reused_until_new_evidence(engine):
    from porygon_api.response import build_recommendation_key, response_policy_hash

    with Session(engine) as db:
        incident_id, run_id, _ = window(db, 1)
        record = recommendation(db, incident_id, run_id)
        record.evidence_run_id = None
        record.recommendation_key = build_recommendation_key(
            incident_id=incident_id,
            target_container_id=CID,
            policy_hash=response_policy_hash(),
        )
        db.commit()
        result = main.generate_response_recommendations(incident_id, db)
        assert [item.recommendation_id for item in result["recommendations"]] == [
            "recommendation"
        ]
        window(db, 2)
        result = main.generate_response_recommendations(incident_id, db)
        assert result["recommendations"][0].recommendation_id != "recommendation"
        assert result["recommendations"][0].evidence_run_id == "run-2"
