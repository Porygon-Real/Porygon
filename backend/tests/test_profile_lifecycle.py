"""Only reviewed scoped benign evidence can become an active immutable profile."""

from datetime import timedelta
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from fastapi import HTTPException
import pytest
from test_assessment_service import (
    engine as engine,
    assessment_engine as assessment_engine,
)
from porygon_api.models import AssessmentTarget, ManagedProfile, AssessmentAudit
from porygon_api.profile_lifecycle import (
    CandidateIn,
    BenignInterval,
    propose_profile,
    shadow_profile,
    activate_profile,
    rollback_profile,
)
from test_assessment_service import setup_target, event, NOW
from test_auth_permissions import (
    post,
    settings as settings,
    database_override as database_override,
)


def test_quality_failure_blocks_shadow_and_unapproved_activation(assessment_engine):
    with Session(assessment_engine) as db:
        target_id, enrollment_id = setup_target(db, activate=False)
        with pytest.raises(HTTPException):
            activate_profile(target_id, enrollment_id, db)
        empty = propose_profile(
            target_id,
            CandidateIn(
                reference="empty controlled interval",
                intervals=[
                    BenignInterval(
                        name="empty",
                        label="benign",
                        start_at=NOW - timedelta(seconds=900),
                        end_at=NOW - timedelta(seconds=800),
                    )
                ],
            ),
            db,
        )
        assert not empty["quality"]["passed"]
        with pytest.raises(HTTPException):
            shadow_profile(
                target_id,
                empty["enrollment"].enrollment_id,
                BenignInterval(
                    name="shadow",
                    label="benign",
                    start_at=NOW - timedelta(seconds=250),
                    end_at=NOW - timedelta(seconds=220),
                ),
                db,
            )
        with pytest.raises(HTTPException):
            shadow_profile(
                target_id,
                enrollment_id,
                BenignInterval(
                    name="overlap",
                    label="benign",
                    start_at=NOW - timedelta(seconds=390),
                    end_at=NOW - timedelta(seconds=350),
                ),
                db,
            )


def test_activation_rollback_preserves_hash_and_transition_history(assessment_engine):
    with Session(assessment_engine) as db:
        target_id, first = setup_target(db)
        first_hash = db.get(ManagedProfile, first).artifact_hash
        for i in range(12):
            event(
                db,
                NOW - timedelta(seconds=320 - i * 2),
                name="node",
                command="node server.js",
            )
        db.commit()
        second = propose_profile(
            target_id,
            CandidateIn(
                reference="second benign configuration",
                intervals=[
                    BenignInterval(
                        name="second",
                        label="benign",
                        start_at=NOW - timedelta(seconds=330),
                        end_at=NOW - timedelta(seconds=280),
                    )
                ],
            ),
            db,
        )["enrollment"]
        shadow_profile(
            target_id,
            second.enrollment_id,
            BenignInterval(
                name="second-shadow",
                label="benign",
                start_at=NOW - timedelta(seconds=250),
                end_at=NOW - timedelta(seconds=220),
            ),
            db,
        )
        activate_profile(target_id, second.enrollment_id, db)
        rollback_profile(target_id, first, db)
        assert db.get(ManagedProfile, first).artifact_hash == first_hash
        activate_profile(target_id, second.enrollment_id, db)
        count = db.scalar(select(func.count()).select_from(AssessmentAudit))
        activate_profile(target_id, second.enrollment_id, db)
        assert db.scalar(select(func.count()).select_from(AssessmentAudit)) == count
        changes = db.scalars(
            select(AssessmentAudit).where(
                AssessmentAudit.action.in_(["activated", "rollback"])
            )
        ).all()
        assert len(changes) == 4
        assert (
            db.get(AssessmentTarget, target_id).active_profile_id
            == second.enrollment_id
        )


@pytest.mark.parametrize(
    "path",
    [
        "/operator/v1/assessment-targets",
        "/operator/v1/assessment-targets/missing/profiles",
        "/operator/v1/assessment-targets/missing/profiles/missing/activate",
        "/operator/v1/assessment-targets/missing/reprocess",
    ],
)
def test_local_anonymous_and_internal_writes_denied(settings, database_override, path):
    for headers, code in [({}, 422), ({"X-Porygon-Internal-Token": "i" * 32}, 401)]:
        assert post(path, {}, headers)[0] == code
    with Session(database_override) as db:
        assert db.scalar(select(func.count()).select_from(AssessmentTarget)) == 0
        assert db.scalar(select(func.count()).select_from(AssessmentAudit)) == 0


def test_candidate_does_not_learn_cross_host_or_contaminated_intervals(
    assessment_engine,
):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BenignInterval(
            name="suspect",
            label="malicious",
            start_at=NOW - timedelta(seconds=100),
            end_at=NOW,
        )
    with Session(assessment_engine) as db:
        target_id, _ = setup_target(db, activate=False)
        for i in range(12):
            event(db, NOW - timedelta(seconds=690 - i * 3), host="host-b")
        db.commit()
        proposal = propose_profile(
            target_id,
            CandidateIn(
                reference="host separation",
                intervals=[
                    BenignInterval(
                        name="foreign-only",
                        label="benign",
                        start_at=NOW - timedelta(seconds=700),
                        end_at=NOW - timedelta(seconds=640),
                    )
                ],
            ),
            db,
        )
        assert proposal["quality"]["checks"]["minimum_process_events"]["actual"] == 0
        assert not proposal["quality"]["passed"]
