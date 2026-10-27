"""Named benign evidence, immutable candidates, shadow review and human promotion."""

from datetime import datetime, timezone
import re
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import Session
from porygon_api.security import require_operator_token
from porygon_api.auth import utc
from porygon_api.baseline import COMMAND_LINEAGE_SCHEMA, build_profile_document
from porygon_api.config import get_settings
from porygon_api.assessment_service import utc_events
from porygon_api.coverage import security_context, target_identity
from porygon_api.db import get_db
from porygon_api.models import (
    AssessmentTarget,
    ManagedProfile,
    AssessmentAudit,
    BehaviorProfile,
    ContainerIdentity,
    ProcessExecEvent,
    RuntimeEvent,
)
from porygon_api.principals import audit_subject
from porygon_api.scoring import score_feature_documents
from porygon_api.vulnerability import sha256_document

router = APIRouter(tags=["continuous-assessment"])


class TargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    docker_host_id: str = Field(min_length=1, max_length=128)
    container_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    image_digest: str = Field(min_length=1, max_length=255)
    start_at: datetime
    window_seconds: int = Field(default=30, ge=5, le=3600)
    allowed_lateness_seconds: int | None = Field(default=None, ge=0, le=3600)

    @model_validator(mode="after")
    def validate_start(self):
        if self.start_at.tzinfo is None or self.start_at > datetime.now(timezone.utc):
            raise ValueError("Start must be a completed timezone-aware instant")
        if not re.search(
            r"@sha256:[a-f0-9]{64}$", self.image_digest
        ) and not re.fullmatch(r"local:sha256:[a-f0-9]{64}", self.image_digest):
            raise ValueError("Target requires an immutable image digest")
        return self


class BenignInterval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128)
    label: str = Field(pattern=r"^benign$")
    start_at: datetime
    end_at: datetime

    @model_validator(mode="after")
    def validate_range(self):
        if (
            self.start_at.tzinfo is None
            or self.end_at.tzinfo is None
            or self.end_at <= self.start_at
            or self.end_at > datetime.now(timezone.utc)
        ):
            raise ValueError("Evidence interval must be completed and timezone-aware")
        return self


class CandidateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intervals: list[BenignInterval] = Field(min_length=1, max_length=32)
    reference: str = Field(min_length=1, max_length=255)
    minimum_process_events: int = Field(default=10, ge=10, le=10000)
    minimum_nonempty_windows: int = Field(default=2, ge=2, le=1000)


def audit(db, target, action, detail):
    # Real lifecycle transitions append history; callers return early on no-op replay.
    db.add(
        AssessmentAudit(
            audit_id=str(uuid4()),
            audit_key=sha256_document({"nonce": str(uuid4())}),
            target_id=target.target_id,
            action=action,
            actor=audit_subject("trusted-local"),
            detail=detail,
            created_at=datetime.now(timezone.utc),
        )
    )


def get_target(db, target_id, *, lock=False):
    query = select(AssessmentTarget).where(AssessmentTarget.target_id == target_id)
    target = db.scalar(query.with_for_update() if lock else query)
    if target is None:
        raise HTTPException(404, "Assessment target not found")
    return target


def validate_identity(db, target):
    identity = target_identity(db, target)
    if (
        identity is None
        or identity.image_digest != target.image_digest
        or sha256_document(security_context(identity.current_snapshot))
        != target.context_hash
    ):
        raise HTTPException(
            409, "Target identity changed; enroll and review a new target"
        )


def document(db, target, intervals, minimum_events=0, minimum_windows=0):
    settings = get_settings()
    ordered = sorted(intervals, key=lambda x: x.start_at)
    if len({item.name for item in ordered}) != len(ordered):
        raise HTTPException(422, "Interval names must be unique")
    if any(a.end_at > b.start_at for a, b in zip(ordered, ordered[1:])):
        raise HTTPException(422, "Evidence intervals must be disjoint")
    start, end = ordered[0].start_at, ordered[-1].end_at
    if (
        end - start
    ).total_seconds() / target.window_seconds > settings.baseline_max_windows:
        raise HTTPException(413, "Evidence interval spans too many windows")
    data = []
    for model in (ProcessExecEvent, RuntimeEvent):
        clauses = [
            model.docker_host_id == target.docker_host_id,
            model.container_id == target.container_id,
            model.image_digest == target.image_digest,
            or_(
                *(
                    and_(
                        model.occurred_at >= item.start_at,
                        model.occurred_at < item.end_at,
                    )
                    for item in ordered
                )
            ),
        ]
        if model is ProcessExecEvent:
            clauses.append(model.correlation_status == "resolved")
        rows = list(
            db.scalars(
                select(model)
                .where(*clauses)
                .order_by(model.occurred_at, model.event_id)
                .limit(settings.baseline_max_events + 1)
            ).all()
        )
        data.append(utc_events(rows))
    if sum(map(len, data)) > settings.baseline_max_events:
        raise HTTPException(413, "Too many profile events")
    return build_profile_document(
        image_digest=target.image_digest,
        start_at=start,
        end_at=end,
        window_seconds=target.window_seconds,
        process_events=data[0],
        runtime_events=data[1],
        minimum_process_events=minimum_events,
        minimum_nonempty_windows=minimum_windows,
        feature_schema_version=COMMAND_LINEAGE_SCHEMA,
    )


@router.post(
    "/operator/v1/assessment-targets", dependencies=[Depends(require_operator_token)]
)
def enroll_target(payload: TargetIn, db: Session = Depends(get_db)):
    identity = db.scalar(
        select(ContainerIdentity).where(
            ContainerIdentity.docker_host_id == payload.docker_host_id,
            ContainerIdentity.container_id == payload.container_id,
        )
    )
    if identity is None or identity.image_digest != payload.image_digest:
        raise HTTPException(
            409, "Target must match exact host/container inventory and immutable digest"
        )
    context = security_context(identity.current_snapshot)
    context_hash = sha256_document(context)
    existing = db.scalar(
        select(AssessmentTarget).where(
            AssessmentTarget.docker_host_id == payload.docker_host_id,
            AssessmentTarget.container_id == payload.container_id,
            AssessmentTarget.image_digest == payload.image_digest,
            AssessmentTarget.context_hash == context_hash,
        )
    )
    if existing:
        return existing
    target = AssessmentTarget(
        target_id=str(uuid4()),
        docker_host_id=payload.docker_host_id,
        container_id=payload.container_id,
        image_digest=payload.image_digest,
        context_hash=context_hash,
        context_manifest=context,
        window_seconds=payload.window_seconds,
        next_window_start=payload.start_at,
        allowed_lateness_seconds=(
            payload.allowed_lateness_seconds
            if payload.allowed_lateness_seconds is not None
            else get_settings().assessment_allowed_lateness_seconds
        ),
        enabled=True,
        coverage_state="unprofiled",
        created_by=audit_subject("trusted-local"),
        created_at=datetime.now(timezone.utc),
    )
    db.add(target)
    db.flush()
    audit(db, target, "enrolled", {"context_hash": context_hash})
    db.commit()
    db.refresh(target)
    return target


@router.post(
    "/operator/v1/assessment-targets/{target_id}/profiles",
    dependencies=[Depends(require_operator_token)],
)
def propose_profile(
    target_id: str, payload: CandidateIn, db: Session = Depends(get_db)
):
    target = get_target(db, target_id, lock=True)
    validate_identity(db, target)
    features, quality, manifest, model_hash = document(
        db,
        target,
        payload.intervals,
        payload.minimum_process_events,
        payload.minimum_nonempty_windows,
    )
    provenance = {
        "intervals": [x.model_dump(mode="json") for x in payload.intervals],
        "reference": payload.reference,
        "context_hash": target.context_hash,
        "docker_host_id": target.docker_host_id,
        "container_id": target.container_id,
        "proposed_by": audit_subject("trusted-local"),
    }
    artifact_hash = sha256_document(
        {"model_hash": model_hash, "provenance": provenance}
    )
    existing = db.scalar(
        select(ManagedProfile).where(
            ManagedProfile.target_id == target_id,
            ManagedProfile.artifact_hash == artifact_hash,
        )
    )
    if existing:
        return existing
    if db.get_bind().dialect.name == "postgresql":
        db.execute(
            select(func.pg_advisory_xact_lock(func.hashtext(target.image_digest)))
        )
    version = (
        db.scalar(
            select(func.max(BehaviorProfile.profile_version)).where(
                BehaviorProfile.image_digest == target.image_digest
            )
        )
        or 0
    ) + 1
    manifest = dict(manifest, managed_provenance=provenance)
    # Managed lifecycle is separate; retired allows explicit artifact scoring
    # without competing with the historical one-active-profile-per-digest rule.
    profile = BehaviorProfile(
        profile_id=str(uuid4()),
        image_digest=target.image_digest,
        profile_version=version,
        status="retired",
        feature_schema_version=COMMAND_LINEAGE_SCHEMA,
        model_hash=artifact_hash,
        training_start=min(x.start_at for x in payload.intervals),
        training_end=max(x.end_at for x in payload.intervals),
        window_seconds=target.window_seconds,
        approved_by=audit_subject("trusted-local"),
        approval_reference=payload.reference,
        process_event_count=manifest["process_event_count"],
        runtime_event_count=manifest["runtime_event_count"],
        container_count=manifest["container_count"],
        window_count=manifest["window_count"],
        quality=quality,
        training_manifest=manifest,
        features=features,
        created_at=datetime.now(timezone.utc),
    )
    db.add(profile)
    db.flush()
    enrollment = ManagedProfile(
        enrollment_id=str(uuid4()),
        target_id=target_id,
        profile_id=profile.profile_id,
        artifact_hash=artifact_hash,
        state="candidate",
        provenance=provenance,
        proposed_by=audit_subject("trusted-local"),
        created_at=datetime.now(timezone.utc),
    )
    db.add(enrollment)
    audit(db, target, "candidate", {"artifact_hash": artifact_hash})
    db.commit()
    db.refresh(enrollment)
    return {"enrollment": enrollment, "quality": quality}


def managed(db, target_id, enrollment_id):
    row = db.scalar(
        select(ManagedProfile)
        .where(
            ManagedProfile.enrollment_id == enrollment_id,
            ManagedProfile.target_id == target_id,
        )
        .with_for_update()
    )
    if row is None:
        raise HTTPException(404, "Managed profile not found")
    return row


@router.post(
    "/operator/v1/assessment-targets/{target_id}/profiles/{enrollment_id}/shadow",
    dependencies=[Depends(require_operator_token)],
)
def shadow_profile(
    target_id: str,
    enrollment_id: str,
    payload: BenignInterval,
    db: Session = Depends(get_db),
):
    target = get_target(db, target_id, lock=True)
    validate_identity(db, target)
    row = managed(db, target_id, enrollment_id)
    if row.state not in {"candidate", "shadow"}:
        raise HTTPException(409, "Only candidates may enter shadow review")
    profile = db.get(BehaviorProfile, row.profile_id)
    if not profile.quality.get("passed"):
        raise HTTPException(409, "Candidate failed quality gates")
    # Reject the whole training envelope, including unobserved gaps.
    if payload.start_at < utc(profile.training_end) and payload.end_at > utc(
        profile.training_start
    ):
        raise HTTPException(409, "Shadow interval overlaps training")
    features, quality, manifest, _ = document(db, target, [payload], 10, 1)
    if not quality.get("passed"):
        raise HTTPException(409, "Shadow interval failed evidence quality gates")
    candidate = score_feature_documents(
        baseline_features=profile.features, observation_features=features
    )
    active = (
        db.get(ManagedProfile, target.active_profile_id)
        if target.active_profile_id
        else None
    )
    prior = db.get(BehaviorProfile, active.profile_id) if active else None
    if (
        prior
        and payload.start_at < utc(prior.training_end)
        and payload.end_at > utc(prior.training_start)
    ):
        raise HTTPException(409, "Shadow interval overlaps active comparator training")
    result = {
        "interval": payload.model_dump(mode="json"),
        "selected_event_ids_sha256": manifest["selected_event_ids_sha256"],
        "candidate_hash": row.artifact_hash,
        "candidate_score": candidate[0],
        "active_hash": active.artifact_hash if active else None,
        "active_score": score_feature_documents(
            baseline_features=prior.features, observation_features=features
        )[0]
        if prior
        else None,
        "reviewed_by": audit_subject("trusted-local"),
        "coverage": manifest.get("observation_coverage", {}),
    }
    if row.shadow_result is not None and row.shadow_result != result:
        raise HTTPException(409, "Shadow result is immutable; propose a new candidate")
    if row.shadow_result == result:
        return row
    row.shadow_result = result
    row.state = "shadow"
    audit(db, target, "shadow", {"artifact_hash": row.artifact_hash, "result": result})
    db.commit()
    db.refresh(row)
    return row


def promote(db, target_id, enrollment_id, rollback=False):
    target = get_target(db, target_id, lock=True)
    validate_identity(db, target)
    row = managed(db, target_id, enrollment_id)
    profile = db.get(BehaviorProfile, row.profile_id)
    if target.active_profile_id == row.enrollment_id:
        return row
    if (
        not profile.quality.get("passed")
        or not row.shadow_result
        or (rollback and not row.approved_by)
    ):
        raise HTTPException(
            409, "Promotion requires a quality-passing, reviewed immutable artifact"
        )
    if (
        not rollback
        and row.state != "shadow"
        and not (row.state == "retired" and row.approved_by)
    ):
        raise HTTPException(409, "Promotion requires shadow state")
    old = (
        managed(db, target_id, target.active_profile_id)
        if target.active_profile_id
        else None
    )
    if old:
        old.state = "retired"
    row.state = "active"
    row.approved_by = audit_subject("trusted-local")
    target.active_profile_id = row.enrollment_id
    target.coverage_state = "degraded"
    audit(
        db,
        target,
        "rollback" if rollback else "activated",
        {
            "artifact_hash": row.artifact_hash,
            "previous_hash": old.artifact_hash if old else None,
        },
    )
    db.commit()
    db.refresh(row)
    return row


@router.post(
    "/operator/v1/assessment-targets/{target_id}/profiles/{enrollment_id}/activate",
    dependencies=[Depends(require_operator_token)],
)
def activate_profile(target_id: str, enrollment_id: str, db: Session = Depends(get_db)):
    return promote(db, target_id, enrollment_id)


@router.post(
    "/operator/v1/assessment-targets/{target_id}/profiles/{enrollment_id}/rollback",
    dependencies=[Depends(require_operator_token)],
)
def rollback_profile(target_id: str, enrollment_id: str, db: Session = Depends(get_db)):
    return promote(db, target_id, enrollment_id, True)


@router.post(
    "/operator/v1/assessment-targets/{target_id}/disable",
    dependencies=[Depends(require_operator_token)],
)
def disable_target(target_id: str, db: Session = Depends(get_db)):
    target = get_target(db, target_id, lock=True)
    if not target.enabled:
        return target
    target.enabled = False
    audit(db, target, "disabled", {})
    db.commit()
    db.refresh(target)
    return target


@router.get("/api/v1/assessment-targets")
def list_targets(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    return list(
        db.scalars(
            select(AssessmentTarget)
            .order_by(AssessmentTarget.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.get("/api/v1/assessment-targets/{target_id}/profiles")
def list_profiles(
    target_id: str, limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)
):
    return list(
        db.scalars(
            select(ManagedProfile)
            .where(ManagedProfile.target_id == target_id)
            .order_by(ManagedProfile.created_at.desc())
            .limit(limit)
        ).all()
    )


@router.get("/api/v1/assessment-targets/{target_id}/audit")
def target_audit(
    target_id: str, limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)
):
    get_target(db, target_id)
    return list(
        db.scalars(
            select(AssessmentAudit)
            .where(AssessmentAudit.target_id == target_id)
            .order_by(AssessmentAudit.created_at.desc(), AssessmentAudit.audit_id)
            .limit(limit)
        ).all()
    )
