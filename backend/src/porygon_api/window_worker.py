"""Bounded PostgreSQL polling with durable checkpoints and fenced assessments."""

from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import logging
import threading
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, or_, and_, func
from porygon_api.security import require_operator_token
from porygon_api.auth import utc
from porygon_api.assessment_service import (
    AssessmentScope,
    compute_anomaly_score,
    run_detection,
)
from porygon_api.config import get_settings
from porygon_api.coverage import coverage_for
from porygon_api.db import SessionLocal, get_db
from porygon_api.models import (
    AssessmentTarget,
    ManagedProfile,
    AssessmentJob,
    BehaviorProfile,
    DetectionAllowlist,
    CustomDetectionRule,
    KernelRuntimeEvent,
)
from porygon_api.profile_lifecycle import get_target, audit
from porygon_api.schemas import AnomalyScoreComputeIn, DetectionRunIn
from porygon_api.scoring import get_scoring_config
from porygon_api.detection import ruleset_hash, custom_ruleset_hash, allowlist_set_hash
from porygon_api.vulnerability import sha256_document

logger = logging.getLogger("porygon.assessments")
router = APIRouter(tags=["continuous-assessment"])


def configuration(db, target, profile, settings, now):
    allowlists = list(
        db.scalars(
            select(DetectionAllowlist)
            .where(
                DetectionAllowlist.image_digest == target.image_digest,
                DetectionAllowlist.active.is_(True),
                or_(
                    DetectionAllowlist.expires_at.is_(None),
                    DetectionAllowlist.expires_at > now,
                ),
            )
            .order_by(DetectionAllowlist.allowlist_id)
        ).all()
    )
    rules = list(
        db.scalars(
            select(CustomDetectionRule)
            .where(CustomDetectionRule.enabled.is_(True))
            .order_by(CustomDetectionRule.slug)
        ).all()
    )
    documents = [
        {
            key: getattr(row, key)
            for key in (
                "slug",
                "name",
                "category",
                "description",
                "target",
                "condition",
                "severity_weight",
                "confidence_weight",
                "incident_eligible",
                "enabled",
            )
        }
        for row in rules
    ]
    from porygon_api.runtime_evidence import RULES_HASH
    from porygon_api.models import AdvisoryModel
    model=db.scalar(select(AdvisoryModel).where(AdvisoryModel.active.is_(True)))
    return {
        "runtime_evidence_rules_hash":RULES_HASH if settings.runtime_evidence_enabled else None,
        "advisory_model_hash":model.artifact_hash if model and settings.runtime_evidence_enabled else None,
        "ruleset_hash": ruleset_hash(),
        "custom_ruleset_hash": custom_ruleset_hash(documents),
        "allowlist_set_hash": allowlist_set_hash(allowlists),
        "scoring": get_scoring_config(profile.feature_schema_version)
        if profile
        else None,
        "minimum_process_events": settings.anomaly_min_process_events,
        "allowed_lateness_seconds": target.allowed_lateness_seconds,
        "target_context_hash": target.context_hash,
    }


def enqueue(db, target, start, revision, settings, now):
    enrollment = (
        db.get(ManagedProfile, target.active_profile_id)
        if target.active_profile_id
        else None
    )
    profile = db.get(BehaviorProfile, enrollment.profile_id) if enrollment else None
    config = configuration(db, target, profile, settings, now)
    config_hash = sha256_document(config)
    end = utc(start) + timedelta(seconds=target.window_seconds)
    key = sha256_document(
        {
            "host": target.docker_host_id,
            "container": target.container_id,
            "image": target.image_digest,
            "context": target.context_hash,
            "profile": enrollment.artifact_hash if enrollment else None,
            "config": config_hash,
            "window_start": utc(start).isoformat(),
            "window_end": end.isoformat(),
            "revision": revision,
        }
    )
    existing = db.scalar(
        select(AssessmentJob).where(AssessmentJob.assessment_key == key)
    )
    if existing:
        return existing
    row = AssessmentJob(
        job_id=str(uuid4()),
        assessment_key=key,
        target_id=target.target_id,
        profile_enrollment_id=enrollment.enrollment_id if enrollment else None,
        window_start=utc(start),
        window_end=end,
        revision=revision,
        config_hash=config_hash,
        config_manifest=config,
        state="pending",
        generation=0,
        attempts=0,
        coverage={},
        created_at=now,
    )
    db.add(row)
    db.flush()
    return row


class ConfigurationChanged(Exception):
    """The evaluator used a different configuration from the durable job."""


class LeaseLost(Exception):
    """A recovered generation has exclusive authority over this assessment."""


class AssessmentWorker:
    def __init__(self, settings, session_factory=SessionLocal, owner=None):
        self.settings = settings
        self.session_factory = session_factory
        self.owner = owner or "assessment-" + uuid4().hex
        self.stop_event = threading.Event()
        self.thread = None

    def schedule(self, now=None):
        now = now or datetime.now(timezone.utc)
        count = 0
        with self.session_factory() as db:
            targets = db.scalars(
                select(AssessmentTarget)
                .where(AssessmentTarget.enabled.is_(True))
                .order_by(
                    AssessmentTarget.next_window_start, AssessmentTarget.target_id
                )
                .with_for_update(skip_locked=True)
                .limit(self.settings.assessment_jobs_per_tick)
            ).all()
            for target in targets:
                start = utc(target.next_window_start)
                while count < self.settings.assessment_jobs_per_tick:
                    end = start + timedelta(seconds=target.window_seconds)
                    if end + timedelta(seconds=target.allowed_lateness_seconds) > now:
                        break
                    enqueue(db, target, start, 0, self.settings, now)
                    start = end
                    target.next_window_start = start
                    count += 1
            db.commit()
        return count

    def claim(self, now=None):
        now = now or datetime.now(timezone.utc)
        with self.session_factory() as db:
            row = db.scalar(
                select(AssessmentJob)
                .where(
                    or_(
                        and_(
                            AssessmentJob.state == "pending",
                            or_(
                                AssessmentJob.next_retry_at.is_(None),
                                AssessmentJob.next_retry_at <= now,
                            ),
                        ),
                        and_(
                            AssessmentJob.state == "claimed",
                            AssessmentJob.lease_expires_at < now,
                        ),
                    )
                )
                .order_by(AssessmentJob.created_at, AssessmentJob.job_id)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if row is None:
                return None
            if row.attempts >= self.settings.assessment_max_attempts:
                row.state = "failed"
                row.error_category = "attempts_exhausted"
                db.commit()
                return None
            row.state = "claimed"
            row.lease_owner = self.owner
            row.generation += 1
            row.attempts += 1
            row.lease_expires_at = now + timedelta(
                seconds=self.settings.assessment_lease_seconds
            )
            db.commit()
            return row.job_id, row.generation

    def renew(self, job_id, generation, now=None):
        now = now or datetime.now(timezone.utc)
        with self.session_factory() as db:
            row = db.scalar(
                select(AssessmentJob)
                .where(AssessmentJob.job_id == job_id)
                .with_for_update()
            )
            self._fence(row, generation, now)
            row.lease_expires_at = now + timedelta(
                seconds=self.settings.assessment_lease_seconds
            )
            db.commit()

    def _fence(self, row, generation, now):
        if (
            row is None
            or row.state != "claimed"
            or row.generation != generation
            or row.lease_owner != self.owner
            or row.lease_expires_at is None
            or utc(row.lease_expires_at) <= now
        ):
            raise LeaseLost("Assessment lease no longer owns this generation")

    def assess(self, job_id, generation):
        with self.session_factory() as db:
            row = db.scalar(
                select(AssessmentJob)
                .where(AssessmentJob.job_id == job_id)
                .with_for_update()
            )
            self._fence(row, generation, datetime.now(timezone.utc))
            target = db.get(AssessmentTarget, row.target_id)
            coverage = coverage_for(db, target, row.window_start, self.settings)
            enrollment = (
                db.get(ManagedProfile, row.profile_enrollment_id)
                if row.profile_enrollment_id
                else None
            )
            profile = (
                db.get(BehaviorProfile, enrollment.profile_id) if enrollment else None
            )
            now = datetime.now(timezone.utc)
            if not target.enabled:
                coverage.update(
                    state="unavailable",
                    reasons=coverage["reasons"] + ["target_disabled"],
                )
            elif enrollment is None:
                coverage.update(
                    state="unavailable"
                    if coverage["state"] == "unavailable"
                    else "unprofiled",
                    reasons=coverage["reasons"] + ["no_approved_profile"],
                )
            elif profile is None or profile.model_hash != enrollment.artifact_hash:
                coverage.update(
                    state="unavailable",
                    reasons=coverage["reasons"] + ["profile_integrity"],
                )
            elif (
                sha256_document(configuration(db, target, profile, self.settings, now))
                != row.config_hash
            ):
                coverage.update(
                    state="unavailable",
                    reasons=coverage["reasons"] + ["configuration_changed"],
                )
            if coverage["state"] not in {"unavailable", "unprofiled"}:
                scope = AssessmentScope(
                    target.docker_host_id,
                    target.container_id,
                    target.context_hash,
                    row.revision,
                    row.config_hash,
                    "porygon.runtime-evidence" if self.settings.runtime_evidence_enabled else None,
                    row.config_manifest.get("runtime_evidence_rules_hash"),
                    row.config_manifest.get("advisory_model_hash"),
                )
                score = compute_anomaly_score(
                    AnomalyScoreComputeIn(
                        image_digest=target.image_digest,
                        profile_id=profile.profile_id,
                        window_start=utc(row.window_start),
                    ),
                    db,
                    scope=scope,
                    commit=False,
                    settings=self.settings,
                )
                detected = run_detection(
                    DetectionRunIn(anomaly_score_id=score.score_id),
                    db,
                    scope=scope,
                    commit=False,
                )
                actual = detected["run"]
                evidence=actual.result.get('runtime_evidence')
                if self.settings.runtime_evidence_enabled and (not evidence or
                    evidence['rules_hash']!=row.config_manifest.get('runtime_evidence_rules_hash') or
                    evidence['model'].get('artifact_sha256')!=row.config_manifest.get('advisory_model_hash')):
                    raise ConfigurationChanged()

                if (
                    actual.ruleset_hash != row.config_manifest["ruleset_hash"]
                    or actual.allowlist_set_hash
                    != row.config_manifest["allowlist_set_hash"]
                    or actual.custom_ruleset_hash
                    != row.config_manifest["custom_ruleset_hash"]
                    or score.scoring_config != row.config_manifest["scoring"]
                ):
                    raise ConfigurationChanged()
                row.score_id = score.score_id
                row.detection_run_id = detected["run"].run_id
                if score.status == "insufficient_data":
                    coverage["state"] = "insufficient_data"
                    coverage["reasons"].append("missing_process_evidence")
                coverage["kernel_event_count"] = (
                    db.scalar(
                        select(func.count())
                        .select_from(KernelRuntimeEvent)
                        .where(
                            KernelRuntimeEvent.docker_host_id == target.docker_host_id,
                            KernelRuntimeEvent.container_id == target.container_id,
                            KernelRuntimeEvent.occurred_at >= row.window_start,
                            KernelRuntimeEvent.occurred_at < row.window_end,
                        )
                    )
                    or 0
                )
            # One transaction owns score, incident evidence and completed job.
            self._fence(row, generation, datetime.now(timezone.utc))
            row.coverage = coverage
            target.coverage_state = coverage["state"]
            row.state = (
                "unavailable" if coverage["state"] == "unavailable" else "completed"
            )
            row.completed_at = datetime.now(timezone.utc)
            row.lease_expires_at = None
            row.error_category = None
            db.commit()

    def fail(self, job_id, generation, configuration_changed=False):
        with self.session_factory() as db:
            row = db.scalar(
                select(AssessmentJob)
                .where(AssessmentJob.job_id == job_id)
                .with_for_update()
            )
            if (
                row is None
                or row.generation != generation
                or row.lease_owner != self.owner
                or row.state != "claimed"
            ):
                return
            row.state = (
                "failed"
                if row.attempts >= self.settings.assessment_max_attempts
                else "pending"
            )
            row.error_category = "assessment_error"
            row.lease_expires_at = None
            row.next_retry_at = datetime.now(timezone.utc) + timedelta(
                seconds=min(300, 2**row.attempts)
            )
            if configuration_changed:
                row.state = "unavailable"
                row.error_category = "configuration_changed"
                row.coverage = {
                    "state": "unavailable",
                    "reasons": ["configuration_changed"],
                    "completeness": "unknown",
                }
                row.completed_at = datetime.now(timezone.utc)
            db.commit()

    def run_once(self):
        self.schedule()
        completed = 0
        for _ in range(self.settings.assessment_jobs_per_tick):
            lease = self.claim()
            if lease is None:
                break
            try:
                self.assess(*lease)
                completed += 1
            except LeaseLost:
                pass
            except ConfigurationChanged:
                self.fail(*lease, configuration_changed=True)
            except Exception:
                # Exception payloads may contain telemetry; expose category only.
                logger.warning("Assessment failed; bounded retry scheduled")
                self.fail(*lease)
        return completed

    def _run(self):
        while not self.stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                logger.warning("Assessment worker unavailable; retrying next tick")
            self.stop_event.wait(self.settings.assessment_poll_seconds)

    def start(self):
        self.thread = threading.Thread(
            target=self._run, name="porygon-assessments", daemon=True
        )
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=15)


class RevisionIn(BaseModel):
    window_start: datetime
    revision: int = Field(ge=1, le=1000000)
    reason: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def timezone_required(self):
        if self.window_start.tzinfo is None:
            raise ValueError("Window start requires a timezone")
        return self


@router.post(
    "/operator/v1/assessment-targets/{target_id}/reprocess",
    dependencies=[Depends(require_operator_token)],
)
def reprocess(target_id: str, payload: RevisionIn, db=Depends(get_db)):
    target = get_target(db, target_id, lock=True)
    if utc(payload.window_start) + timedelta(
        seconds=target.window_seconds + target.allowed_lateness_seconds
    ) > datetime.now(timezone.utc):
        raise HTTPException(409, "Window is not eligible after allowed lateness")
    base = db.scalar(
        select(AssessmentJob).where(
            AssessmentJob.target_id == target_id,
            AssessmentJob.window_start == payload.window_start,
            AssessmentJob.revision == 0,
        )
    )
    if base is None:
        raise HTTPException(
            409, "Revision requires an actually scheduled original window"
        )
    previous = db.scalar(
        select(AssessmentJob).where(
            AssessmentJob.target_id == target_id,
            AssessmentJob.window_start == payload.window_start,
            AssessmentJob.revision == payload.revision,
        )
    )
    if previous is not None:
        return previous
    highest = (
        db.scalar(
            select(func.max(AssessmentJob.revision)).where(
                AssessmentJob.target_id == target_id,
                AssessmentJob.window_start == payload.window_start,
            )
        )
        or 0
    )
    if payload.revision != highest + 1:
        raise HTTPException(
            409, "Revision must advance the latest recorded generation by one"
        )
    row = enqueue(
        db,
        target,
        payload.window_start,
        payload.revision,
        get_settings(),
        datetime.now(timezone.utc),
    )
    audit(
        db,
        target,
        "reprocess",
        {"assessment_key": row.assessment_key, "reason": payload.reason},
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/api/v1/assessment-jobs")
def list_jobs(
    target_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    db=Depends(get_db),
):
    query = select(AssessmentJob)
    if target_id:
        query = query.where(AssessmentJob.target_id == target_id)
    return list(
        db.scalars(query.order_by(AssessmentJob.created_at.desc()).limit(limit)).all()
    )


@router.get("/api/v1/assessment-worker/status")
def worker_status(db=Depends(get_db)):
    counts = dict(
        db.execute(
            select(AssessmentJob.state, func.count()).group_by(AssessmentJob.state)
        ).all()
    )
    oldest = db.scalar(
        select(func.min(AssessmentJob.window_start)).where(
            AssessmentJob.state.in_(["pending", "claimed"])
        )
    )
    latest = db.scalar(select(func.max(AssessmentJob.completed_at)))
    return {
        "enabled_in_api": get_settings().assessment_enabled,
        "counts": counts,
        "oldest_pending_window": oldest,
        "latest_completion": latest,
        "response_approval": "never",
        "source_drop_coverage": "unknown",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--owner", default=None)
    args = parser.parse_args()
    worker = AssessmentWorker(get_settings(), owner=args.owner)
    if args.once:
        worker.run_once()
    else:
        try:
            worker._run()
        except KeyboardInterrupt:
            worker.stop()


if __name__ == "__main__":
    main()
