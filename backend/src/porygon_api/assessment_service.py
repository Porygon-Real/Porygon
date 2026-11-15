"""Shared assessment orchestration with explicit scope and transaction ownership."""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import re
from uuid import uuid4
from fastapi import HTTPException, status
from sqlalchemy import select, func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from porygon_api.config import get_settings
from porygon_api.baseline import (
    build_profile_document,
    COMMAND_LINEAGE_SCHEMA,
    SUPPORT_AWARE_SCHEMA,
    MIN_COMMAND_COVERAGE,
    FEATURE_SCHEMA_VERSION,
)
from porygon_api.models import (
    BehaviorProfile,
    AnomalyScore,
    ProcessExecEvent,
    RuntimeEvent,
    KernelRuntimeEvent,
    DetectionAllowlist,
    DetectionRun,
    DetectionIncidentLink,
    Incident,
    IncidentEvidence,
)
from porygon_api.schemas import AnomalyScoreComputeIn, DetectionRunIn
from porygon_api.scoring import (
    get_scoring_config,
    build_observation_key,
    score_feature_documents,
    ALGORITHM_VERSION,
)
from porygon_api.detection import (
    allowlist_set_hash,
    build_detection_run_key,
    evaluate_detection,
    RULESET_VERSION,
    ruleset_hash,
)
from porygon_api.incident_grouping import attach_incident
from porygon_api.ml_classifier import default_classifier
from porygon_api.vulnerability import sha256_document
from porygon_api.vulnerability import is_local_image_identity

logger = logging.getLogger("porygon.assessment")


def utc_events(rows):
    """SQLite fixture timestamps follow PostgreSQL's UTC event contract."""
    from types import SimpleNamespace
    from porygon_api.auth import utc

    return [
        row
        if row.occurred_at.tzinfo is not None
        else SimpleNamespace(
            **{
                key: value
                for key, value in row.__dict__.items()
                if not key.startswith("_") and key != "occurred_at"
            },
            occurred_at=utc(row.occurred_at),
        )
        for row in rows
    ]


@dataclass(frozen=True)
class AssessmentScope:
    docker_host_id: str
    container_id: str
    context_hash: str
    revision: int = 0
    config_hash: str | None = None
    evidence_contract: str | None = None
    evidence_rules_hash: str | None = None
    advisory_model_hash: str | None = None

    def __post_init__(self):
        if not self.docker_host_id or not re.fullmatch(
            r"[a-f0-9]{64}", self.container_id
        ):
            raise ValueError(
                "Assessment scope requires host and exact full container ID"
            )
        if not re.fullmatch(r"[a-f0-9]{64}", self.context_hash) or self.revision < 0:
            raise ValueError("Invalid assessment context or revision")

    def manifest(self):
        return {
            "docker_host_id": self.docker_host_id,
            "container_id": self.container_id,
            "context_hash": self.context_hash,
            "revision": self.revision,
            "config_hash": self.config_hash,
            "evidence_contract": self.evidence_contract,
            "evidence_rules_hash": self.evidence_rules_hash,
            "advisory_model_hash": self.advisory_model_hash,
        }

    def filters(self, model):
        return (
            model.docker_host_id == self.docker_host_id,
            model.container_id == self.container_id,
        )


def _detection_execution(db: Session, run: DetectionRun) -> dict[str, object]:
    link = db.get(DetectionIncidentLink, run.run_id)
    incident = (
        db.get(Incident, link.incident_id)
        if link is not None
        else db.scalar(select(Incident).where(Incident.detection_run_id == run.run_id))
    )
    timeline: list[IncidentEvidence] = []
    if incident is not None:
        timeline = list(
            db.scalars(
                select(IncidentEvidence)
                .where(IncidentEvidence.incident_id == incident.incident_id)
                .order_by(IncidentEvidence.sequence_no)
            ).all()
        )
    return {"run": run, "incident": incident, "timeline": timeline}


def compute_anomaly_score(
    payload: AnomalyScoreComputeIn,
    db: Session,
    *,
    scope: AssessmentScope | None = None,
    commit: bool = True,
    settings=None,
) -> AnomalyScore:
    """Score one fixed window against an immutable-digest behaviour profile.

    The result is a distance measurement, not a maliciousness verdict. A window
    without process telemetry is persisted as insufficient_data so telemetry loss
    is not silently interpreted as normal or anomalous behaviour.
    """

    settings = settings or get_settings()
    if payload.profile_id:
        profile = db.get(BehaviorProfile, payload.profile_id)
        if profile is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found"
            )
        if profile.image_digest != payload.image_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Profile image digest does not match requested image digest",
            )
        if profile.status == "draft" or not bool(profile.quality.get("passed")):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Only quality-passing active or retired profiles may be used for scoring",
            )
    else:
        profile = db.scalar(
            select(BehaviorProfile).where(
                BehaviorProfile.image_digest == payload.image_digest,
                BehaviorProfile.status == "active",
            )
        )
        if profile is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active profile exists for the requested image digest",
            )

    managed = profile.training_manifest.get("managed_provenance")
    if managed:
        expected = (
            managed["docker_host_id"],
            managed["container_id"],
            managed["context_hash"],
        )
        if scope is None:
            scope = AssessmentScope(*expected)
        elif (scope.docker_host_id, scope.container_id, scope.context_hash) != expected:
            raise HTTPException(
                409, "Managed profile cannot cross its approved target scope"
            )
    try:
        scoring_config = get_scoring_config(
            profile.feature_schema_version, payload.algorithm_version
        )
        if profile.features.get("schema_version") != profile.feature_schema_version:
            raise ValueError(
                "Profile feature document does not match its schema identity"
            )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    window_start = payload.window_start.astimezone(timezone.utc)
    window_end = window_start + timedelta(seconds=profile.window_seconds)
    if window_end > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The fixed observation window has not completed yet",
        )
    from porygon_api.auth import utc

    if window_start < utc(profile.training_end) and window_end > utc(
        profile.training_start
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scoring windows must not overlap the profile training interval",
        )

    local_image_id = (
        payload.image_digest.removeprefix("local:")
        if is_local_image_identity(payload.image_digest)
        else None
    )
    process_image_filter = (
        ProcessExecEvent.image_id == local_image_id
        if local_image_id is not None
        else ProcessExecEvent.image_digest == payload.image_digest
    )
    runtime_image_filter = (
        RuntimeEvent.image_id == local_image_id
        if local_image_id is not None
        else RuntimeEvent.image_digest == payload.image_digest
    )
    process_filters = (
        process_image_filter,
        ProcessExecEvent.correlation_status == "resolved",
        ProcessExecEvent.occurred_at >= window_start,
        ProcessExecEvent.occurred_at < window_end,
    )
    runtime_filters = (
        runtime_image_filter,
        RuntimeEvent.occurred_at >= window_start,
        RuntimeEvent.occurred_at < window_end,
    )
    if scope is not None and scope.evidence_contract:
        from porygon_api.runtime_evidence import epoch_ns

        process_filters = process_filters[:2] + (
            ProcessExecEvent.time_nano >= epoch_ns(window_start),
            ProcessExecEvent.time_nano < epoch_ns(window_end),
        )
        runtime_filters = runtime_filters[:1] + (
            RuntimeEvent.time_nano >= epoch_ns(window_start),
            RuntimeEvent.time_nano < epoch_ns(window_end),
        )
    if scope is not None:
        process_filters += scope.filters(ProcessExecEvent)
        runtime_filters += scope.filters(RuntimeEvent)
    process_count = (
        db.scalar(
            select(func.count()).select_from(ProcessExecEvent).where(*process_filters)
        )
        or 0
    )
    runtime_count = (
        db.scalar(
            select(func.count()).select_from(RuntimeEvent).where(*runtime_filters)
        )
        or 0
    )
    if process_count + runtime_count > settings.anomaly_max_events:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Observation window contains {process_count + runtime_count} events; "
                f"maximum is {settings.anomaly_max_events}"
            ),
        )

    process_events = list(
        db.scalars(
            select(ProcessExecEvent)
            .where(*process_filters)
            .order_by(ProcessExecEvent.occurred_at, ProcessExecEvent.event_id)
        ).all()
    )
    runtime_events = list(
        db.scalars(
            select(RuntimeEvent)
            .where(*runtime_filters)
            .order_by(RuntimeEvent.occurred_at, RuntimeEvent.event_id)
        ).all()
    )

    process_events = utc_events(process_events)
    runtime_events = utc_events(runtime_events)
    observation_features, _, observation_manifest, _ = build_profile_document(
        image_digest=payload.image_digest,
        start_at=window_start,
        end_at=window_end,
        window_seconds=profile.window_seconds,
        process_events=process_events,
        runtime_events=runtime_events,
        minimum_process_events=0,
        minimum_nonempty_windows=0,
        feature_schema_version=profile.feature_schema_version,
        include_temporal_windows=profile.feature_schema_version == SUPPORT_AWARE_SCHEMA,
    )
    observation_key = build_observation_key(
        profile_id=profile.profile_id,
        profile_model_hash=profile.model_hash,
        window_start=window_start.isoformat(),
        window_end=window_end.isoformat(),
        selected_event_ids_sha256=observation_manifest["selected_event_ids_sha256"],
        feature_schema_version=profile.feature_schema_version,
        observation_features_sha256=observation_manifest.get("feature_document_sha256"),
        algorithm_version=scoring_config["algorithm_version"],
    )

    kernel_event_rows = []
    runtime_context = None
    if scope is not None:
        observation_manifest["assessment_scope"] = scope.manifest()
        observation_manifest["assessment_event_ids"] = {
            "process": [x.event_id for x in process_events],
            "runtime": [x.event_id for x in runtime_events],
        }
        from porygon_api.runtime_evidence import epoch_ns

        kernel_event_rows = list(
            db.scalars(
                select(KernelRuntimeEvent)
                .where(
                    *scope.filters(KernelRuntimeEvent),
                    (
                        KernelRuntimeEvent.image_id == local_image_id
                        if local_image_id is not None
                        else KernelRuntimeEvent.image_digest == payload.image_digest
                    ),
                    KernelRuntimeEvent.correlation_status == "resolved",
                    KernelRuntimeEvent.time_nano >= epoch_ns(window_start),
                    KernelRuntimeEvent.time_nano < epoch_ns(window_end),
                )
                .order_by(KernelRuntimeEvent.time_nano, KernelRuntimeEvent.event_id)
                .limit(settings.anomaly_max_events + 1)
            ).all()
        )
        if len(kernel_event_rows) > settings.anomaly_max_events:
            raise HTTPException(413, "Selected kernel evidence exceeds its bounded window")
        if process_count + runtime_count + len(kernel_event_rows) > settings.anomaly_max_events:
            raise HTTPException(413, "Selected assessment evidence exceeds its bounded window")
        observation_manifest["assessment_event_ids"]["kernel"] = [
            row.event_id for row in kernel_event_rows
        ]
        kernel_identities = [
            {
                "event_id": row.event_id,
                "docker_host_id": row.docker_host_id,
                "container_id": row.container_id,
                "sensor_instance_id": row.sensor_instance_id,
                "sensor_epoch": row.sensor_epoch,
                "pid_namespace_start_ns": row.pid_namespace_start_ns,
                "process_pid": row.process_pid,
                "process_start_ns": row.process_start_ns,
            }
            for row in kernel_event_rows
        ]
        observation_manifest["assessment_event_identities"] = {
            "kernel": kernel_identities,
        }
        if scope.evidence_contract:
            from porygon_api.runtime_evidence import (
                PROCESS_CONTEXT_CONTRACT,
                query_context_events,
                query_events,
                rules_hash_for,
            )

            try:
                expected_evidence_hash = rules_hash_for(scope.evidence_contract)
            except ValueError as exc:
                raise HTTPException(409, "Unsupported runtime evidence contract") from exc
            if scope.evidence_rules_hash != expected_evidence_hash:
                raise HTTPException(409, "Unsupported runtime evidence rule hash")
            selected = query_events(
                db,
                scope,
                window_start,
                window_end,
                process_ids=observation_manifest["assessment_event_ids"]["process"],
                kernel_ids=observation_manifest["assessment_event_ids"]["kernel"],
            )
            selected_kernel_ids = [
                item["event_id"] for item in selected if item["channel"] == "kernel"
            ]
            if selected_kernel_ids != observation_manifest["assessment_event_ids"]["kernel"]:
                raise HTTPException(409, "Selected kernel evidence is no longer available")
            if scope.evidence_contract == PROCESS_CONTEXT_CONTRACT:
                runtime_context = query_context_events(
                    db, scope, window_start, window_end, selected
                )
                context_ids = [
                    item["event_id"] for item in runtime_context["events"]
                ]
                observation_manifest["assessment_event_ids"]["context"] = context_ids
                observation_manifest["assessment_event_identities"]["context"] = [
                    {
                        "event_id": item["event_id"],
                        "docker_host_id": item.get("docker_host_id"),
                        "container_id": item.get("container_id"),
                        "sensor_instance_id": item.get("sensor_instance_id"),
                        "sensor_epoch": item.get("sensor_epoch"),
                        "pid_namespace_start_ns": item.get("pid_namespace_start_ns"),
                        "process_pid": item.get("process_pid"),
                        "process_start_ns": item.get("process_start_ns"),
                    }
                    for item in runtime_context["events"]
                ]
                observation_manifest["assessment_event_coverage"] = {
                    "process_context": runtime_context.get("status", "unavailable")
                }
        observation_key = sha256_document(
            {
                "legacy_key": observation_key,
                "scope": scope.manifest(),
                "assessment_event_identities": observation_manifest.get(
                    "assessment_event_identities", {}
                ),
                "context_status": (runtime_context or {}).get("status"),
            }
        )
    try:
        if db.get_bind().dialect.name == "postgresql":
            db.execute(
                select(func.pg_advisory_xact_lock(func.hashtext(observation_key)))
            )
        existing = db.scalar(
            select(AnomalyScore).where(AnomalyScore.observation_key == observation_key)
        )
        if existing is not None:
            return existing

        coverage_document = observation_manifest.get("observation_coverage", {})
        command_coverage = (
            coverage_document.get("command_usable_fraction", 0)
            if profile.feature_schema_version == SUPPORT_AWARE_SCHEMA
            else coverage_document.get("command_event_fraction", 0)
        )
        minimum_coverage_schema = profile.feature_schema_version in {
            COMMAND_LINEAGE_SCHEMA,
            SUPPORT_AWARE_SCHEMA,
        }
        missing_command_evidence = (
            minimum_coverage_schema and command_coverage < MIN_COMMAND_COVERAGE
        )
        if (
            process_count < settings.anomaly_min_process_events
            or missing_command_evidence
        ):
            score_status = "insufficient_data"
            band = "insufficient_data"
            total_score = None
            components = {
                "status": "insufficient_data",
                "available": False,
                "reason": "Insufficient process-execution telemetry",
                "reason_codes": ["process_event_support_below_minimum"],
                "required_process_events": settings.anomaly_min_process_events,
                "observed_process_events": process_count,
                "observed_runtime_events": runtime_count,
                "observed_kernel_events": len(kernel_event_rows),
            }
            if missing_command_evidence:
                components.update(
                    {
                        "reason": "Insufficient command-line evidence coverage",
                        "reason_codes": sorted(
                            {
                                *components.get("reason_codes", []),
                                "usable_command_coverage_below_minimum",
                            }
                        ),
                        "required_command_coverage": MIN_COMMAND_COVERAGE,
                        "observed_command_coverage": command_coverage,
                    }
                )
            explanation = {
                "band": band,
                "interpretation": (
                    "The observation was not scored because the process-execution evidence did not "
                    "meet the configured minimum. This is not evidence of normal behaviour."
                ),
                "top_contributors": [],
                "unseen_tokens": [],
                "highest_numeric_deviations": [],
            }
        else:
            try:
                total_score, band, components, explanation = score_feature_documents(
                    baseline_features=profile.features,
                    observation_features=observation_features,
                    algorithm_version=scoring_config["algorithm_version"],
                )
                score_status = components.get("status", "scored")
                if (
                    score_status == "scored"
                    and total_score is not None
                    and scoring_config["algorithm_version"] == ALGORITHM_VERSION
                ):
                    ml_res = default_classifier.predict_document(
                        observation_features=observation_features,
                        baseline_features=profile.features,
                        drift_score=total_score,
                    )
                    explanation["ml_threat_classification"] = ml_res.to_dict()
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=str(exc),
                ) from exc
            score_status = components.get("status", "scored")

        if (
            profile.feature_schema_version != FEATURE_SCHEMA_VERSION
            or scoring_config["algorithm_version"] != ALGORITHM_VERSION
        ):
            explanation["ml_input_contract"] = {
                "supported": False,
                "status": "unsupported_feature_contract",
                "required_feature_schema": FEATURE_SCHEMA_VERSION,
                "required_algorithm": ALGORITHM_VERSION,
                "observed_algorithm": scoring_config["algorithm_version"],
                "observed_feature_schema": profile.feature_schema_version,
            }

        now = datetime.now(timezone.utc)
        record = AnomalyScore(
            score_id=str(uuid4()),
            observation_key=observation_key,
            profile_id=profile.profile_id,
            image_digest=payload.image_digest,
            profile_version=profile.profile_version,
            profile_model_hash=profile.model_hash,
            algorithm_version=scoring_config["algorithm_version"],
            status=score_status,
            score_band=band,
            total_score=total_score,
            window_start=window_start,
            window_end=window_end,
            window_seconds=profile.window_seconds,
            process_event_count=observation_manifest["process_event_count"],
            runtime_event_count=observation_manifest["runtime_event_count"],
            container_count=observation_manifest["container_count"],
            components=components,
            explanation=explanation,
            observation_manifest=observation_manifest,
            assessment_scope=scope.manifest() if scope else None,
            scoring_config=scoring_config,
            created_at=now,
        )
        db.add(record)
        if scope and scope.evidence_contract:
            from porygon_api.runtime_evidence import build_bundle, rules_hash_for
            from porygon_api.evidence_features import extract_features
            from porygon_api.model_registry import predict
            from porygon_api.models import RuntimeEvidenceBundle, AdvisoryModel

            expected_hash = rules_hash_for(scope.evidence_contract)
            if scope.evidence_rules_hash != expected_hash:
                raise HTTPException(409, "Scheduled evidence rules changed")
            db.flush()
            # Freeze the entire argument-free replay bundle with the score.
            document = build_bundle(
                selected,
                scope,
                window_start,
                window_end,
                profile.features.get("observed_sets", {}).get("executables", []),
                context=runtime_context,
            )
            if runtime_context is not None and [
                item["event_id"] for item in document.get("context_events", [])
            ] != observation_manifest["assessment_event_ids"].get("context", []):
                raise HTTPException(409, "Frozen process context selection changed")
            features = extract_features(document)
            model = (
                db.get(AdvisoryModel, scope.advisory_model_hash)
                if scope.advisory_model_hash
                else None
            )
            if scope.advisory_model_hash and model is None:
                raise HTTPException(
                    409, "Scheduled advisory model artifact unavailable"
                )
            db.add(
                RuntimeEvidenceBundle(
                    bundle_hash=document["bundle_hash"],
                    score_id=record.score_id,
                    contract=scope.evidence_contract,
                    rules_hash=expected_hash,
                    document=document,
                    feature_document=features,
                    model_prediction=predict(
                        features, model.artifact if model else None
                    ),
                    created_at=now,
                )
            )
        if commit:
            db.commit()
            db.refresh(record)
        else:
            db.flush()
        return record
    except HTTPException:
        if not commit:
            raise
        db.rollback()
        raise
    except IntegrityError as exc:
        if not commit:
            raise
        db.rollback()
        existing = db.scalar(
            select(AnomalyScore).where(AnomalyScore.observation_key == observation_key)
        )
        if existing is not None:
            return existing
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A concurrent scoring request created a conflicting record",
        ) from exc
    except SQLAlchemyError as exc:
        if not commit:
            raise
        db.rollback()
        logger.exception("Anomaly-score persistence failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Anomaly-score persistence failed",
        ) from exc


def run_detection(
    payload: DetectionRunIn,
    db: Session,
    *,
    scope: AssessmentScope | None = None,
    commit: bool = True,
) -> dict[str, object]:
    score = db.get(AnomalyScore, payload.anomaly_score_id)
    if score is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly score not found"
        )

    if score.assessment_scope:
        persisted_scope = AssessmentScope(**score.assessment_scope)
        if scope is not None and scope != persisted_scope:
            raise HTTPException(
                409, "Detection scope differs from immutable score scope"
            )
        scope = persisted_scope
    elif scope is not None:
        raise HTTPException(409, "An unscoped score cannot be reinterpreted as scoped")
    now = datetime.now(timezone.utc)
    active_allowlists = list(
        db.scalars(
            select(DetectionAllowlist)
            .where(
                DetectionAllowlist.image_digest == score.image_digest,
                DetectionAllowlist.active.is_(True),
                or_(
                    DetectionAllowlist.expires_at.is_(None),
                    DetectionAllowlist.expires_at > now,
                ),
            )
            .order_by(DetectionAllowlist.allowlist_id)
        ).all()
    )
    selected_allowlist_hash = allowlist_set_hash(active_allowlists)
    from porygon_api.rule_workbench import resolve_active_snapshot

    custom_rule_snapshot = resolve_active_snapshot(db)
    custom_rule_documents = custom_rule_snapshot["rules"]
    selected_custom_ruleset_hash = custom_rule_snapshot["ruleset_hash"]
    custom_rule_interpreter_hash = custom_rule_snapshot["interpreter_hash"]
    run_key = build_detection_run_key(
        score.score_id,
        selected_allowlist_hash,
        selected_custom_ruleset_hash,
        custom_rule_interpreter_hash,
    )
    run_key = sha256_document({
        "legacy_run_key": run_key,
        "custom_rule_snapshot_hash": custom_rule_snapshot["snapshot_hash"],
    })
    evidence_bundle = None
    if scope and scope.evidence_contract:
        from porygon_api.runtime_evidence import (
            PROCESS_CONTEXT_CONTRACT,
            query_events,
            epoch_ns,
        )
        from porygon_api.models import RuntimeEvidenceBundle

        selected = score.observation_manifest["assessment_event_ids"]
        frozen_bundle = db.scalar(
            select(RuntimeEvidenceBundle).where(
                RuntimeEvidenceBundle.score_id == score.score_id
            )
        )
        if (
            frozen_bundle is None
            or frozen_bundle.rules_hash != scope.evidence_rules_hash
        ):
            raise HTTPException(409, "Frozen runtime evidence bundle unavailable")
        evidence_bundle = frozen_bundle.document
        raw_document = {
            key: value for key, value in evidence_bundle.items() if key != "bundle_hash"
        }
        if sha256_document(raw_document) != frozen_bundle.bundle_hash:
            raise HTTPException(409, "Runtime evidence bundle integrity mismatch")
        if scope.evidence_contract == PROCESS_CONTEXT_CONTRACT:
            frozen_context_ids = [
                item.get("event_id") for item in evidence_bundle.get("context_events", [])
            ]
            if frozen_context_ids != selected.get("context", []):
                raise HTTPException(409, "Frozen process context selection mismatch")
        run_key = sha256_document(
            {
                "legacy_run_key": run_key,
                "runtime_evidence_bundle_hash": evidence_bundle["bundle_hash"],
            }
        )
        if scope.evidence_contract == PROCESS_CONTEXT_CONTRACT:
            from porygon_api.runtime_evidence import query_context_events

            query_context_events(
                db,
                scope,
                score.window_start,
                score.window_end,
                [],
                context_ids=selected.get("context", []),
            )

    if db.get_bind().dialect.name == "postgresql":
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext(run_key))))
    existing = db.scalar(select(DetectionRun).where(DetectionRun.run_key == run_key))
    if existing is not None:
        return _detection_execution(db, existing)

    if evidence_bundle is not None:
        query_events(
            db,
            scope,
            score.window_start,
            score.window_end,
            process_ids=selected["process"],
            kernel_ids=selected.get("kernel", []),
        )
    profile = db.get(BehaviorProfile, score.profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The immutable profile referenced by the anomaly score no longer exists",
        )

    process_events = list(
        db.scalars(
            select(ProcessExecEvent)
            .where(
                *(scope.filters(ProcessExecEvent) if scope else ()),
                *(
                    (
                        ProcessExecEvent.event_id.in_(
                            score.observation_manifest["assessment_event_ids"][
                                "process"
                            ]
                        ),
                    )
                    if scope
                    else ()
                ),
                (
                    ProcessExecEvent.image_id == score.image_digest.removeprefix("local:")
                    if is_local_image_identity(score.image_digest)
                    else ProcessExecEvent.image_digest == score.image_digest
                ),
                ProcessExecEvent.correlation_status == "resolved",
                *(
                    (
                        ProcessExecEvent.time_nano >= epoch_ns(score.window_start),
                        ProcessExecEvent.time_nano < epoch_ns(score.window_end),
                    )
                    if scope and scope.evidence_contract
                    else (
                        ProcessExecEvent.occurred_at >= score.window_start,
                        ProcessExecEvent.occurred_at < score.window_end,
                    )
                ),
            )
            .order_by(ProcessExecEvent.occurred_at, ProcessExecEvent.event_id)
        ).all()
    )
    runtime_events = list(
        db.scalars(
            select(RuntimeEvent)
            .where(
                *(scope.filters(RuntimeEvent) if scope else ()),
                *(
                    (
                        RuntimeEvent.event_id.in_(
                            score.observation_manifest["assessment_event_ids"][
                                "runtime"
                            ]
                        ),
                    )
                    if scope
                    else ()
                ),
                (
                    RuntimeEvent.image_id == score.image_digest.removeprefix("local:")
                    if is_local_image_identity(score.image_digest)
                    else RuntimeEvent.image_digest == score.image_digest
                ),
                *(
                    (
                        RuntimeEvent.time_nano >= epoch_ns(score.window_start),
                        RuntimeEvent.time_nano < epoch_ns(score.window_end),
                    )
                    if scope and scope.evidence_contract
                    else (
                        RuntimeEvent.occurred_at >= score.window_start,
                        RuntimeEvent.occurred_at < score.window_end,
                    )
                ),
            )
            .order_by(RuntimeEvent.occurred_at, RuntimeEvent.event_id)
        ).all()
    )
    kernel_events = []
    if scope:
        selected = score.observation_manifest["assessment_event_ids"]
        kernel_events = list(db.scalars(
            select(KernelRuntimeEvent).where(
                *scope.filters(KernelRuntimeEvent),
                KernelRuntimeEvent.event_id.in_(selected.get("kernel", [])),
                (
                    KernelRuntimeEvent.image_id == score.image_digest.removeprefix("local:")
                    if is_local_image_identity(score.image_digest)
                    else KernelRuntimeEvent.image_digest == score.image_digest
                ),
                KernelRuntimeEvent.correlation_status == "resolved",
                *(
                    (
                        KernelRuntimeEvent.time_nano >= epoch_ns(score.window_start),
                        KernelRuntimeEvent.time_nano < epoch_ns(score.window_end),
                    ) if scope.evidence_contract else (
                        KernelRuntimeEvent.occurred_at >= score.window_start,
                        KernelRuntimeEvent.occurred_at < score.window_end,
                    )
                ),
            ).order_by(KernelRuntimeEvent.time_nano, KernelRuntimeEvent.event_id)
        ).all())

    if scope:
        selected = score.observation_manifest["assessment_event_ids"]
        if (len(process_events) != len(selected["process"])
            or len(runtime_events) != len(selected["runtime"])
            or len(kernel_events) != len(selected.get("kernel", []))):
            raise HTTPException(409, "Selected scoped evidence is no longer available")
    process_events = utc_events(process_events)
    runtime_events = utc_events(runtime_events)
    result = evaluate_detection(
        anomaly_score=score,
        profile=profile,
        process_events=process_events,
        runtime_events=runtime_events,
        allowlists=active_allowlists,
        custom_rules=custom_rule_documents,
        kernel_events=kernel_events,
    )
    if evidence_bundle is not None:
        from porygon_api.runtime_evidence import detection_matches

        additional = detection_matches(evidence_bundle)
        advisory = frozen_bundle.model_prediction
        if additional:
            result = dict(
                result,
                matches=[*result["matches"], *additional],
                incident_eligible=True,
                status="incident_created",
                severity_score=max(
                    result["severity_score"]
                    if result["severity_score"] is not None
                    else 0.0,
                    max(x["severity_weight"] for x in additional),
                ),
                confidence_score=max(result["confidence_score"], 0.9),
                confidence_level="high",
            )
            severity = result["severity_score"]
            result["severity_level"] = "critical" if severity >= 0.85 else "high"
            result["summary"] = (
                "Observed attributable runtime evidence; process-distance availability is recorded separately."
            )
        result = dict(
            result,
            runtime_evidence={
                "contract": evidence_bundle["contract"],
                "bundle_hash": evidence_bundle["bundle_hash"],
                "rules_hash": frozen_bundle.rules_hash,
                "model": advisory,
                "coverage": evidence_bundle["coverage"],
            },
        )
    if kernel_events:
        result = dict(result, kernel_evidence=[
            {
                "event_id": row.event_id,
                "docker_host_id": row.docker_host_id,
                "container_id": row.container_id,
                "sensor_instance_id": row.sensor_instance_id,
                "sensor_epoch": row.sensor_epoch,
                "pid_namespace_start_ns": row.pid_namespace_start_ns,
                "process_pid": row.process_pid,
                "process_start_ns": row.process_start_ns,
                "time_nano": row.time_nano,
            }
            for row in kernel_events
        ])
    run = DetectionRun(
        run_id=str(uuid4()),
        run_key=run_key,
        score_id=score.score_id,
        ruleset_version=RULESET_VERSION,
        ruleset_hash=ruleset_hash(),
        allowlist_set_hash=selected_allowlist_hash,
        custom_ruleset_hash=selected_custom_ruleset_hash,
        custom_rule_snapshot=custom_rule_snapshot,
        custom_rule_interpreter_hash=custom_rule_interpreter_hash,
        applied_allowlist_ids=[item.allowlist_id for item in active_allowlists],
        image_digest=score.image_digest,
        window_start=score.window_start,
        window_end=score.window_end,
        status=result["status"],
        matches_count=len(result["matches"]),
        incident_created=bool(result["incident_eligible"]),
        result=result,
        created_at=now,
    )
    db.add(run)

    incident, timeline = attach_incident(
        db, run, score, result, process_events, runtime_events, now
    )

    try:
        if commit:
            db.commit()
            db.refresh(run)
            if incident is not None:
                db.refresh(incident)
        else:
            db.flush()
        return {"run": run, "incident": incident, "timeline": timeline}
    except IntegrityError as exc:
        if not commit:
            raise
        db.rollback()
        existing = db.scalar(
            select(DetectionRun).where(DetectionRun.run_key == run_key)
        )
        if existing is not None:
            return _detection_execution(db, existing)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A concurrent detection request created a conflicting run",
        ) from exc
    except SQLAlchemyError as exc:
        if not commit:
            raise
        db.rollback()
        logger.exception("Detection persistence failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection persistence failed",
        ) from exc
