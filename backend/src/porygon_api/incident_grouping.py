"""Group active incident episodes without pooling different workload identities."""

from __future__ import annotations

import re
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import func, select
from porygon_api.models import (
    DetectionIncidentLink,
    DetectionRun,
    Incident,
    IncidentEvidence,
)


def utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


CID_HEX = re.compile(r"^[0-9a-fA-F]{12,64}$")


def grouping_key(score, container_ids, process_events, runtime_events, configuration=None):
    if not container_ids or any(
        not isinstance(cid, str) or not CID_HEX.match(cid) for cid in container_ids
    ):
        return None
    scope = set()
    for cid in container_ids:
        matching = [
            event
            for event in [*process_events, *runtime_events]
            if getattr(event, "container_id", None) == cid
        ]
        if not matching:
            return None
        hosts = {
            event.docker_host_id for event in matching if getattr(event, "docker_host_id", None)
        }
        if len(hosts) > 1:
            return None
        host = next(iter(hosts)) if hosts else "local"
        scope.add((host, cid.lower()))
    # Different profiles and detection configurations retain separate episodes.
    document = [score.image_digest, score.profile_id, sorted(scope), configuration]
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()


def attach_incident(db, run, score, result, process_events, runtime_events, now):
    incident: Incident | None = None
    timeline: list[IncidentEvidence] = []
    if result["incident_eligible"]:
        matches = list(result["matches"])
        incident_matches = [item for item in matches if item["incident_eligible"]]
        times = [datetime.fromisoformat(item["occurred_at"]) for item in matches]
        container_ids = sorted({item["container_id"] for item in matches if item["container_id"]})
        leading = max(
            incident_matches,
            key=lambda item: (
                item["severity_weight"],
                item["confidence_weight"],
                item["rule_id"],
            ),
        )
        key = grouping_key(
            score,
            container_ids,
            process_events,
            runtime_events,
            [run.ruleset_hash, run.allowlist_set_hash, run.custom_ruleset_hash]
            + ([result["runtime_evidence"]["rules_hash"],result["runtime_evidence"]["model"].get("artifact_sha256")] if result.get("runtime_evidence") else []),
        )
        if key is not None:
            if db.get_bind().dialect.name == "postgresql":
                db.execute(select(func.pg_advisory_xact_lock(func.hashtext(key))))
            incident = db.scalar(
                select(Incident)
                .where(
                    Incident.grouping_key == key,
                    Incident.status.in_(["open", "acknowledged"]),
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        previous_severity=incident.severity_level if incident is not None else None
        created = incident is None
        if created:
            incident = Incident(
                incident_id=str(uuid4()),
                grouping_key=key,
                latest_detection_run_id=run.run_id,
                detection_run_id=run.run_id,
                score_id=score.score_id,
                image_digest=score.image_digest,
                title=f"{leading['name']} in {score.image_digest.split('@', 1)[0]}",
                status="open",
                anomaly_score=float(result["anomaly_score"]) if result["anomaly_score"] is not None else None,
                severity_score=float(result["severity_score"]),
                severity_level=str(result["severity_level"]),
                confidence_score=float(result["confidence_score"]),
                confidence_level=str(result["confidence_level"]),
                summary=str(result["summary"]),
                findings=matches,
                container_ids=container_ids,
                first_seen_at=min(times) if times else score.window_start,
                last_seen_at=max(times) if times else score.window_end,
                created_at=now,
                updated_at=now,
                acknowledged_at=None,
                acknowledged_by=None,
                closed_at=None,
                closed_by=None,
                closure_note=None,
            )
            db.add(incident)
        else:
            latest = db.get(
                DetectionRun,
                incident.latest_detection_run_id or incident.detection_run_id,
            )
            if latest is None or utc(score.window_end) >= utc(latest.window_end):
                # Keep one coherent window's assessment; do not combine unrelated
                # peak severity/confidence values into a stronger response policy.
                incident.latest_detection_run_id = run.run_id
                incident.score_id = score.score_id
                incident.anomaly_score = float(result["anomaly_score"]) if result["anomaly_score"] is not None else None
                incident.severity_score = float(result["severity_score"])
                incident.severity_level = str(result["severity_level"])
                incident.confidence_score = float(result["confidence_score"])
                incident.confidence_level = str(result["confidence_level"])
                incident.findings = matches
                incident.summary = str(result["summary"])
            incident.first_seen_at = min(utc(incident.first_seen_at), *map(utc, times))
            incident.last_seen_at = max(utc(incident.last_seen_at), *map(utc, times))
            incident.updated_at = now
            run.status = "incident_updated"
            run.incident_created = False
            run.result = {
                **result,
                "status": "incident_updated",
                "incident_grouped": True,
            }
        db.flush()
        db.add(DetectionIncidentLink(detection_run_id=run.run_id, incident_id=incident.incident_id))

        evidence_documents = [
            {
                "occurred_at": score.window_end,
                "source_type": "anomaly_score",
                "source_id": score.score_id,
                "rule_id": None,
                "evidence_type": "behavioural_distance",
                "summary": (
                    f"Observed behavioural distance was {score.total_score:.3f} ({score.score_band})." if score.total_score is not None else
                    "Process distance is unavailable for this evidence-backed incident."
                ),
                "details": {
                    "algorithm_version": score.algorithm_version,
                    "profile_id": score.profile_id,
                    "profile_version": score.profile_version,
                    "total_score": score.total_score,
                    "score_band": score.score_band,
                },
            }
        ]
        evidence_documents.extend(
            {
                "occurred_at": datetime.fromisoformat(item["occurred_at"]),
                "source_type": item["source_type"],
                "source_id": item["source_id"],
                "rule_id": item["rule_id"],
                "evidence_type": item["category"],
                "summary": item["summary"],
                "details": item["details"],
            }
            for item in matches
        )
        evidence_documents.sort(
            key=lambda item: (
                item["occurred_at"],
                item["source_type"],
                item["source_id"],
            )
        )
        next_sequence = (
            db.scalar(
                select(func.coalesce(func.max(IncidentEvidence.sequence_no), 0)).where(
                    IncidentEvidence.incident_id == incident.incident_id
                )
            )
            or 0
        ) + 1
        for sequence_no, item in enumerate(evidence_documents, start=next_sequence):
            evidence = IncidentEvidence(
                evidence_id=str(uuid4()),
                incident_id=incident.incident_id,
                sequence_no=sequence_no,
                occurred_at=item["occurred_at"],
                source_type=item["source_type"],
                source_id=item["source_id"],
                rule_id=item["rule_id"],
                evidence_type=item["evidence_type"],
                summary=item["summary"],
                details={**item["details"], "detection_run_id": run.run_id},
                created_at=now,
            )
            db.add(evidence)
            timeline.append(evidence)

    if incident is not None:
        from porygon_api.notifications import enqueue_transition
        enqueue_transition(db,incident,previous_severity)
    return incident, timeline
