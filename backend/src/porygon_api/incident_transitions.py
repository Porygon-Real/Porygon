"""Row-locked incident workflow transitions and their ordered audit evidence."""
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from porygon_api.models import Incident, IncidentEvidence
from porygon_api.principals import Principal

ACTIVE_STATUSES = ("open", "acknowledged")
TRANSITIONS = {
    "open": {"acknowledged", "resolved", "dismissed"},
    "acknowledged": {"resolved", "dismissed"},
    "resolved": set(),
    "dismissed": set(),
}


def transition_incident(
    db: Session, incident_id: str, *, target_status: str,
    principal: Principal, note: str | None = None,
) -> Incident:
    """Apply one transition in the caller's transaction; repeated status is a no-op."""
    incident = db.scalar(
        select(Incident).where(Incident.incident_id == incident_id)
        .with_for_update().execution_options(populate_existing=True)
    )
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if incident.status == target_status:
        return incident
    if target_status not in TRANSITIONS.get(incident.status, set()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Incident cannot transition from {incident.status} to {target_status}",
        )
    now = datetime.now(timezone.utc)
    previous_status = incident.status
    incident.status = target_status
    incident.updated_at = now
    if target_status == "acknowledged":
        incident.acknowledged_at = now
        incident.acknowledged_by = principal.subject
    else:
        incident.closed_at = now
        incident.closed_by = principal.subject
        incident.closure_note = note
    sequence = (db.scalar(
        select(func.coalesce(func.max(IncidentEvidence.sequence_no), 0))
        .where(IncidentEvidence.incident_id == incident_id)
    ) or 0) + 1
    db.add(IncidentEvidence(
        evidence_id=str(uuid4()), incident_id=incident_id, sequence_no=sequence,
        occurred_at=now, source_type="incident_status", source_id=incident_id,
        rule_id=None, evidence_type="status_change",
        summary=f"Incident status changed to {target_status} by {principal.subject}.",
        details={"previous_status": previous_status, "status": target_status,
                 "actor": principal.subject, "principal_kind": principal.kind, "note": note},
        created_at=now,
    ))
    db.flush()
    return incident


def resolve_incident_batch(
    db: Session, *, principal: Principal, limit: int = 100,
    note: str = "Resolved by operator bulk action",
) -> tuple[int, bool]:
    """Resolve one bounded active batch; caller commits all transitions atomically."""
    if not 1 <= limit <= 500:
        raise ValueError("Incident batch limit must be between 1 and 500")
    # Consistent lock order avoids cross-batch deadlocks. Locked rows belong to
    # other transitions and remain eligible for a later explicit batch request.
    incidents = list(db.scalars(
        select(Incident).where(Incident.status.in_(ACTIVE_STATUSES))
        .order_by(Incident.incident_id).limit(limit).with_for_update(skip_locked=True)
        .execution_options(populate_existing=True)
    ).all())
    for incident in incidents:
        transition_incident(db, incident.incident_id, target_status="resolved",
                            principal=principal, note=note)
    more_pending = db.scalar(
        select(Incident.incident_id).where(Incident.status.in_(ACTIVE_STATUSES)).limit(1)
    ) is not None
    return len(incidents), more_pending
