"""Typed non-exec evidence, deliberately isolated from historical exec features."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from porygon_api.db import get_db
from porygon_api.identity import resolve_container_identity
from porygon_api.models import ContainerIdentity, KernelRuntimeEvent
from porygon_api.schemas import KernelRuntimeBatchIn, KernelRuntimeEventOut
from porygon_api.security import require_internal_token, require_operator_token

router = APIRouter(tags=["kernel-runtime"])


def reconcile_kernel_identities(db: Session, limit: int = 500) -> int:
    matching = (
        select(func.count())
        .select_from(ContainerIdentity)
        .where(
            ContainerIdentity.container_id.startswith(KernelRuntimeEvent.reported_container_id),
            or_(
                KernelRuntimeEvent.reported_docker_host_id.is_(None),
                ContainerIdentity.docker_host_id == KernelRuntimeEvent.reported_docker_host_id,
            ),
        )
        .correlate(KernelRuntimeEvent)
        .scalar_subquery()
    )
    digest = (
        select(func.max(ContainerIdentity.image_digest))
        .where(
            ContainerIdentity.container_id.startswith(KernelRuntimeEvent.reported_container_id),
            or_(
                KernelRuntimeEvent.reported_docker_host_id.is_(None),
                ContainerIdentity.docker_host_id == KernelRuntimeEvent.reported_docker_host_id,
            ),
        )
        .correlate(KernelRuntimeEvent)
        .scalar_subquery()
    )
    rows = db.scalars(
        select(KernelRuntimeEvent)
        .where(
            matching == 1,
            or_(
                KernelRuntimeEvent.correlation_status != "resolved",
                KernelRuntimeEvent.image_digest.is_(None) & digest.is_not(None),
            ),
        )
        .order_by(KernelRuntimeEvent.received_at, KernelRuntimeEvent.event_id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    ).all()
    count = 0
    for row in rows:
        status, identity = resolve_container_identity(
            db, row.reported_container_id, row.reported_docker_host_id
        )
        if identity is not None and status == "resolved":
            for field in (
                "docker_host_id",
                "container_id",
                "container_name",
                "image_id",
                "image_ref",
                "image_digest",
            ):
                setattr(row, field, getattr(identity, field))
            row.correlation_status = "resolved"
            count += 1
    return count


@router.post("/internal/v1/kernel-events/batch", dependencies=[Depends(require_internal_token)])
def ingest_kernel_events(
    payload: KernelRuntimeBatchIn, request: Request, db: Session = Depends(get_db)
):
    inserted = 0
    statuses = {"resolved": 0, "unresolved": 0, "ambiguous": 0}
    now = datetime.now(timezone.utc)
    try:
        for event in payload.events:
            status, identity = resolve_container_identity(
                db, event.reported_container_id, event.reported_docker_host_id
            )
            values = event.model_dump()
            values["occurred_at"] = event.occurred_at.astimezone(timezone.utc)
            values.update(received_at=now, correlation_status=status)
            for field in (
                "docker_host_id",
                "container_id",
                "container_name",
                "image_id",
                "image_ref",
                "image_digest",
            ):
                values[field] = getattr(identity, field) if identity is not None else None
            if identity is None:
                values["docker_host_id"] = event.reported_docker_host_id
            result = db.execute(
                pg_insert(KernelRuntimeEvent)
                .values(**values)
                .on_conflict_do_nothing(index_elements=["event_id"])
                .returning(KernelRuntimeEvent.event_id)
            )
            inserted += int(result.scalar_one_or_none() is not None)
            statuses[status] += 1
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Kernel event persistence failed") from exc
    worker = getattr(request.app.state, "identity_reconciliation", None)
    if worker is not None:
        worker.notify()
    return dict(
        received=len(payload.events),
        inserted=inserted,
        duplicates=len(payload.events) - inserted,
        **statuses,
    )


@router.get("/api/v1/kernel-events", response_model=list[KernelRuntimeEventOut])
def list_kernel_events(
    runtime_action: str | None = Query(default=None, max_length=32),
    container_id: str | None = Query(default=None, max_length=128),
    docker_host_id: str | None = Query(default=None, max_length=128),
    image_digest: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    statement = select(KernelRuntimeEvent)
    for field, value in (
        ("runtime_action", runtime_action),
        ("container_id", container_id),
        ("docker_host_id", docker_host_id),
        ("image_digest", image_digest),
    ):
        if value is not None:
            statement = statement.where(getattr(KernelRuntimeEvent, field) == value)
    return list(
        db.scalars(
            statement.order_by(
                desc(KernelRuntimeEvent.time_nano), KernelRuntimeEvent.event_id
            ).limit(limit)
        ).all()
    )


@router.get("/api/v1/kernel-events/summary")
def kernel_summary(db: Session = Depends(get_db)):
    rows = db.execute(
        select(KernelRuntimeEvent.runtime_action, func.count()).group_by(
            KernelRuntimeEvent.runtime_action
        )
    ).all()
    resolved = (
        db.scalar(
            select(func.count())
            .select_from(KernelRuntimeEvent)
            .where(KernelRuntimeEvent.correlation_status == "resolved")
        )
        or 0
    )
    return dict(
        total_events=sum(count for _, count in rows),
        resolved_events=resolved,
        by_action={kind: count for kind, count in rows},
    )


@router.post("/operator/v1/kernel-events/reconcile", dependencies=[Depends(require_operator_token)])
def reconcile_kernel_events(db: Session = Depends(get_db)):
    count = reconcile_kernel_identities(db)
    db.commit()
    return {"repaired": count}


@router.get("/api/v1/kernel-events/{event_id}", response_model=KernelRuntimeEventOut)
def get_kernel_event(event_id: str, db: Session = Depends(get_db)):
    event = db.get(KernelRuntimeEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Kernel runtime event not found")
    return event
