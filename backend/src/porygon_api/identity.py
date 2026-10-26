"""Shared exact-host, unambiguous-prefix identity resolution."""

from sqlalchemy import select, or_, desc
from sqlalchemy.orm import Session
from porygon_api.models import ContainerIdentity


def resolve_container_identity(
    db: Session,
    reported_container_id: str | None,
    reported_docker_host_id: str | None,
) -> tuple[str, ContainerIdentity | None]:
    if not reported_container_id or reported_container_id == "host":
        return "unresolved", None

    statement = select(ContainerIdentity).where(
        or_(
            ContainerIdentity.container_id == reported_container_id,
            ContainerIdentity.container_id.startswith(reported_container_id, autoescape=True),
        )
    )
    if reported_docker_host_id:
        statement = statement.where(ContainerIdentity.docker_host_id == reported_docker_host_id)

    candidates = list(db.scalars(statement.order_by(desc(ContainerIdentity.last_seen_at)).limit(2)))
    if len(candidates) == 1:
        return "resolved", candidates[0]
    if len(candidates) > 1:
        return "ambiguous", None
    return "unresolved", None
