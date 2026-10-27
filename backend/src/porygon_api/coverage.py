"""Coverage evidence is operational context, never a completeness guarantee."""

from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from porygon_api.models import ContainerIdentity, ServiceHeartbeat
from porygon_api.vulnerability import sha256_document
from porygon_api.auth import utc


def security_context(snapshot):
    """Whitelist normalized collector fields; absent configuration is unknown."""
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    host = snapshot.get("host_config")
    host = host if isinstance(host, dict) else {}
    config = snapshot.get("config")
    config = config if isinstance(config, dict) else {}
    result = {}
    for key in ("privileged", "readonly_rootfs"):
        result[key] = host.get(key) if isinstance(host.get(key), bool) else None
    for key in ("network_mode", "pid_mode", "ipc_mode", "uts_mode", "userns_mode"):
        result[key] = host.get(key) if isinstance(host.get(key), str) else None
    for key in ("cap_add", "cap_drop", "security_opt"):
        value = host.get(key)
        result[key] = (
            sorted(value)
            if isinstance(value, list) and all(isinstance(x, str) for x in value)
            else None
        )
    result["user"] = config.get("user") if isinstance(config.get("user"), str) else None
    mounts = snapshot.get("mounts")
    result["mounts"] = None
    if isinstance(mounts, list) and all(isinstance(x, dict) for x in mounts):
        result["mounts"] = sorted(
            [
                {
                    key: mount.get(key) if isinstance(mount.get(key), str) else None
                    for key in ("type", "source", "destination")
                }
                | {"rw": mount.get("rw") if isinstance(mount.get("rw"), bool) else None}
                for mount in mounts
            ],
            key=lambda row: str(row["destination"]),
        )
    return result


def target_identity(db, target):
    return db.scalar(
        select(ContainerIdentity).where(
            ContainerIdentity.docker_host_id == target.docker_host_id,
            ContainerIdentity.container_id == target.container_id,
        )
    )


def coverage_for(db, target, window_start, settings, now=None):
    now = now or datetime.now(timezone.utc)
    reasons = []
    if any(value is None for value in target.context_manifest.values()):
        reasons.append("security_context_unknown")
    identity = target_identity(db, target)
    if (
        identity is None
        or identity.image_digest != target.image_digest
        or sha256_document(security_context(identity.current_snapshot))
        != target.context_hash
    ):
        reasons.append("identity_changed")
    if utc(window_start) < now - timedelta(days=settings.raw_event_retention_days):
        reasons.append("retention_unavailable")
    for service in ("collector", "telemetry"):
        records = db.scalars(
            select(ServiceHeartbeat).where(
                ServiceHeartbeat.service_name == service,
                ServiceHeartbeat.last_seen_at
                >= now
                - timedelta(seconds=settings.assessment_heartbeat_max_age_seconds),
            )
        ).all()
        if not any(
            row.service_metadata.get("docker_host_id") == target.docker_host_id
            and row.status == "healthy"
            for row in records
        ):
            reasons.append(service + "_heartbeat_stale")
    from porygon_api.health_metrics import health_coverage
    health=health_coverage(db,target.docker_host_id,utc(window_start),utc(window_start)+timedelta(seconds=target.window_seconds))
    reasons.extend(health['reasons'])
    state = (
        "unavailable"
        if "retention_unavailable" in reasons
        else "unprofiled"
        if "identity_changed" in reasons
        else "degraded"
    )
    return {
        "state": state,
        "reasons": reasons,
        "source_drop_coverage": health["source_loss"],
        "health_boundaries":health["boundaries"],
        "completeness": "unknown",
        "allowed_lateness_seconds": target.allowed_lateness_seconds,
    }
