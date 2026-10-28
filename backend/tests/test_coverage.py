"""Security context changes matter; transient state and secrets never do."""

from copy import deepcopy
from test_assessment_service import (
    engine as engine,
    assessment_engine as assessment_engine,
)
from porygon_api.coverage import security_context
from porygon_api.vulnerability import sha256_document


def test_normalized_collector_snapshot_context_is_stable_and_secret_free():
    source = {
        "config": {
            "user": "1000",
            "env": ["TOKEN=private"],
            "labels": {"secret": "private"},
        },
        "host_config": {
            "privileged": False,
            "readonly_rootfs": True,
            "cap_add": ["NET_ADMIN"],
        },
        "state": {"pid": 123},
        "container": {"restart_count": 0},
        "networks": {"ip": "1.2.3.4"},
    }
    context = security_context(source)
    changed = deepcopy(source)
    changed["state"]["pid"] = 999
    changed["container"]["restart_count"] = 10
    assert security_context(changed) == context
    assert "private" not in str(context)
    for key, value in [
        ("privileged", True),
        ("readonly_rootfs", False),
        ("cap_add", ["SYS_ADMIN"]),
    ]:
        changed = deepcopy(source)
        changed["host_config"][key] = value
        assert sha256_document(security_context(changed)) != sha256_document(context)
    changed = deepcopy(source)
    changed["config"]["user"] = "0"
    assert security_context(changed) != context
    assert security_context({})["privileged"] is None


def test_malformed_security_snapshot_is_unknown():
    for snapshot in [
        {"config": [], "host_config": "invalid"},
        {
            "config": {"user": []},
            "host_config": {"privileged": "false", "cap_add": [{}]},
        },
    ]:
        context = security_context(snapshot)
        assert context["privileged"] is None and context["user"] is None


def test_real_schema_healthy_heartbeats_clear_stale_reasons(assessment_engine):
    from datetime import datetime, timezone
    from sqlalchemy.orm import Session
    from porygon_api.models import ServiceHeartbeat, AssessmentTarget
    from porygon_api.config import get_settings
    from porygon_api.coverage import coverage_for
    from porygon_api.schemas import HeartbeatIn
    from test_assessment_service import setup_target, START

    current = datetime.now(timezone.utc)
    with Session(assessment_engine) as db:
        target_id, _ = setup_target(db)
        for name in ["collector", "telemetry"]:
            value = HeartbeatIn(
                service_name=name,
                instance_id=name,
                status="healthy",
                observed_at=current,
                metadata={"docker_host_id": "host-a"},
            )
            db.add(
                ServiceHeartbeat(
                    docker_host_id="host-a",
                    service_name=value.service_name,
                    instance_id=value.instance_id,
                    status=value.status,
                    service_metadata=value.metadata,
                    first_seen_at=current,
                    last_seen_at=current,
                )
            )
        db.commit()
        result = coverage_for(
            db, db.get(AssessmentTarget, target_id), START, get_settings(), current
        )
        assert not any("heartbeat_stale" in reason for reason in result["reasons"])
        assert result["completeness"] == "unknown"
