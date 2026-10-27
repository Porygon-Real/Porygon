"""Host and purpose bindings reject impersonation before handlers write."""

import pytest
from fastapi import HTTPException
from porygon_api.auth import bind_service_payload
from porygon_api.principals import Principal
from test_credentials import (
    settings as settings,
    database_override as database_override,
    engine as engine,
    enroll,
    post,
    TOKEN,
)


@pytest.mark.parametrize(
    "payload",
    [
        {"events": [{"docker_host_id": "host-b"}]},
        {"events": [{"docker_host_id": "host-a"}, {"docker_host_id": "host-b"}]},
    ],
)
def test_host_spoof_is_rejected_before_invalid_payload_reaches_handler(
    settings, database_override, payload
):
    assert (
        enroll(
            kind="service",
            roles=[],
            subject="service:collector",
            service_name="collector",
            instance_id="collector-a",
            host_ids=["host-a"],
            scopes=["ingest_runtime"],
        )[0]
        == 201
    )
    assert (
        post("/internal/v1/events/batch", payload, {"X-Porygon-Internal-Token": TOKEN})[
            0
        ]
        == 403
    )


@pytest.mark.parametrize(
    "service,scopes", [("scanner", ["ingest_runtime"]), ("collector", ["scan_worker"])]
)
def test_mixed_purpose_enrollment_rejected(
    settings, database_override, service, scopes
):
    assert (
        enroll(
            kind="service",
            roles=[],
            subject="service:worker",
            service_name=service,
            instance_id="worker",
            host_ids=["host-a"],
            scopes=scopes,
        )[0]
        == 422
    )


def test_binding_fills_only_enrolled_host_and_rejects_heartbeat_instance():
    worker = Principal(
        "sensor",
        "service",
        host_ids=("host-a",),
        service_name="telemetry",
        instance_id="sensor-a",
    )
    event = {
        "events": [
            {"reported_docker_host_id": "auto", "sensor_instance_id": "sensor-a"}
        ]
    }
    assert (
        bind_service_payload(worker, "ingest_process", event)["events"][0][
            "reported_docker_host_id"
        ]
        == "host-a"
    )
    with pytest.raises(HTTPException) as denied:
        bind_service_payload(
            worker,
            "heartbeat",
            {"instance_id": "sensor-b", "service_name": "telemetry"},
        )
    assert denied.value.status_code == 403


@pytest.mark.parametrize("status", ["claimed", "rollback_claimed"])
def test_expired_claim_requeue_is_host_scoped(settings, database_override, status):
    from datetime import datetime, timedelta, timezone
    from sqlalchemy.orm import Session
    from porygon_api.models import ResponseExecution
    from test_incident_transitions import seed
    from test_incident_grouping import recommendation

    assert (
        enroll(
            kind="service",
            roles=[],
            subject="service:responder",
            service_name="responder",
            instance_id="responder-a",
            host_ids=["host-a"],
            scopes=["response_worker"],
        )[0]
        == 201
    )
    expired = datetime.now(timezone.utc) - timedelta(minutes=5)
    with Session(database_override) as db:
        incident_id = seed(db)[0]
        proposal = recommendation(db, incident_id, None)
        db.add(
            ResponseExecution(
                execution_id="foreign",
                recommendation_id=proposal.recommendation_id,
                incident_id=incident_id,
                target_container_id="a" * 64,
                target_docker_host_id="host-b",
                action_type="observe_only",
                status=status,
                idempotency_key="k" * 64,
                executor_instance_id="responder-b",
                lease_expires_at=expired,
                created_at=expired,
            )
        )
        db.commit()
    code, body = post(
        "/internal/v1/response-executions/claim",
        {"executor_instance_id": "responder-a"},
        {"X-Porygon-Internal-Token": TOKEN},
    )
    assert code == 200 and body["execution"] is None
    with Session(database_override) as db:
        row = db.get(ResponseExecution, "foreign")
        assert row.status == status and row.executor_instance_id == "responder-b"
        assert row.lease_expires_at is not None


@pytest.mark.parametrize(
    "operation,payload",
    [
        ("renew", {"scanner_instance_id": "scanner-a", "lease_seconds": 60}),
        (
            "fail",
            {
                "scanner_instance_id": "scanner-a",
                "error_code": "scanner_error",
                "error_message": "failed",
            },
        ),
    ],
)
def test_scanner_cannot_mutate_another_hosts_claim(
    settings, database_override, operation, payload
):
    from datetime import datetime, timezone
    from sqlalchemy.orm import Session
    from porygon_api.models import ImageScan

    assert (
        enroll(
            kind="service",
            roles=[],
            subject="service:scanner",
            service_name="scanner",
            instance_id="scanner-a",
            host_ids=["host-a"],
            scopes=["scan_worker"],
        )[0]
        == 201
    )
    with Session(database_override) as db:
        db.add(
            ImageScan(
                scan_id="foreign",
                scan_key="s" * 64,
                image_digest="example@sha256:" + "a" * 64,
                image_id="sha256:" + "a" * 64,
                docker_host_id="host-b",
                scanner_name="trivy",
                scanner_version="test",
                scan_reference="example",
                status="claimed",
                requested_by="operator",
                scanner_instance_id="scanner-b",
                created_at=datetime.now(timezone.utc),
            )
        )
        db.commit()
    assert (
        post(
            "/internal/v1/image-scans/foreign/" + operation,
            payload,
            {"X-Porygon-Internal-Token": TOKEN},
        )[0]
        == 403
    )
    with Session(database_override) as db:
        row = db.get(ImageScan, "foreign")
        assert row.status == "claimed" and row.scanner_instance_id == "scanner-b"
        assert row.lease_expires_at is None and row.error_code is None


def test_recommendation_host_is_frozen_and_duplicate_inventory_refused(
    settings, database_override
):
    from datetime import datetime, timezone
    from sqlalchemy.orm import Session
    from porygon_api import main
    from porygon_api.models import ContainerIdentity
    from porygon_api.principals import CURRENT_PRINCIPAL
    from porygon_api.schemas import ResponseRecommendationApproveIn
    from test_incident_transitions import seed
    from test_incident_grouping import CID

    ctx = CURRENT_PRINCIPAL.set(Principal("human:anurup", "operator", roles=("admin",)))
    try:
        with Session(database_override) as db:
            incident_id = seed(db)[0]
            now = datetime.now(timezone.utc)
            identity = ContainerIdentity(
                docker_host_id="host-a",
                container_id=CID,
                image_digest_status="resolved",
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(identity)
            db.commit()
            proposal = main.generate_response_recommendations(incident_id, db)[
                "recommendations"
            ][0]
            assert proposal.target_docker_host_id == "host-a"
            identity.docker_host_id = "host-b"
            db.commit()
            execution = main.approve_response_recommendation(
                proposal.recommendation_id,
                ResponseRecommendationApproveIn(
                    actor="forged", note="reviewed", action_type="observe_only"
                ),
                db,
            )
            assert execution.target_docker_host_id == "host-a"
            assert proposal.decided_by == "human:anurup"
            db.add(
                ContainerIdentity(
                    docker_host_id="host-a",
                    container_id=CID,
                    image_digest_status="resolved",
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            db.commit()
            with pytest.raises(HTTPException) as error:
                main.generate_response_recommendations(incident_id, db)
            assert error.value.status_code == 409
    finally:
        CURRENT_PRINCIPAL.reset(ctx)


@pytest.mark.parametrize(
    "binding,owner",
    [("host-b", "responder-a"), ("host-a", "responder-b"), (None, "responder-a")],
)
def test_response_completion_wrong_host_or_owner_is_write_free(
    settings, database_override, binding, owner
):
    from datetime import datetime, timezone
    from sqlalchemy.orm import Session
    from porygon_api.models import ResponseExecution
    from test_incident_transitions import seed
    from test_incident_grouping import recommendation

    assert (
        enroll(
            kind="service",
            roles=[],
            subject="service:responder",
            service_name="responder",
            instance_id="responder-a",
            host_ids=["host-a"],
            scopes=["response_worker"],
        )[0]
        == 201
    )
    with Session(database_override) as db:
        incident_id = seed(db)[0]
        proposal = recommendation(db, incident_id, None)
        db.add(
            ResponseExecution(
                execution_id="foreign",
                recommendation_id=proposal.recommendation_id,
                incident_id=incident_id,
                target_container_id="a" * 64,
                target_docker_host_id=binding,
                action_type="observe_only",
                status="claimed",
                idempotency_key="k" * 64,
                executor_instance_id=owner,
                created_at=datetime.now(timezone.utc),
            )
        )
        db.commit()
    assert (
        post(
            "/internal/v1/response-executions/foreign/complete",
            {"executor_instance_id": "responder-a", "success": True},
            {"X-Porygon-Internal-Token": TOKEN},
        )[0]
        == 403
    )
    with Session(database_override) as db:
        row = db.get(ResponseExecution, "foreign")
        assert row.status == "claimed" and row.executor_instance_id == owner
        assert row.completed_at is None and row.result == {}
