"""Exercise enrolled authentication through the real ASGI boundary."""

from datetime import datetime, timedelta, timezone
import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from porygon_api.models import ApiCredential
from porygon_api.auth import token_digest
from test_auth_permissions import (
    settings as settings,
    database_override as database_override,
    engine as engine,
    post,
)

ADMIN = {"X-Porygon-Operator-Token": "o" * 32}
TOKEN = "enrolled_" + "x" * 43


def enroll(token=TOKEN, **values):
    return post(
        "/operator/v1/credentials",
        {
            "subject": "human:anurup",
            "kind": "operator",
            "roles": ["admin"],
            "token": token,
            **values,
        },
        ADMIN,
    )


def test_registry_hash_only_and_revocation(settings, database_override):
    code, metadata = enroll()
    assert code == 201
    assert TOKEN not in json.dumps(metadata)
    with Session(database_override) as db:
        row = db.get(ApiCredential, metadata["credential_id"])
        assert row.token_sha256 == token_digest(TOKEN)
        assert TOKEN not in repr(row.__dict__)
    settings.access_mode = "authenticated"
    headers = {"Authorization": "Bearer " + TOKEN}
    code, _ = post(
        "/operator/v1/credentials/" + metadata["credential_id"] + "/revoke", {}, headers
    )
    assert code == 200
    assert post("/operator/v1/credentials", {}, headers)[0] == 401
    assert post("/operator/v1/credentials", {}, ADMIN)[0] == 401


@pytest.mark.parametrize("invalid", ["short-credential-secret", "!" * 45])
def test_validation_never_echoes_secret(settings, database_override, invalid):
    code, body = enroll(invalid)
    assert code == 422
    assert invalid not in json.dumps(body)
    assert all("input" not in item and "ctx" not in item for item in body["detail"])


def test_rotation_overlap_and_expiry(settings, database_override):
    code, initial = enroll()
    assert code == 201
    replacement = "replacement_" + "z" * 43
    code, metadata = post(
        "/operator/v1/credentials/" + initial["credential_id"] + "/rotate",
        {"token": replacement, "overlap_seconds": 60},
        ADMIN,
    )
    assert code == 200
    settings.access_mode = "authenticated"
    # Both tokens remain authenticated during the explicit overlap.
    for token in (TOKEN, replacement):
        assert (
            post("/operator/v1/credentials", {}, {"Authorization": "Bearer " + token})[
                0
            ]
            == 422
        )
    with Session(database_override) as db:
        db.get(ApiCredential, initial["credential_id"]).expires_at = datetime.now(
            timezone.utc
        ) - timedelta(seconds=1)
        db.commit()
    assert (
        post("/operator/v1/credentials", {}, {"Authorization": "Bearer " + TOKEN})[0]
        == 401
    )
    assert replacement not in json.dumps(metadata)


@pytest.mark.parametrize(
    "path",
    [
        "/operator/v1/incidents/clean-all",
        "/api/v1/ai/audit",
        "/internal/v1/image-scans/claim",
        "/internal/v1/response-executions/claim",
    ],
)
def test_ingestion_credential_cannot_cross_purpose(settings, database_override, path):
    code, _ = enroll(
        kind="service",
        roles=[],
        subject="service:collector",
        service_name="collector",
        instance_id="collector-a",
        host_ids=["host-a"],
        scopes=["ingest_runtime", "heartbeat"],
    )
    assert code == 201
    with Session(database_override) as db:
        count = len(db.scalars(select(ApiCredential)).all())
    assert post(path, {}, {"X-Porygon-Internal-Token": TOKEN})[0] == 403
    with Session(database_override) as db:
        assert len(db.scalars(select(ApiCredential)).all()) == count


@pytest.mark.parametrize("events", [None, 42, "invalid"])
def test_malformed_ingestion_is_validation_error(settings, database_override, events):
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
        post(
            "/internal/v1/events/batch",
            {"events": events},
            {"X-Porygon-Internal-Token": TOKEN},
        )[0]
        == 422
    )


def test_authenticated_reads_docs_and_unknown_routes_fail_closed(
    settings, database_override
):
    assert enroll(roles=["viewer"])[0] == 201
    settings.access_mode = "authenticated"
    for path in ["/api/v1/services", "/docs", "/openapi.json", "/api/v1/services/"]:
        assert post(path, {}, {}, method="GET")[0] == 401
        assert post(path, {}, ADMIN, method="GET")[0] == 401
    headers = {"Authorization": "Bearer " + TOKEN}
    assert post("/api/v1/services", {}, headers, method="GET")[0] == 200
    assert post("/openapi.json", {}, headers, method="GET")[0] == 200
    assert post("/api/v1/services", {}, headers, method="OPTIONS")[0] == 404
    assert post("/missing", {}, headers, method="GET")[0] == 404
    assert post("/health/live", {}, {}, method="GET")[0] == 200
    assert post("/operator/v1/incidents/clean-all", {}, headers)[0] == 403


def test_missing_registry_never_falls_back_to_anonymous(settings, monkeypatch):
    from sqlalchemy.exc import OperationalError
    from porygon_api import auth

    def unavailable(*args, **kwargs):
        raise OperationalError("unavailable", None, Exception("unavailable"))

    monkeypatch.setattr(auth, "credential_session", unavailable)
    settings.access_mode = "authenticated"
    assert (
        post(
            "/api/v1/services", {}, {"Authorization": "Bearer " + TOKEN}, method="GET"
        )[0]
        == 503
    )


@pytest.mark.skipif(
    __import__("os").environ.get("PORYGON_TEST_POSTGRES") != "1",
    reason="PostgreSQL row locks required",
)
def test_concurrent_rotation_allows_only_one_replacement(settings, database_override):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from porygon_api.credentialroutes import rotate_credential, CredentialRotateIn
    from porygon_api.principals import LOCAL_OPERATOR_PRINCIPAL
    from fastapi import HTTPException

    assert (created := enroll())[0] == 201
    barrier = Barrier(2)

    def rotate(index):
        with Session(database_override) as db:
            barrier.wait()
            try:
                rotate_credential(
                    created[1]["credential_id"],
                    CredentialRotateIn(
                        token="rotation_" + str(index) * 43, overlap_seconds=60
                    ),
                    db,
                    LOCAL_OPERATOR_PRINCIPAL,
                )
                return 200
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(rotate, [1, 2])) == [200, 409]
    with Session(database_override) as db:
        assert (
            len(
                db.scalars(
                    select(ApiCredential).where(
                        ApiCredential.replaces_credential_id
                        == created[1]["credential_id"]
                    )
                ).all()
            )
            == 1
        )
