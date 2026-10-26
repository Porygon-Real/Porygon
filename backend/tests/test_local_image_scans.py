from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier

from fastapi import HTTPException
from pydantic import ValidationError
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from porygon_api import main
from porygon_api.models import ImageIdentity, ImageScan, SbomArtifact, VulnerabilityFinding
from porygon_api.schemas import (
    ImageScanClaimIn,
    ImageScanCompleteIn,
    ImageScanCreateIn,
    ImageScanOut,
)
from test_incident_grouping import engine as _disposable_engine
from test_identity_reconciliation import identity
from test_parent_correlation import _event

engine = _disposable_engine
IMAGE_ID = "sha256:" + "c" * 64
LOCAL = "local:" + IMAGE_ID
DIGEST = "example/app@sha256:" + "d" * 64


def inventory(db, host="host-a", digest=None):
    now = datetime.now(timezone.utc)
    db.add(
        ImageIdentity(
            docker_host_id=host,
            image_id=IMAGE_ID,
            image_ref="example:local",
            primary_repo_digest=digest,
            repo_digests=[digest] if digest else [],
            repo_tags=["example:local"],
            digest_status="resolved" if digest else "unavailable",
            os="linux",
            architecture="amd64",
            first_seen_at=now,
            last_seen_at=now,
        )
    )
    db.commit()


def queue(db, host="host-a", reference="initial", target=LOCAL):
    return main.create_image_scan(
        ImageScanCreateIn(
            image_identity=target,
            docker_host_id=host,
            requested_by="Anurup R Krishnan",
            scan_reference=reference,
        ),
        db,
    )


def claim(db, host="host-a"):
    return main.claim_image_scan(
        ImageScanClaimIn(
            scanner_instance_id="worker", scanner_version="0.72.0", docker_host_id=host
        ),
        db,
    )["scan"]


def completion(host="host-a"):
    return ImageScanCompleteIn(
        scanner_instance_id="worker",
        scanner_metadata={
            "docker_host_id": host,
            "image_identity": {
                "image_id": IMAGE_ID,
                "image_identity": LOCAL,
                "identity_kind": "local_image_id",
            },
        },
        trivy_report={
            "Metadata": {"ImageID": IMAGE_ID},
            "Results": [
                {
                    "Target": "example",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-12345",
                            "PkgName": "curl",
                            "PkgPath": "/usr/bin/curl",
                            "InstalledVersion": "1",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        },
        cyclonedx_sbom={"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []},
    )


def test_identity_aliases_require_exact_full_config_ids():
    assert ImageScanCreateIn(image_digest=DIGEST, requested_by="test").image_identity == DIGEST
    assert ImageScanCreateIn(image_identity=LOCAL, requested_by="test").image_digest == LOCAL
    for target in ("local:abc", "local:sha256:abc", "sha256:" + "a" * 64, "example:latest"):
        with pytest.raises(ValidationError):
            ImageScanCreateIn(image_identity=target, requested_by="test")
    with pytest.raises(ValidationError, match="must agree"):
        ImageScanCreateIn(image_identity=LOCAL, image_digest=DIGEST, requested_by="test")


def test_undeployed_local_scan_requires_host_and_does_not_forge_inventory(engine):
    with Session(engine) as db:
        with pytest.raises(HTTPException) as error:
            main.create_image_scan(ImageScanCreateIn(image_identity=LOCAL, requested_by="test"), db)
        assert error.value.status_code == 404
        record = queue(db)
        assert record.status == "queued"
        assert db.scalar(select(func.count()).select_from(ImageIdentity)) == 0
        document = ImageScanOut.model_validate(record).model_dump()
        assert document["identity_kind"] == "local_image_id"
        assert document["image_identity"] == document["image_digest"] == LOCAL
        assert queue(db).scan_id == record.scan_id


@pytest.mark.parametrize("target", [LOCAL, DIGEST])
def test_identical_content_on_different_hosts_has_distinct_queue_keys(engine, target):
    with Session(engine) as db:
        inventory(db, "host-a", DIGEST)
        inventory(db, "host-b", DIGEST)
        with pytest.raises(HTTPException) as error:
            main.create_image_scan(
                ImageScanCreateIn(image_identity=target, requested_by="test"), db
            )
        assert error.value.status_code == 409
        a, b = queue(db, target=target), queue(db, host="host-b", target=target)
        assert a.scan_key != b.scan_key
        assert queue(db, target=target).scan_id == a.scan_id


def test_local_claims_require_exact_daemon_and_legacy_workers_cannot_take_them(engine):
    with Session(engine) as db:
        record = queue(db)
        assert claim(db, "host-b") is None
        assert claim(db, None) is None
        assert claim(db).scan_id == record.scan_id


def test_completion_preserves_local_provenance_and_rejects_host_or_content_confusion(engine):
    with Session(engine) as db:
        record = queue(db)
        claim(db)
        with pytest.raises(HTTPException) as error:
            main.complete_image_scan(record.scan_id, completion("host-b"), db)
        assert error.value.status_code == 409
        bad = completion()
        bad.scanner_metadata["image_identity"]["image_id"] = "sha256:" + "e" * 64
        with pytest.raises(HTTPException):
            main.complete_image_scan(record.scan_id, bad, db)
        bad_report = completion()
        bad_report.trivy_report["Metadata"]["ImageID"] = "sha256:" + "e" * 64
        with pytest.raises(HTTPException):
            main.complete_image_scan(record.scan_id, bad_report, db)
        done = main.complete_image_scan(record.scan_id, completion(), db)
        assert done.status == "completed"
        assert db.scalar(select(SbomArtifact)).image_digest == LOCAL
        assert main.complete_image_scan(record.scan_id, completion(), db).scan_id == done.scan_id
        assert db.scalar(select(func.count()).select_from(SbomArtifact)) == 1


def test_other_host_runtime_does_not_inflate_local_exposure(engine):
    with Session(engine) as db:
        other = identity(host="host-b")
        other.image_id = IMAGE_ID
        other.current_snapshot = {"network_settings": {"ports": {"80/tcp": [{"HostPort": "8080"}]}}}
        db.add(other)
        observed = _event("f" * 64, datetime.now(timezone.utc), 100)
        observed.docker_host_id = "host-b"
        observed.image_id = IMAGE_ID
        observed.executable = "/usr/bin/curl"
        observed.container_id = other.container_id
        db.add(observed)
        db.commit()
        record = queue(db)
        claim(db)
        main.complete_image_scan(record.scan_id, completion(), db)
        finding = db.scalar(select(VulnerabilityFinding))
        assert finding.evidence_stage == "package_present"


def test_postgres_concurrent_completion_creates_one_receipt(engine):
    if engine.dialect.name != "postgresql":
        pytest.skip("Requires PostgreSQL completion row locking")
    with Session(engine) as db:
        record = queue(db)
        claim(db)
        scan_id = record.scan_id
    barrier = Barrier(2)

    def finish(_):
        with Session(engine) as db:
            barrier.wait(timeout=10)
            return main.complete_image_scan(scan_id, completion(), db).status

    with ThreadPoolExecutor(2) as pool:
        assert list(pool.map(finish, range(2))) == ["completed", "completed"]
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(SbomArtifact)) == 1
        assert db.scalar(select(func.count()).select_from(ImageScan)) == 1


def test_legacy_repository_key_is_reused_only_on_its_original_host(engine):
    from porygon_api.vulnerability import build_scan_key

    with Session(engine) as db:
        inventory(db, "host-a", DIGEST)
        inventory(db, "host-b", DIGEST)
        first = queue(db, target=DIGEST)
        first.scan_key = build_scan_key(
            image_digest=DIGEST, image_id=IMAGE_ID, scanner_name="trivy", scanner_version="0.72.0"
        )
        db.commit()
        assert queue(db, target=DIGEST).scan_id == first.scan_id
        assert queue(db, host="host-b", target=DIGEST).scan_id != first.scan_id


def test_local_registry_hostname_is_not_a_local_id_marker(engine):
    with Session(engine) as db:
        target = "local:5000/team/app@sha256:" + "d" * 64
        inventory(db, "host-a", target)
        record = queue(db, target=target)
        assert ImageScanOut.model_validate(record).identity_kind == "repository_digest"
