"""Persisted promotion decisions bind predeclared criteria and run evidence."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from test_incident_grouping import engine as engine
from porygon_api import evidence_routes as routes
from porygon_api.auth import utc
from porygon_api.models import AdvisoryModel, ModelPromotionReview, ModelQualityLock
from porygon_api.permissions import ROUTE_PERMISSIONS, require_permission
from porygon_api.principals import CURRENT_PRINCIPAL, Principal
from porygon_api.vulnerability import sha256_document

MODEL = "a" * 64
SPLIT = "b" * 64
NOW = datetime.now(timezone.utc)


@pytest.fixture
def registered(engine):
    # Artifact shape/training validation has separate tests. Seed the persisted
    # provenance consumed by activation to isolate its transactional guards.
    with Session(engine) as db:
        db.add(
            AdvisoryModel(
                artifact_hash=MODEL,
                artifact={
                    "provenance": {
                        "data_kind": "independent-measured",
                        "heldout_run_ids": ["heldout-benign", "heldout-attack"],
                        "split_manifest_sha256": SPLIT,
                    }
                },
                approved_by="human:registrar",
                evaluation_reference="fixture-registration",
                active=False,
                created_at=NOW,
            )
        )
        db.commit()
    return engine


def criteria():
    return routes.QualityCriteria(
        minimum_recall=0.8,
        maximum_false_alerts_per_container_hour=0.1,
        comparator="rules",
        decision_reference="fixture-precollection-decision",
    )


def payload(lock_hash):
    records = [
        {
            "run_id": "heldout-" + label,
            "label": label,
            "ground_truth_sha256": digest * 64,
            "positive": label == "attack",
            "container_hours": 1.0,
        }
        for label, digest in (("benign", "c"), ("attack", "d"))
    ]
    report = routes.HeldoutReport.model_validate(
        {
            "contract": "porygon.model-evaluation",
            "artifact_sha256": MODEL,
            "test_dataset_sha256": "e" * 64,
            "data_kind": "independent-measured",
            "test_run_ids": [row["run_id"] for row in records],
            "split_manifest_sha256": SPLIT,
            "first_test_collection_at": (NOW - timedelta(hours=2)).isoformat(),
            "last_test_collection_at": (NOW - timedelta(hours=1)).isoformat(),
            "metrics": {"recall": 1.0, "false_alerts_per_container_hour": 0.0},
            "records": records,
            "passed_validation": True,
        }
    ).model_dump()
    comparison = routes.ComparatorReport.model_validate(
        {
            "comparator": "rules",
            "artifact_sha256": MODEL,
            "test_dataset_sha256": report["test_dataset_sha256"],
            "split_manifest_sha256": SPLIT,
            "records": deepcopy(records),
        }
    ).model_dump()
    return {
        "heldout_report": report,
        "report_sha256": sha256_document(report),
        "quality_lock_sha256": lock_hash,
        "comparison_report": comparison,
        "comparison_report_sha256": sha256_document(comparison),
        "review_reference": "fixture-human-review",
    }


def install_precollection_lock(db):
    document = criteria().model_dump()
    digest = sha256_document(document)
    db.add(
        ModelQualityLock(
            artifact_hash=MODEL,
            criteria_hash=digest,
            criteria=document,
            locked_by="human:planner",
            locked_at=NOW - timedelta(days=1),
        )
    )
    db.commit()
    return digest


def test_quality_lock_is_server_recorded_and_immutable(registered):
    token = CURRENT_PRINCIPAL.set(
        Principal("human:planner", "operator", roles=("admin",))
    )
    try:
        with Session(registered) as db:
            before = datetime.now(timezone.utc)
            first = routes.lock_model_quality(MODEL, criteria(), db)
            after = datetime.now(timezone.utc)
            assert before <= utc(first["locked_at"]) <= after
            assert first["locked_by"] == "human:planner"
            assert routes.lock_model_quality(MODEL, criteria(), db) == first
            changed = criteria().model_copy(update={"minimum_recall": 0.5})
            with pytest.raises(HTTPException) as failure:
                routes.lock_model_quality(MODEL, changed, db)
            assert failure.value.status_code == 409
            assert db.get(ModelQualityLock, MODEL).criteria["minimum_recall"] == 0.8
    finally:
        CURRENT_PRINCIPAL.reset(token)


@pytest.mark.parametrize("lock_state", ["missing", "post-collection"])
def test_promotion_requires_a_persisted_precollection_lock(registered, lock_state):
    with Session(registered) as db:
        digest = sha256_document(criteria().model_dump())
        if lock_state == "post-collection":
            install_precollection_lock(db)
            db.get(ModelQualityLock, MODEL).locked_at = NOW
            db.commit()
        with pytest.raises(HTTPException) as failure:
            routes.activate_model(
                MODEL, routes.PromoteModelIn.model_validate(payload(digest)), db
            )
        assert failure.value.status_code == 409
        assert not db.get(AdvisoryModel, MODEL).active
        assert db.scalar(select(func.count()).select_from(ModelPromotionReview)) == 0


@pytest.mark.parametrize(
    "tamper",
    [
        "report-hash",
        "comparison-hash",
        "comparison-dataset",
        "comparison-split",
        "comparison-ground-truth",
        "comparison-exposure",
    ],
)
def test_comparator_and_heldout_evidence_cannot_be_substituted(registered, tamper):
    with Session(registered) as db:
        data = payload(install_precollection_lock(db))
        if tamper == "report-hash":
            data["report_sha256"] = "f" * 64
        elif tamper == "comparison-hash":
            data["comparison_report_sha256"] = "f" * 64
        else:
            comparison = data["comparison_report"]
            if tamper == "comparison-dataset":
                comparison["test_dataset_sha256"] = "f" * 64
            elif tamper == "comparison-split":
                comparison["split_manifest_sha256"] = "f" * 64
            elif tamper == "comparison-ground-truth":
                comparison["records"][0]["ground_truth_sha256"] = "f" * 64
            else:
                comparison["records"][0]["container_hours"] = 2.0
            data["comparison_report_sha256"] = sha256_document(comparison)
        with pytest.raises(HTTPException) as failure:
            routes.activate_model(MODEL, routes.PromoteModelIn.model_validate(data), db)
        assert failure.value.status_code == 409
        if tamper == "report-hash":
            assert "matching independently measured heldout evidence" in failure.value.detail
        elif tamper in {"comparison-ground-truth", "comparison-exposure"}:
            assert "run accounting or independent ground truth differs" in failure.value.detail
        else:
            assert "Comparator must bind the same model and heldout collection" in failure.value.detail
        assert not db.get(AdvisoryModel, MODEL).active
        assert db.scalar(select(func.count()).select_from(ModelPromotionReview)) == 0


def test_validated_heldout_report_keeps_its_hash_after_json_roundtrip():
    # Omitted optional metrics are valid input. Their defaults must have the
    # same JSON numeric representation when the report is later validated as
    # part of the activation request, otherwise its accepted digest changes.
    first = payload("b" * 64)["heldout_report"]
    second = routes.HeldoutReport.model_validate(first).model_dump()
    assert sha256_document(first) == sha256_document(second)


def test_report_metrics_are_recomputed_from_independent_run_evidence():
    report = payload("b" * 64)["heldout_report"]
    report["metrics"]["recall"] = 0.5
    with pytest.raises(ValidationError, match="Metrics differ"):
        routes.HeldoutReport.model_validate(report)


def test_future_heldout_collection_cannot_authorize_activation(registered):
    with Session(registered) as db:
        data = payload(install_precollection_lock(db))
        report = data["heldout_report"]
        report["first_test_collection_at"] = (NOW + timedelta(days=1)).isoformat()
        report["last_test_collection_at"] = (NOW + timedelta(days=2)).isoformat()
        data["report_sha256"] = sha256_document(report)
        with pytest.raises(HTTPException) as failure:
            routes.activate_model(MODEL, routes.PromoteModelIn.model_validate(data), db)
        assert failure.value.status_code == 422
        assert not db.get(AdvisoryModel, MODEL).active


def test_synthetic_model_refusal_and_successful_human_review_are_persisted(registered):
    token = CURRENT_PRINCIPAL.set(
        Principal("human:reviewer", "operator", roles=("admin",))
    )
    try:
        with Session(registered) as db:
            data = routes.PromoteModelIn.model_validate(
                payload(install_precollection_lock(db))
            )
            model = db.get(AdvisoryModel, MODEL)
            document = deepcopy(model.artifact)
            document["provenance"]["data_kind"] = "synthetic-fixture"
            model.artifact = document
            db.commit()
            with pytest.raises(HTTPException) as failure:
                routes.activate_model(MODEL, data, db)
            assert failure.value.status_code == 409 and not model.active
            document = deepcopy(model.artifact)
            document["provenance"]["data_kind"] = "independent-measured"
            model.artifact = document
            db.commit()
            result = routes.activate_model(MODEL, data, db)
            assert result["active"] and result["advisory_only"]
            review = db.scalar(select(ModelPromotionReview))
            assert review.reviewed_by == "human:reviewer"
            assert review.document["model_report"] == data.heldout_report.model_dump()
            assert (
                review.document["comparison_report"]
                == data.comparison_report.model_dump()
            )
            assert review.document["quality_lock_sha256"] == data.quality_lock_sha256
            assert model.approved_by == "human:reviewer"
            routes.activate_model(MODEL, data, db)
            assert (
                db.scalar(select(func.count()).select_from(ModelPromotionReview)) == 1
            )
    finally:
        CURRENT_PRINCIPAL.reset(token)


@pytest.mark.parametrize(
    "path",
    [
        "/operator/v1/advisory-models",
        "/operator/v1/advisory-models/{artifact_hash}/quality-lock",
        "/operator/v1/advisory-models/{artifact_hash}/activate",
    ],
)
def test_model_administration_requires_admin_permission(path):
    permission = ROUTE_PERMISSIONS[("POST", path)]
    for role in ("viewer", "analyst", "responder"):
        with pytest.raises(HTTPException) as failure:
            require_permission(
                Principal("human:" + role, "operator", roles=(role,)), permission, path
            )
        assert failure.value.status_code == 403
    require_permission(
        Principal("human:admin", "operator", roles=("admin",)), permission, path
    )
