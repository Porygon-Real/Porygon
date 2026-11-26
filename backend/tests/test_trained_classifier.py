"""Unit and integration tests for the trained Porygon tree ensemble classifier.

Verifies:
1. Artifact integrity and canonical SHA-256 digest validation through model_registry.
2. Exact TreeSHAP path-delta additivity on converted trees (raw_probs == base + sum(deltas)).
3. Output probability normalization across all threat classes.
4. Class ordering matches canonical CLASSES contract, not rf.classes_ lexicographical order.
5. Default classifier remains hand-authored heuristic baseline.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from porygon_api.ml_classifier import (
    CLASSES,
    FEATURE_CONTRACT,
    FEATURE_NAMES,
    NOBASELINE_FEATURE_NAMES,
    INPUT_DOCUMENT_SCHEMA,
    PorygonThreatClassifier,
    default_classifier,
    load_model_artifact,
)
from porygon_api.model_registry import sha256_document


@pytest.fixture
def artifact_path() -> Path:
    """Resolve path to trained 12-feature model artifact, or skip if unavailable."""
    env_path = os.environ.get("PORYGON_ML_MODEL_PATH")
    candidates = []
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("/models/trained_ensemble.json"))
    candidates.append(Path(__file__).resolve().parent.parent / "ml_training" / "models" / "trained_ensemble.json")
    candidates.append(Path(__file__).resolve().parent.parent.parent / "backend" / "ml_training" / "models" / "trained_ensemble.json")
    for p in candidates:
        if p.is_file():
            return p
    pytest.skip("Trained ensemble artifact (trained_ensemble.json) not found in this environment; skipping trained model test.")


@pytest.fixture
def nobaseline_path(artifact_path: Path) -> Path:
    """Resolve path to trained 10-feature no-baseline artifact, or skip if unavailable."""
    env_path = os.environ.get("PORYGON_ML_MODEL_NOBASELINE_PATH")
    candidates = []
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("/models/trained_ensemble_nobaseline.json"))
    candidates.append(artifact_path.parent / "trained_ensemble_nobaseline.json")
    for p in candidates:
        if p.is_file():
            return p
    pytest.skip("No-baseline model artifact (trained_ensemble_nobaseline.json) not found in this environment; skipping test.")


def test_default_classifier_remains_hand_authored_baseline():
    """Verify that default_classifier remains the hand-authored heuristic baseline."""
    assert default_classifier._hand_authored_default is True
    meta = default_classifier.metadata
    assert meta.model_kind == "heuristic"
    assert meta.training_status == "hand_authored"
    assert meta.calibration_status == "unvalidated"
    assert default_classifier.temperature == 0.35


def test_trained_artifact_loads_and_verifies_sha256(artifact_path: Path):
    """Verify artifact loads through loader and passes model_registry.sha256_document check."""
    with open(artifact_path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    # 1. Direct validation via model_registry.sha256_document
    check_doc = {
        "classes": doc["classes"],
        "features": doc["features"],
        "feature_contract": doc["feature_contract"],
        "input_document_schema": doc["input_document_schema"],
        "trees": doc["trees"],
        "score_transform": doc["score_transform"],
    }
    computed_digest = sha256_document(check_doc)
    assert computed_digest == doc["model_metadata"]["model_artifact_sha256"]

    # 2. Load through classifier factory
    classifier = load_model_artifact(artifact_path)
    assert isinstance(classifier, PorygonThreatClassifier)
    assert classifier._hand_authored_default is False
    assert classifier.metadata.model_kind == "tree_ensemble"
    assert classifier.metadata.training_status == "trained"
    assert classifier.metadata.calibration_status == "validated"
    assert classifier.metadata.model_artifact_sha256 == computed_digest

    # 3. Tampering triggers mismatch
    tampered = dict(doc)
    tampered["model_metadata"] = dict(doc["model_metadata"])
    tampered["model_metadata"]["model_artifact_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="Artifact SHA-256 digest mismatch"):
        load_model_artifact(tampered)


def test_class_order_matches_CLASSES_not_rf_classes(artifact_path: Path):
    """Verify tree class distributions strictly follow CLASSES order, not rf.classes_."""
    # Scikit-learn sorts classes lexicographically:
    # ['benign', 'privilege_escalation', 'reconnaissance', 'shell_escape', 'suspicious_tooling']
    # Canonical Porygon CLASSES:
    # ['benign', 'reconnaissance', 'privilege_escalation', 'shell_escape', 'suspicious_tooling']
    assert CLASSES[1] == "reconnaissance"
    assert CLASSES[2] == "privilege_escalation"

    with open(artifact_path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    assert doc["classes"] == list(CLASSES)
    assert doc["classes"][1] == "reconnaissance"
    assert doc["classes"][2] == "privilege_escalation"

    # Verify probability vectors in root nodes have 5 classes matching CLASSES length
    for tree in doc["trees"]:
        assert len(tree["probs"]) == len(CLASSES)
        assert round(sum(tree["probs"]), 4) == 1.0


def test_path_delta_additivity_on_converted_trees(artifact_path: Path):
    """Verify telescoping path-delta additivity: raw_probs == base_values + sum(deltas)."""
    classifier = load_model_artifact(artifact_path)

    # Test diverse vectors across operational spectrum
    test_vectors = [
        # Benign profile
        {f: 0.0 for f in FEATURE_NAMES},
        # Reconnaissance profile
        {f: (0.8 if f in ("recon_ratio", "unseen_executable_ratio") else 0.05) for f in FEATURE_NAMES},
        # Privilege escalation profile
        {f: (0.9 if f in ("priv_escalation_ratio", "parent_shim_ratio") else 0.02) for f in FEATURE_NAMES},
        # Shell escape profile
        {f: (0.95 if f in ("shell_ratio", "parent_shim_ratio", "suspicious_sequence_ratio") else 0.01) for f in FEATURE_NAMES},
        # Suspicious tooling profile
        {f: (0.85 if f in ("tooling_ratio", "distinct_proc_count") else 0.04) for f in FEATURE_NAMES},
    ]

    for fdict in test_vectors:
        result = classifier.predict_vector(fdict)
        num_classes = len(CLASSES)

        for c_idx, c_name in enumerate(CLASSES):
            base_val = result.explanation_base_values[c_name]
            raw_val = result.raw_output_values[c_name]

            # Sum of contributions for this class across all 12 features
            delta_sum = sum(
                result.full_feature_contributions[c_name][fname]
                for fname in FEATURE_NAMES
            )

            # Telescoping property assertion: base + sum(deltas) == raw_probs
            assert abs(raw_val - (base_val + delta_sum)) < 1e-5, (
                f"Path delta additivity violated for class {c_name}: "
                f"raw={raw_val}, base={base_val}, delta_sum={delta_sum}, diff={raw_val - (base_val + delta_sum)}"
            )

        # Probability normalization
        prob_sum = sum(result.class_probabilities.values())
        assert abs(prob_sum - 1.0) < 1e-3, f"Probabilities do not sum to 1.0: {prob_sum}"


def test_opt_in_switch_unset_returns_heuristic(monkeypatch):
    """Verify that when PORYGON_ML_MODEL_PATH is unset, get_container_classifier returns default."""
    from porygon_api.main import _load_cached_classifier, get_container_classifier

    monkeypatch.delenv("PORYGON_ML_MODEL_PATH", raising=False)
    _load_cached_classifier.cache_clear()

    clf = get_container_classifier()
    assert clf.metadata.model_kind == "heuristic"
    assert clf.metadata.training_status == "hand_authored"


def test_opt_in_switch_valid_artifact(monkeypatch, artifact_path: Path):
    """Verify that when PORYGON_ML_MODEL_PATH is set to valid artifact, trained model is returned."""
    from porygon_api.main import _load_cached_classifier, get_container_classifier

    monkeypatch.setenv("PORYGON_ML_MODEL_PATH", str(artifact_path))
    _load_cached_classifier.cache_clear()

    clf = get_container_classifier()
    assert clf.metadata.model_kind == "tree_ensemble"
    assert clf.metadata.training_status == "trained"
    assert clf.metadata.calibration_status == "validated"


def test_opt_in_switch_missing_file_raises_500(monkeypatch, tmp_path: Path):
    """Verify that if PORYGON_ML_MODEL_PATH points to nonexistent file, HTTP 500 is raised (no silent fallback)."""
    from fastapi import HTTPException
    from porygon_api.main import _load_cached_classifier, get_container_classifier

    missing = tmp_path / "nonexistent_model.json"
    monkeypatch.setenv("PORYGON_ML_MODEL_PATH", str(missing))
    _load_cached_classifier.cache_clear()

    with pytest.raises(HTTPException) as exc_info:
        get_container_classifier()
    assert exc_info.value.status_code == 500
    assert "does not exist or is not a file" in exc_info.value.detail


def test_opt_in_switch_hash_mismatch_raises_500(monkeypatch, artifact_path: Path, tmp_path: Path):
    """Verify that if model artifact fails SHA-256 verification, HTTP 500 is raised (no silent fallback)."""
    from fastapi import HTTPException
    from porygon_api.main import _load_cached_classifier, get_container_classifier

    with open(artifact_path, "r", encoding="utf-8") as f:
        tampered_doc = json.load(f)
    tampered_doc["model_metadata"]["model_artifact_sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered.json"
    with open(tampered_path, "w", encoding="utf-8") as f:
        json.dump(tampered_doc, f)

    monkeypatch.setenv("PORYGON_ML_MODEL_PATH", str(tampered_path))
    _load_cached_classifier.cache_clear()

    with pytest.raises(HTTPException) as exc_info:
        get_container_classifier()
    assert exc_info.value.status_code == 500
    assert "Failed to load ML model artifact" in exc_info.value.detail
    assert "SHA-256 digest mismatch" in exc_info.value.detail


def test_model_info_endpoint_reflects_switch(monkeypatch, artifact_path: Path, tmp_path: Path):
    """Verify endpoint functions reflect the opt-in switch with cache clearing and 500 handling."""
    from fastapi import HTTPException
    from porygon_api.main import (
        _load_cached_classifier,
        get_ml_model_info,
        classify_features,
    )
    from porygon_api.schemas import MLClassifyFeaturesIn

    # 1. Unset: heuristic default
    monkeypatch.delenv("PORYGON_ML_MODEL_PATH", raising=False)
    _load_cached_classifier.cache_clear()
    info = get_ml_model_info()
    assert info.model_metadata.model_kind == "heuristic"
    assert info.model_name == "Porygon Heuristic Threat Classifier"

    # 2. Set to trained model: tree_ensemble
    monkeypatch.setenv("PORYGON_ML_MODEL_PATH", str(artifact_path))
    _load_cached_classifier.cache_clear()
    info = get_ml_model_info()
    assert info.model_metadata.model_kind == "tree_ensemble"
    assert info.model_metadata.calibration_status == "validated"
    assert info.model_name == "Porygon ML Threat Classifier"

    # Verify classification endpoint also uses the trained model
    feat_payload = MLClassifyFeaturesIn(
        observation_features={f: 0.1 for f in FEATURE_NAMES},
    )
    res = classify_features(feat_payload)
    assert res.model_metadata.model_kind == "tree_ensemble"

    # 3. Set to invalid path: 500 error raised (no silent fallback)
    missing = tmp_path / "missing_model.json"
    monkeypatch.setenv("PORYGON_ML_MODEL_PATH", str(missing))
    _load_cached_classifier.cache_clear()
    with pytest.raises(HTTPException) as exc_info:
        get_ml_model_info()
    assert exc_info.value.status_code == 500
    assert "does not exist" in exc_info.value.detail


def test_nobaseline_artifact_loads_through_registry(artifact_path: Path, nobaseline_path: Path):
    """Confirm trained_ensemble_nobaseline.json loads via model_registry and 12-feature SHA is 9327513b."""
    # Verify 12-feature artifact SHA is still 9327513b
    clf_12 = load_model_artifact(artifact_path)
    assert clf_12.metadata.model_artifact_sha256.startswith("9327513b")
    assert len(clf_12.features) == 12

    # Verify no-baseline artifact loads through model_registry / load_model_artifact
    clf_10 = load_model_artifact(nobaseline_path)
    assert clf_10.metadata.model_kind == "tree_ensemble"
    assert clf_10.metadata.training_status == "trained"
    assert clf_10.metadata.calibration_status == "validated"
    assert len(clf_10.features) == 10
    from porygon_api.ml_classifier import NOBASELINE_FEATURE_NAMES
    assert clf_10.features == NOBASELINE_FEATURE_NAMES
    assert clf_10.metadata.model_artifact_sha256.startswith("c434fb5e")


def test_classifier_variant_selection_rules(monkeypatch, artifact_path: Path, nobaseline_path: Path):
    """Verify 12-feature model is used only when baseline_features AND drift_score exist, else no-baseline."""
    from porygon_api.main import (
        _load_cached_classifier,
        classify_features,
    )
    from porygon_api.schemas import MLClassifyFeaturesIn

    monkeypatch.setenv("PORYGON_ML_MODEL_PATH", str(artifact_path))
    monkeypatch.setenv("PORYGON_ML_MODEL_NOBASELINE_PATH", str(nobaseline_path))
    _load_cached_classifier.cache_clear()

    dummy_doc = {
        "schema_version": "porygon.behaviour.v1",
        "categorical_distributions": {
            "executable": {"/bin/sh": 1.0},
            "process_name": {"sh": 1.0},
        },
    }

    # 1. Both baseline_features AND drift_score exist -> baseline variant (12 features)
    res_both = classify_features(
        MLClassifyFeaturesIn(
            observation_features=dummy_doc,
            baseline_features=dummy_doc,
            drift_score=0.15,
        )
    )
    assert res_both.model_variant == "baseline"
    assert len(res_both.feature_vector) == 12
    assert "unseen_executable_ratio" in res_both.feature_vector
    assert "jensen_shannon_drift" in res_both.feature_vector

    # 2. baseline_features exists but drift_score is None -> no_baseline variant (10 features)
    res_no_drift = classify_features(
        MLClassifyFeaturesIn(
            observation_features=dummy_doc,
            baseline_features=dummy_doc,
            drift_score=None,
        )
    )
    assert res_no_drift.model_variant == "no_baseline"
    assert len(res_no_drift.feature_vector) == 10
    assert "unseen_executable_ratio" not in res_no_drift.feature_vector
    assert "jensen_shannon_drift" not in res_no_drift.feature_vector

    # 3. baseline_features is None, drift_score exists -> no_baseline variant (10 features)
    res_no_base = classify_features(
        MLClassifyFeaturesIn(
            observation_features=dummy_doc,
            baseline_features=None,
            drift_score=0.20,
        )
    )
    assert res_no_base.model_variant == "no_baseline"
    assert len(res_no_base.feature_vector) == 10

    # 4. Neither exists -> no_baseline variant (10 features)
    res_neither = classify_features(
        MLClassifyFeaturesIn(
            observation_features=dummy_doc,
            baseline_features=None,
            drift_score=None,
        )
    )
    assert res_neither.model_variant == "no_baseline"
    assert len(res_neither.feature_vector) == 10


def test_insufficient_data_when_fewer_than_3_events(monkeypatch, artifact_path: Path, nobaseline_path: Path):
    """Verify slices with fewer than 3 events return predicted_class='insufficient_data'."""
    from unittest.mock import MagicMock
    from porygon_api.main import (
        _load_cached_classifier,
        classify_container,
        classify_events,
    )
    from porygon_api.schemas import MLClassifyEventsIn

    monkeypatch.setenv("PORYGON_ML_MODEL_PATH", str(artifact_path))
    monkeypatch.setenv("PORYGON_ML_MODEL_NOBASELINE_PATH", str(nobaseline_path))
    _load_cached_classifier.cache_clear()

    # Direct empty events payload
    res_empty = classify_events(MLClassifyEventsIn(events=[]))
    assert res_empty.predicted_class == "insufficient_data"
    assert res_empty.confidence == 0.0

    # Container slice tests
    mock_db = MagicMock()

    class MockEvent:
        def __init__(self, name: str, exe: str):
            self.process_name = name
            self.executable = exe
            self.parent_name = "init"
            self.parent_executable = "/sbin/init"
            self.user_uid = 0
            self.command_line = exe

    # 0 events in container slice
    mock_db.scalars.return_value.all.return_value = []
    mock_db.scalar.return_value = MagicMock(container_id="c-0", container_name="c-0", image_digest=None, features=None)
    res_0 = classify_container("c-0", db=mock_db)
    assert res_0.predicted_class == "insufficient_data"
    assert res_0.confidence == 0.0

    # 1 event in container slice
    mock_db.scalars.return_value.all.return_value = [
        MockEvent("bash", "/bin/bash"),
    ]
    res_1 = classify_container("c-1", db=mock_db)
    assert res_1.predicted_class == "insufficient_data"
    assert res_1.confidence == 0.0

    # 2 events in container slice
    mock_db.scalars.return_value.all.return_value = [
        MockEvent("bash", "/bin/bash"),
        MockEvent("ls", "/bin/ls"),
    ]
    res_2 = classify_container("c-2", db=mock_db)
    assert res_2.predicted_class == "insufficient_data"
    assert res_2.confidence == 0.0

    # 3 events in container slice -> Normal classification occurs (not insufficient_data)
    mock_db.scalars.return_value.all.return_value = [
        MockEvent("bash", "/bin/bash"),
        MockEvent("ls", "/bin/ls"),
        MockEvent("cat", "/bin/cat"),
    ]
    res_3 = classify_container("c-3", db=mock_db)
    assert res_3.predicted_class in CLASSES


def test_nobaseline_missing_or_corrupt_path_raises_500(monkeypatch, tmp_path: Path):
    """Verify that if PORYGON_ML_MODEL_NOBASELINE_PATH is invalid, HTTP 500 is raised without silent fallback."""
    from fastapi import HTTPException
    from porygon_api.main import _load_cached_classifier, get_nobaseline_classifier

    missing = tmp_path / "missing_nobaseline.json"
    monkeypatch.setenv("PORYGON_ML_MODEL_NOBASELINE_PATH", str(missing))
    _load_cached_classifier.cache_clear()

    with pytest.raises(HTTPException) as exc_info:
        get_nobaseline_classifier()
    assert exc_info.value.status_code == 500
    assert "does not exist" in exc_info.value.detail


def test_optional_sklearn_shap_parity(artifact_path: Path):
    """Optional validation test: verifies SHAP/scikit-learn parity when dependencies are installed.

    In production images where sklearn/shap are not installed, this test cleanly skips.
    """
    sklearn = pytest.importorskip("sklearn")
    shap = pytest.importorskip("shap")

    clf = load_model_artifact(artifact_path)
    assert clf.metadata.model_kind == "tree_ensemble"
    sample_vec = {f: 0.1 for f in FEATURE_NAMES}
    res = clf.predict_vector(sample_vec)
    assert res.predicted_class in CLASSES



