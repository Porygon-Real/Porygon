"""Truthful heuristic provenance without changing legacy classifier scores."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from porygon_api import main
from porygon_api.ml_classifier import CLASSES, MODEL_VERSION, PorygonThreatClassifier, default_classifier
from porygon_api.schemas import MLClassifyEventsIn, MLClassifyFeaturesIn
from test_ml_classifier import _make_dummy_features

# Captured from the pre-metadata implementation before modifying the classifier.
LEGACY_CASES = [
    ({'event_count': 3, 'distinct_proc_count': 2, 'jensen_shannon_drift': 0.02},
     'benign', 'clean', 0.8969, [0.8969, 0.0366, 0.0366, 0.0216, 0.0084]),
    ({'shell_ratio': 1, 'root_ratio': 1, 'parent_shim_ratio': 0.5,
      'event_count': 2, 'distinct_proc_count': 2, 'jensen_shannon_drift': 0.85},
     'shell_escape', 'high', 0.5494, [0.3557, 0.0401, 0.0401, 0.5494, 0.0148]),
    ({'recon_ratio': 1, 'root_ratio': 1, 'event_count': 5,
      'distinct_proc_count': 5, 'jensen_shannon_drift': 0.65},
     'reconnaissance', 'medium', 0.6148, [0.3175, 0.6148, 0.0358, 0.0195, 0.0125]),
    ({'priv_escalation_ratio': 1, 'root_ratio': 1, 'event_count': 3,
      'distinct_proc_count': 3, 'jensen_shannon_drift': 0.75},
     'privilege_escalation', 'high', 0.6148, [0.3175, 0.0358, 0.6148, 0.0195, 0.0125]),
    ({'tooling_ratio': 1, 'event_count': 3, 'distinct_proc_count': 3,
      'jensen_shannon_drift': 0.70},
     'suspicious_tooling', 'high', 0.4633, [0.4053, 0.0457, 0.0457, 0.0401, 0.4633]),
]


@pytest.mark.parametrize('features,label,risk,confidence,scores', LEGACY_CASES)
def test_legacy_numeric_outputs_are_unchanged(features, label, risk, confidence, scores):
    result = default_classifier.predict_vector(features)
    assert result.model_version == MODEL_VERSION == 'porygon.ml.rf.v1'
    assert result.predicted_class == label
    assert result.risk_level == risk
    assert result.confidence == confidence
    assert [result.class_probabilities[name] for name in CLASSES] == scores


@pytest.mark.parametrize('features,_label,_risk,_confidence,_scores', LEGACY_CASES)
def test_full_path_deltas_reconstruct_only_the_declared_raw_output(
        features, _label, _risk, _confidence, _scores):
    result = default_classifier.predict_vector(features)
    assert result.model_metadata.explanation_method == 'tree_path_delta'
    assert result.model_metadata.explanation_output_space == 'raw_ensemble_probability'
    for name in CLASSES:
        reconstructed = result.explanation_base_values[name] + sum(
            result.full_feature_contributions[name].values())
        assert reconstructed == pytest.approx(result.raw_output_values[name], abs=1e-12)
    assert result.raw_output_values != result.class_probabilities


def test_metadata_is_immutable_and_survives_stored_explanation_serialization():
    result = default_classifier.predict_vector({})
    metadata = result.model_metadata
    assert metadata.model_kind == 'heuristic'
    assert metadata.training_status == 'hand_authored'
    assert metadata.calibration_status == 'unvalidated'
    assert metadata.input_document_schema == 'porygon.behaviour.v1'
    assert metadata.feature_contract == 'porygon.ml.features.exec-taxonomy'
    with pytest.raises(FrozenInstanceError):
        metadata.training_status = 'trained'
    stored = result.to_dict()
    assert stored['model_metadata'] == metadata.to_dict()
    assert stored['raw_output_values'] == result.raw_output_values
    assert stored['full_feature_contributions'] == result.full_feature_contributions


def reorder(value):
    if isinstance(value, dict):
        return {key: reorder(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reorder(item) for item in value]
    return value


def test_ensemble_hash_is_canonical_and_detects_changed_tree_content():
    trees = deepcopy(default_classifier.trees)
    original = PorygonThreatClassifier(trees)
    rearranged = PorygonThreatClassifier(reorder(trees))
    assert original.metadata.model_artifact_sha256 == rearranged.metadata.model_artifact_sha256
    trees[0]['threshold'] += 0.01
    altered = PorygonThreatClassifier(trees)
    assert altered.metadata.model_artifact_sha256 != rearranged.metadata.model_artifact_sha256
    assert len(altered.metadata.model_artifact_sha256) == 64


def test_custom_trees_do_not_claim_training_or_calibration_provenance():
    custom = PorygonThreatClassifier(deepcopy(default_classifier.trees))
    result = custom.predict_vector({})
    assert result.model_metadata.model_kind == 'tree_ensemble'
    assert result.model_metadata.training_status == 'unspecified'
    assert result.model_metadata.calibration_status == 'unvalidated'


def test_model_info_and_all_three_api_constructors_expose_consistent_metadata():
    expected = default_classifier.metadata.to_dict()
    info = main.get_ml_model_info()
    assert info.model_metadata.model_dump() == expected
    assert 'TreeSHAP' not in info.explainability_method
    assert 'calibrated' not in info.algorithm.lower()
    events = [{'process_name': 'python', 'executable': '/usr/bin/python',
               'parent_name': None, 'parent_executable': None, 'user_uid': 1000,
               'command_line': 'python'}]
    db = MagicMock()
    db.scalar.return_value = None
    db.scalars.return_value.all.return_value = [SimpleNamespace(**events[0], image_digest=None)]
    outputs = [
        main.classify_events(MLClassifyEventsIn(events=events), db),
        main.classify_features(MLClassifyFeaturesIn(observation_features=_make_dummy_features())),
        main.classify_container('test-container', event_limit=10, db=db),
    ]
    for output in outputs:
        assert output.model_metadata.model_dump() == expected
        assert set(output.explanation_base_values) == set(CLASSES)
        assert set(output.raw_output_values) == set(CLASSES)
        assert set(output.full_feature_contributions) == set(CLASSES)
