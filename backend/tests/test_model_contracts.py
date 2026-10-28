import pytest
from porygon_api.ml_classifier import default_classifier
from porygon_api.model_registry import predict,ModelArtifact


def test_default_model_reports_heuristic_and_actual_explanation_space():
    metadata=default_classifier.metadata
    assert metadata.model_kind=='heuristic' and metadata.training_status=='hand_authored'
    assert metadata.explanation_method=='tree_path_delta' and metadata.explanation_output_space=='raw_ensemble_probability'


def test_missing_trained_model_is_explicit_and_unknown_artifact_refused():
    assert predict({},None)['status']=='model_unavailable'
    with pytest.raises(ValueError):ModelArtifact.model_validate({'kind':'pickle','artifact_sha256':'a'*64})
