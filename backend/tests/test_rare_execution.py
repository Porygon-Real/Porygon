from copy import deepcopy

import pytest

from porygon_api.baseline import COMMAND_LINEAGE_SCHEMA
from porygon_api.main import get_anomaly_scoring_config
from porygon_api.scoring import (
    RARE_EXECUTION_ALGORITHM,
    build_observation_key,
    get_scoring_config,
    score_feature_documents,
)
from test_scoring import _features
from test_command_lineage import event, profile


def test_isolated_shell_no_longer_disappears_inside_zero_baseline_tolerance():
    baseline = _features()
    observed = deepcopy(baseline)
    observed["numeric_summaries"]["shell_process_ratio"]["mean"] = 1 / 1000
    legacy = score_feature_documents(baseline_features=baseline, observation_features=observed)
    rare = score_feature_documents(
        baseline_features=baseline,
        observation_features=observed,
        algorithm_version=RARE_EXECUTION_ALGORITHM,
    )
    assert legacy[2]["numeric_deviation"]["features"]["shell_process_ratio"]["score"] == 0
    detail = rare[2]["numeric_deviation"]["features"]["shell_process_ratio"]
    assert detail["score"] == 0.7
    assert detail["score_before_policy"] == 0
    assert detail["policy"] == "zero_baseline_shell_floor"
    assert rare[0] > legacy[0]


@pytest.mark.parametrize("observed_value", [0, 0.001, 0.05, 0.5, 1])
def test_floor_is_bounded_monotone_and_unchanged_without_shells(observed_value):
    baseline = _features()
    observed = deepcopy(baseline)
    observed["numeric_summaries"]["shell_process_ratio"]["mean"] = observed_value
    total, _, components, _ = score_feature_documents(
        baseline_features=baseline,
        observation_features=observed,
        algorithm_version=RARE_EXECUTION_ALGORITHM,
    )
    component = components["numeric_deviation"]["features"]["shell_process_ratio"]["score"]
    assert 0 <= total <= 1
    assert component >= 0.7 if observed_value > 0 else component == 0
    if observed_value == 0:
        assert "policy" not in components["numeric_deviation"]["features"]["shell_process_ratio"]


def test_nonzero_or_incomplete_training_summary_does_not_claim_zero_tolerance():
    for key, value in [("max", 0.001), ("stddev", 0.001), ("max", None)]:
        baseline = _features()
        if value is None:
            baseline["numeric_summaries"]["shell_process_ratio"].pop(key)
        else:
            baseline["numeric_summaries"]["shell_process_ratio"][key] = value
        observed = deepcopy(baseline)
        observed["numeric_summaries"]["shell_process_ratio"]["mean"] = 0.001
        detail = score_feature_documents(
            baseline_features=baseline,
            observation_features=observed,
            algorithm_version=RARE_EXECUTION_ALGORITHM,
        )[2]["numeric_deviation"]["features"]["shell_process_ratio"]
        assert "policy" not in detail


def test_algorithm_is_explicit_and_does_not_reuse_existing_score_ids():
    args = dict(
        profile_id="profile",
        profile_model_hash="m" * 64,
        window_start="start",
        window_end="end",
        selected_event_ids_sha256="e" * 64,
    )
    assert build_observation_key(**args) != build_observation_key(
        **args, algorithm_version=RARE_EXECUTION_ALGORITHM
    )
    assert get_scoring_config()["algorithm_version"] == "porygon.distance.v1"
    assert (
        get_scoring_config(COMMAND_LINEAGE_SCHEMA)["algorithm_version"]
        == "porygon.distance.command-lineage"
    )
    assert (
        get_anomaly_scoring_config(algorithm_version=RARE_EXECUTION_ALGORITHM)["scoring_config"][
            "numeric_policy"
        ]["zero_baseline_shell_score"]
        == 0.7
    )
    features = profile([event("a")])[0]
    assert (
        score_feature_documents(
            baseline_features=features,
            observation_features=features,
            algorithm_version=RARE_EXECUTION_ALGORITHM,
        )[0]
        == 0
    )
