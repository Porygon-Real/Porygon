import ast
import json
import pytest
from experiments.benchmarks.run import validate_samples
from experiments.benchmarks import lab
from experiments.benchmarks.lab import summarize_lab, validate_spec
from datetime import datetime, timezone


def test_measurement_cannot_omit_hardware_or_unknown_loss_boundaries():
    with pytest.raises(ValueError):
        validate_samples(
            {
                "contract": "porygon.capacity-measurement",
                "hardware": {},
                "samples": [{}],
            }
        )


def _trace(
    host="node-a",
    *,
    selected=360_000,
    persisted=360_000,
    assessment_state="completed",
    coverage="available",
    latency_complete=True,
    source_present=True,
):
    """Small deterministic evidence packet; synthetic only, never capacity evidence."""
    start, end = 1_000_000_000_000, 4_600_000_000_000
    started = datetime.fromtimestamp(
        (start - 1_000_000_000) / 1e9, timezone.utc
    ).isoformat()
    finished = datetime.fromtimestamp(
        (end + 1_000_000_000) / 1e9, timezone.utc
    ).isoformat()
    health = {
        "source_epoch": "epoch-a",
        "observed_at": started,
        "metrics": {"falco_drops": 0, "falco_output_drops": 0},
    }
    end_health = {**health, "observed_at": finished}
    backend = {
        "persisted": persisted,
        "persisted_id_set_sha256": "same-set"
        if persisted == selected
        else "different-set",
        "duplicate_logical_jobs": 0,
        "assessment_latency_complete": latency_complete,
        "assessment_completed": 1,
        "assessment_pending": 0,
        "assessment_latency_p95_seconds": 2.0,
        "assessment_state_counts": {assessment_state: 1},
        "assessment_coverage_counts": {coverage: 1},
        "negative_assessment_lag_count": 0,
        "health": end_health,
    }
    source = {
        "selected_source_records": selected,
        "counter_resets": 0,
        "parse_errors": 0,
        "id_set_sha256": "same-set",
        "started_ns": start,
        "finished_ns": end,
        "event_timestamps_ns": [start + 1_000_000_000] * min(selected, 4),
    }
    controller = {
        "controller": {
            "started_ns": start,
            "finished_ns": end,
            "elapsed_seconds": 3600,
            "failure_count": 0,
        }
    }
    return {
        "host_id": host,
        "kernel_boot_id": "boot-" + host,
        "source": source if source_present else None,
        "controller": controller,
        "samples": [
            {
                "backend": {**backend, "health": health},
                "telemetry": {
                    "counter_epoch": "epoch-a",
                    "adapter_accepted": 10,
                    "adapter_delivered": 10,
                    "backpressure_events": 0,
                    "dead_letters": 0,
                },
            },
            {
                "backend": backend,
                "telemetry": {
                    "counter_epoch": "epoch-a",
                    "adapter_accepted": 20,
                    "adapter_delivered": 20,
                    "backpressure_events": 0,
                    "dead_letters": 0,
                },
            },
        ],
        "failures": [],
        "fault": None,
    }


def test_measured_boundaries_can_pass_but_missing_source_boundary_is_unknown():
    report = summarize_lab([_trace()], "sustained")
    assert report["nodes"][0]["matching_measured_boundaries"] == "pass"
    missing = summarize_lab([_trace(source_present=False)], "sustained")
    assert missing["nodes"][0]["matching_measured_boundaries"] == "unknown"
    assert missing["targets"]["three_node_envelope"] == "unknown"


def test_observed_identity_mismatch_fails_even_when_other_boundaries_are_measured():
    report = summarize_lab([_trace(persisted=359_999)], "sustained")
    assert report["nodes"][0]["matching_measured_boundaries"] == "fail"
    assert (
        "observed_file_to_database_identity_set_mismatch"
        in report["nodes"][0]["failure_reasons"]
    )


@pytest.mark.parametrize(
    ("state", "coverage", "complete", "expected_boundary"),
    [
        ("failed", "available", False, "fail"),
        ("completed", "unknown", False, "unknown"),
        ("unavailable", "available", False, "unknown"),
        ("completed", "available", False, "unknown"),
    ],
)
def test_incomplete_failed_or_unavailable_assessment_jobs_cannot_pass_latency(
    state, coverage, complete, expected_boundary
):
    report = summarize_lab(
        [_trace(assessment_state=state, coverage=coverage, latency_complete=complete)],
        "sustained",
    )
    assert report["targets"]["p95_assessment_latency"] == "unknown"
    assert report["nodes"][0]["matching_measured_boundaries"] == expected_boundary


def test_generation_interval_excludes_downstream_drain_from_throughput():
    trace = _trace(selected=2)
    trace["source"]["event_timestamps_ns"] = [
        1_001_000_000_000,
        4_599_000_000_000,
        4_600_000_000_000,
        9_000_000_000_000,
    ]
    node = summarize_lab([trace], "sustained")["nodes"][0]
    assert node["measured_selected_events_per_second"] == pytest.approx(2 / 3600)


def test_lab_spec_rejects_observer_reusing_telemetry_container(monkeypatch):
    monkeypatch.setattr(
        "experiments.benchmarks.lab.inspect_owned", lambda *_args, **_kwargs: {}
    )
    shared = "a" * 64
    spec = {
        "contract": "porygon.benchmark-lab",
        "control_plane": {"backend": "b" * 64},
        "nodes": [
            {
                "host_id": "host-a",
                "target": "c" * 64,
                "telemetry": shared,
                "falco": "d" * 64,
                "observer": shared,
            }
        ],
    }
    with pytest.raises(ValueError, match="distinct containers"):
        validate_spec(spec)


def test_seven_day_soak_with_a_missing_daily_canary_bin_cannot_pass():
    trace = _trace()
    start, end = 1_000_000_000_000, 605_800_000_000_000
    trace["controller"]["controller"].update(
        {
            "started_ns": start,
            "finished_ns": end,
            "elapsed_seconds": 604_800,
            "completion_times_ns": [start + 1_000_000_000],
            "completion_records": [],
        }
    )
    trace["source"].update(
        {
            "started_ns": start,
            "finished_ns": end,
            "canary_sequences": [],
            "canary_observations": [],
        }
    )
    report = summarize_lab([trace], "soak")
    assert (
        report["daily_canary_accounting"][0]["endpoints_and_selected_canaries_observed"]
        is False
    )
    assert report["targets"]["seven_day_soak"] == "fail"


def test_full_identity_and_percentile_statements_are_exact_mode_only():
    tree = ast.parse(lab.BACKEND_QUERY)
    exact_branches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "mode == 'exact'"
    ]
    identity_branch = next(
        node
        for node in exact_branches
        if any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and isinstance(child.func.value, ast.Name)
            and child.func.value.id == "db"
            and child.func.attr == "scalars"
            and any(isinstance(arg, ast.Attribute) and arg.attr == "event_id" for arg in ast.walk(child))
            for statement in node.body
            for child in ast.walk(statement)
        )
    )
    percentile_branch = next(
        node
        for node in exact_branches
        if any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "percentile_cont"
            for statement in node.body
            for child in ast.walk(statement)
        )
    )
    assert identity_branch is not percentile_branch
    assert "identity_query_count=0" in lab.BACKEND_QUERY
    assert "percentile_query_count=0" in lab.BACKEND_QUERY


def test_assessment_coverage_grouping_reuses_projected_json_scalar():
    query = lab.BACKEND_QUERY
    tree = ast.parse(query)
    coverage_assignment = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "coverage_state"
            for target in node.targets
        )
    )
    assert ast.unparse(coverage_assignment.value) == (
        "AssessmentJob.coverage['state'].as_string().label('coverage_state')"
    )
    grouped_selects = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "group_by"
        and "joined.c.coverage_state" in ast.unparse(node)
    ]
    assert len(grouped_selects) == 2
    assert "joined.c.coverage['state']" not in query


def test_capture_marks_periodic_snapshot_and_records_zero_identity_work(monkeypatch):
    node = {
        "host_id": "host-a",
        "target": "a" * 64,
        "telemetry": "b" * 64,
        "falco": "c" * 64,
    }
    control = {"backend": "d" * 64}
    query_arguments = []

    def fake_docker(_node, *args, **_kwargs):
        script = args[4]
        if script == lab.BACKEND_QUERY:
            query_arguments.append(json.loads(args[5]))
            return json.dumps(
                {
                    "snapshot_mode": "periodic",
                    "observer_query_metrics": {
                        "identity_query_count": 0,
                        "identity_ids_materialized": 0,
                        "assessment_query_count": 3,
                        "percentile_query_count": 0,
                        "identity_query_elapsed_seconds": 0.0,
                        "assessment_query_elapsed_seconds": 0.01,
                        "snapshot_query_elapsed_seconds": 0.02,
                    },
                }
            )
        if script == lab.SPOOL_QUERY:
            return "{}"
        if script == lab.RESOURCE_QUERY:
            return "{}"
        raise AssertionError("unexpected bounded collector command")

    monkeypatch.setattr(lab, "docker", fake_docker)
    sample = lab.capture(node, 10, 20, control, mode="periodic")

    assert sample["observer_mode"] == "periodic"
    assert sample["backend"]["snapshot_mode"] == "periodic"
    assert query_arguments == [["host-a", "a" * 64, 10, 20, "periodic"]]
    assert sample["backend"]["observer_query_metrics"]["identity_ids_materialized"] == 0
    assert sample["observer_elapsed_seconds"] >= 0


@pytest.mark.parametrize(
    ("final_identity_hash", "expected_boundary", "recovery_ready"),
    [
        ("exact-source-set", "pass", True),
        ("different-final-set", "fail", True),
        (None, "unknown", True),
        ("exact-source-set", "fail", False),
    ],
)
def test_run_node_polls_cheaply_then_performs_one_exact_final_reconciliation(
    monkeypatch, tmp_path, final_identity_hash, expected_boundary, recovery_ready
):
    import experiments.benchmarks.run as runner

    start_ns = 1_000_000_000_000
    finished_ns = start_ns + 2_000_000_000
    health_before = datetime.fromtimestamp((start_ns - 1_000_000_000) / 1e9, timezone.utc)
    health_after = datetime.fromtimestamp((finished_ns + 1_000_000_000) / 1e9, timezone.utc)
    source = {
        "selected_source_records": 1,
        "id_set_sha256": "exact-source-set",
        "started_ns": start_ns,
        "finished_ns": finished_ns,
        "event_timestamps_ns": [start_ns + 500_000_000],
        "counter_resets": 0,
        "parse_errors": 0,
    }
    modes = []
    samples_seen = 0

    def fake_docker(_node, *_args, **_kwargs):
        return str(start_ns)

    def fake_source_window(_node, _seconds, _start, ready, *_args):
        ready.set()
        return source

    def fake_driver(*_args, **_kwargs):
        return {
            "controller": {
                "started_ns": start_ns,
                "finished_ns": start_ns + 1_000_000_000,
                "elapsed_seconds": 1.0,
                "failure_count": 0,
            }
        }

    def fake_capture(_node, _start, _end, _control, *, mode):
        nonlocal samples_seen
        samples_seen += 1
        modes.append(mode)
        ready_now = mode == "exact" or (recovery_ready and samples_seen > 1)
        observed_at = (health_after if ready_now else health_before).isoformat()
        backend = {
            "snapshot_mode": mode,
            "persisted": 1 if ready_now else 0,
            "assessment_jobs": 1 if ready_now else 0,
            "assessment_pending": 0,
            "health": {
                "observed_at": observed_at,
                "source_epoch": "epoch-a",
                "metrics": {"falco_drops": 0, "falco_output_drops": 0},
            },
            "observer_query_metrics": {
                "identity_query_count": 0 if mode == "periodic" else 2,
                "identity_ids_materialized": 0 if mode == "periodic" else 1,
                "assessment_query_count": 3 if mode == "periodic" else 6,
                "percentile_query_count": 0 if mode == "periodic" else 1,
                "identity_query_elapsed_seconds": 0.0,
                "assessment_query_elapsed_seconds": 0.01,
                "snapshot_query_elapsed_seconds": 0.02,
            },
        }
        telemetry = {
            "counter_epoch": "epoch-a",
            "adapter_accepted": samples_seen * 10,
            "adapter_delivered": samples_seen * 10,
            "backpressure_events": 0,
            "dead_letters": 0,
        }
        if mode == "exact" and final_identity_hash is None:
            return {
                "observer_mode": mode,
                "observer_elapsed_seconds": 0.01,
                "backend": None,
                "telemetry": telemetry,
                "resources": {},
                "failures": ["backend_unavailable"],
            }
        if mode == "exact":
            backend.update(
                {
                    "persisted_id_set_sha256": final_identity_hash,
                    "duplicate_logical_jobs": 0,
                    "assessment_completed": 1,
                    "assessment_state_counts": {"completed": 1},
                    "assessment_coverage_counts": {"available": 1},
                    "assessment_latency_p95_seconds": 2.0,
                    "assessment_latency_complete": True,
                    "negative_assessment_lag_count": 0,
                }
            )
        return {
            "observer_mode": mode,
            "observer_elapsed_seconds": 0.01,
            "backend": backend,
            "telemetry": telemetry,
            "resources": {},
            "failures": [],
        }

    monkeypatch.setattr(lab, "docker", fake_docker)
    monkeypatch.setattr(lab, "source_window", fake_source_window)
    monkeypatch.setattr(lab, "capture", fake_capture)
    monkeypatch.setattr(runner, "driver", fake_driver)
    monkeypatch.setattr(lab.time, "sleep", lambda _seconds: None)
    node = {
        "host_id": "host-a",
        "target": "a" * 64,
        "_daemon_id": "daemon-a",
        "_kernel_boot_id": "boot-a",
        "_hardware": {"logical_cpus": 4},
    }
    result = lab.run_node(
        node,
        {"backend": "b" * 64},
        "exec",
        1,
        1,
        1729,
        1,
        1 if recovery_ready else 0.001,
        tmp_path / "trace",
    )

    if final_identity_hash is None:
        assert result["failures"] == ["exact_final_backend_snapshot_unavailable"]
    elif recovery_ready:
        assert result["failures"] == []
    else:
        assert "bounded_recovery_readiness_deadline_exceeded" in result["failures"]
    assert modes.count("exact") == 1
    assert modes.count("periodic") >= 2
    assert result["observer_metrics"]["periodic_identity_query_count"] == 0
    assert result["observer_metrics"]["periodic_event_ids_materialized"] == 0
    assert result["observer_metrics"]["periodic_percentile_query_count"] == 0
    assert result["observer_metrics"]["exact_final_query_count"] == 1
    if final_identity_hash is not None:
        assert result["observer_metrics"]["exact_identity_query_count"] == 2
        assert result["observer_metrics"]["exact_event_ids_materialized"] == 1
        assert result["samples"][-1]["backend"]["assessment_latency_complete"] is True
    else:
        assert result["observer_metrics"]["exact_identity_query_count"] is None
        assert "exact_final_backend_snapshot_unavailable" in result["failures"]
    summary_node = summarize_lab([result], "exec")["nodes"][0]
    assert summary_node["matching_measured_boundaries"] == expected_boundary, summary_node
