"""Public projection preserves paired strata and abstains on unknown applets."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace

import pytest

from experiments import export_study, frozen_analysis
from experiments.frozen_statistics import summarize
from porygon_api.evaluation_routes import SnapshotIn, export_snapshot
from porygon_api.runtime_evidence import epoch_ns
from porygon_api.vulnerability import sha256_document

DIGEST = "fixture@sha256:" + "d" * 64
START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def policy():
    return {
        "contract": "porygon.frozen-analysis-policy",
        "implementation": frozen_analysis.POLICY_IMPLEMENTATION,
        "window_seconds": 60,
        "minimum_process_events": 1,
        "minimum_nonempty_windows": 1,
        "minimum_fit_runs": 10,
        "minimum_calibration_runs": 10,
        "minimum_replicas": 3,
        "scenario_horizon_seconds": 60,
        "alpha": 0.05,
        "missing_component_policy": "abstain",
        "quality_justification": "software regression fixture",
        "review_reference": "software regression fixture",
    }


def collection():
    trials = []
    snapshots = {}
    assignments = {}
    for split, count in (("fit", 10), ("calibration", 10), ("test", 2)):
        for index in range(count):
            identifier = f"{split}-{index}"
            cid = hashlib.sha256(identifier.encode()).hexdigest()
            label = "controlled-positive" if split == "test" and index else "benign"
            trial = {
                "trial_id": identifier,
                "workload_id": "WL-NGX-V1",
                "status": "completed",
                "ground_truth_class": label,
                "image": {"reference": DIGEST, "human_tag": "fixture:mutable"},
                "human_tag": "fixture:mutable",
                "runtime_context_hash": "context",
                "stratum": "WL-NGX-V1:fixture",
                "split": split,
                "docker_host_id": "private-host",
                "container_id": cid,
                "timeline": {
                    "setup_started_at_utc": START.isoformat(),
                    "cleanup_finished_at_utc": (
                        START + timedelta(minutes=2)
                    ).isoformat(),
                },
                "ground_truth": {"action_started_at_utc": START.isoformat()},
                "private_runtime_payload": "must be removed",
            }
            row = {
                "event_id": hashlib.sha256(
                    (identifier + ":event").encode()
                ).hexdigest(),
                "docker_host_id": "private-host",
                "container_id": cid,
                "time_nano": epoch_ns(START) + 1_000_000_000,
                "occurred_at": (START + timedelta(seconds=1)).isoformat(),
            }
            snapshot = {
                "contract": "porygon.frozen-study-snapshot",
                "scope": {
                    "docker_host_id": "private-host",
                    "container_id": cid,
                    "image_digest": DIGEST,
                    "start": trial["timeline"]["setup_started_at_utc"],
                    "end": trial["timeline"]["cleanup_finished_at_utc"],
                },
                "events": {"process": [row], "runtime": []},
                "selected_id_set_sha256": sha256_document([row["event_id"]]),
            }
            snapshot["sha256"] = sha256_document(snapshot)
            trials.append(trial)
            snapshots[identifier] = snapshot
            assignments[identifier] = split
    return trials, snapshots, assignments


def test_complete_paired_export_and_offline_replay_preserve_workload_identity(
    tmp_path, monkeypatch
):
    trials, snapshots, assignments = collection()

    # Exercise actual scope selection, identity guards, paired statistics,
    # public projection and replay. Feature extraction/detector accuracy are
    # independently tested; deterministic stubs keep this projection test small.
    def features(trial, snapshot, locked_policy):
        frozen_analysis.decoded_snapshot(snapshot, trial)
        return {
            "process_events": 1,
            "nonempty_windows": 1,
            "identity": (
                trial.get("workload_id"),
                trial["image"]["reference"],
                trial["runtime_context_hash"],
            ),
            "positive": trial["ground_truth_class"] == "controlled-positive",
        }

    def compare(fit, calibration, observed, locked_policy):
        return {
            name: {
                "status": "scored",
                "positive": observed["positive"],
                "p_value": 0.01 if observed["positive"] else 0.9,
            }
            for name in (*frozen_analysis.DETECTORS, *frozen_analysis.ABLATIONS)
        }

    monkeypatch.setattr(frozen_analysis, "trial_features", features)
    monkeypatch.setattr(frozen_analysis, "score_comparators", compare)
    original = frozen_analysis.evaluate_trials(trials, snapshots, assignments, policy())
    original["result_tables"] = summarize(original)
    assert all(
        row["status"] == "analysed"
        for row in original["result_tables"]["primary_contrasts"]
    )
    monkeypatch.setattr(export_study, "replay", lambda path: deepcopy(original))
    run_dir = tmp_path / "private"
    run_dir.mkdir()
    (run_dir / "trials").mkdir()
    (run_dir / "snapshots").mkdir()
    plan = {
        "entries": [
            {"trial_id": row["trial_id"], "split": row["split"]} for row in trials
        ],
        "analysis_policy": policy(),
        "plan_sha256": "e" * 64,
    }
    (run_dir / "plan.json").write_text(json.dumps(plan))
    (run_dir / "analysis.json").write_text(json.dumps(original))
    for trial in trials:
        identifier = trial["trial_id"]
        (run_dir / "trials" / (identifier + ".json")).write_text(json.dumps(trial))
        (run_dir / "snapshots" / (identifier + ".json")).write_text(
            json.dumps(snapshots[identifier])
        )
    rights = {
        "dataset_license": "CC-BY-4.0",
        "dataset_rights": "owned-or-permission-recorded",
        "approved_by": "fixture-rights-reviewer",
        "approval_reference": "fixture-only",
        "third_party": [
            {
                "name": "fixture-software",
                "license": "MIT",
                "source": "fixture-only",
                "redistributed": False,
            }
        ],
    }
    output = tmp_path / "public"
    result = export_study.export(run_dir, output, rights)
    assert result["prepared"] and not result["published"]
    exported = json.loads((output / "dataset.json").read_text())
    assert exported["result_tables"] == original["result_tables"]
    assert {row["workload_id"] for row in exported["trials"]} == {"WL-NGX-V1"}
    assert all(row["docker_host_id"] != "private-host" for row in exported["trials"])
    assert all("private_runtime_payload" not in row for row in exported["trials"])
    assert export_study.replay_public(output) == {
        "replay": "matched",
        "published": False,
    }


@pytest.mark.parametrize("binary", ["busybox", "toybox"])
@pytest.mark.parametrize(
    "arguments, available",
    [(None, False), ('"unterminated', False), ("busybox sh", True)],
)
def test_multicall_projection_retains_unknown_arguments_as_abstention(
    binary, arguments, available
):
    arguments = (
        arguments.replace("busybox", binary)
        if isinstance(arguments, str)
        else arguments
    )
    row = SimpleNamespace(
        event_id="a" * 64,
        docker_host_id="host",
        container_id="b" * 64,
        time_nano=epoch_ns(START) + 1_000_000_000,
        occurred_at=START + timedelta(seconds=1),
        process_name=binary,
        executable="/bin/" + binary,
        parent_name="init",
        parent_executable="/sbin/init",
        user_uid=1000,
        parent_event_id=None,
        command_line=arguments,
        parent_command_line=None,
    )
    channels = iter([[row], []])
    db = SimpleNamespace(scalars=lambda query: next(channels))
    payload = SnapshotIn(
        docker_host_id="host",
        container_id="b" * 64,
        image_digest=DIGEST,
        start=START,
        end=START + timedelta(seconds=60),
    )
    result = export_snapshot(payload, db)
    projected = result["events"]["process"][0]
    assert projected["rules_projection_available"] is available
    expected = binary + " sh" if available else None
    assert projected["command_line"] == expected
