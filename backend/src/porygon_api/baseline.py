from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable, Protocol

from porygon_api.command_shapes import (
    CONTRACT as COMMAND_SHAPE_CONTRACT,
    SUPPORT_AWARE_CONTRACT as SUPPORT_AWARE_COMMAND_CONTRACT,
    command_shape_counts,
    command_shape_coverage,
)

COMMAND_LINEAGE_SCHEMA = "porygon.behaviour.command-lineage"
SUPPORT_AWARE_SCHEMA = "porygon.behaviour.support-aware"
FEATURE_SCHEMA_VERSION = "porygon.behaviour.v1"
SUPPORTED_FEATURE_SCHEMAS = (
    FEATURE_SCHEMA_VERSION,
    COMMAND_LINEAGE_SCHEMA,
    SUPPORT_AWARE_SCHEMA,
)
MIN_COMMAND_COVERAGE = 0.8
MIN_SUPPORT_AWARE_BASELINE_EVENTS = 20
MAX_TEMPORAL_SEGMENTS_PER_WINDOW = 4
MAX_TEMPORAL_FEATURE_RECORDS = 4096
MAX_TEMPORAL_EVENTS = 100_000
MAX_SUPPORT_AWARE_WINDOWS = 4096
MAX_SUPPORT_AWARE_DURATION_SECONDS = 30 * 24 * 60 * 60
MAX_SUPPORT_AWARE_EVENTS = 100_000
_SHELL_NAMES = {"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh"}
_UNKNOWN = "<unknown>"


class ProcessEventLike(Protocol):
    event_id: str
    occurred_at: datetime
    container_id: str | None
    process_name: str | None
    executable: str | None
    parent_name: str | None
    parent_executable: str | None
    user_uid: int | None


class RuntimeEventLike(Protocol):
    event_id: str
    occurred_at: datetime
    container_id: str | None
    event_type: str
    action: str


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _normalise(counter: Counter[str]) -> dict[str, float]:
    total = sum(counter.values())
    if total <= 0:
        return {}
    return {key: round(counter[key] / total, 12) for key in sorted(counter)}


def command_lineage_contract() -> dict[str, Any]:
    return {
        "command_shape": deepcopy(COMMAND_SHAPE_CONTRACT),
        "sequence": "verified-parent-links-within-host-container-sensor-window",
        "minimum_command_coverage": MIN_COMMAND_COVERAGE,
    }


def support_aware_contract() -> dict[str, Any]:
    return {
        "command_shape": deepcopy(SUPPORT_AWARE_COMMAND_CONTRACT),
        "sequence": "verified-parent-links-within-host-container-sensor-window",
        "minimum_usable_command_coverage": MIN_COMMAND_COVERAGE,
        "minimum_baseline_process_events": MIN_SUPPORT_AWARE_BASELINE_EVENTS,
        "temporal_segments_per_window": MAX_TEMPORAL_SEGMENTS_PER_WINDOW,
        "maximum_temporal_feature_records": MAX_TEMPORAL_FEATURE_RECORDS,
        "maximum_temporal_events": MAX_TEMPORAL_EVENTS,
        "maximum_profile_windows": MAX_SUPPORT_AWARE_WINDOWS,
        "maximum_profile_duration_seconds": MAX_SUPPORT_AWARE_DURATION_SECONDS,
        "maximum_profile_events": MAX_SUPPORT_AWARE_EVENTS,
        "windows_are_independent_runs": False,
    }


def validate_support_aware_bounds(
    start_at: datetime,
    end_at: datetime,
    window_seconds: int,
    *,
    process_event_count: int = 0,
    runtime_event_count: int = 0,
) -> int:
    """Reject oversized modern profile intervals before allocating per-window lists."""
    duration_seconds = (end_at - start_at).total_seconds()
    if duration_seconds <= 0 or window_seconds <= 0:
        raise ValueError("Profile interval and window duration must be positive")
    if duration_seconds > MAX_SUPPORT_AWARE_DURATION_SECONDS:
        raise ValueError("Support-aware profile duration exceeds its bounded contract")
    window_count = max(1, math.ceil(duration_seconds / window_seconds))
    if window_count > MAX_SUPPORT_AWARE_WINDOWS:
        raise ValueError("Support-aware profile window count exceeds its bounded contract")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (process_event_count, runtime_event_count)
    ):
        raise ValueError("Support-aware profile event counts are invalid")
    if process_event_count + runtime_event_count > MAX_SUPPORT_AWARE_EVENTS:
        raise ValueError("Support-aware profile event count exceeds its bounded contract")
    return window_count


def _token(value: str | None) -> str:
    rendered = (value or "").strip()
    return rendered if rendered else _UNKNOWN


def _process_token(event: ProcessEventLike) -> str:
    return _token(event.executable or event.process_name)


def _parent_token(event: ProcessEventLike) -> str:
    return _token(event.parent_executable or event.parent_name)


def _nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return float(ordered[rank - 1])


def _summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0, "p95": 0.0, "stddev": 0.0}
    return {
        "min": round(float(min(values)), 12),
        "max": round(float(max(values)), 12),
        "mean": round(float(statistics.fmean(values)), 12),
        "median": round(float(statistics.median(values)), 12),
        "p95": round(_nearest_rank(values, 0.95), 12),
        "stddev": round(float(statistics.pstdev(values)), 12),
    }


def _window_index(occurred_at: datetime, start_at: datetime, window_seconds: int) -> int:
    offset = (occurred_at - start_at).total_seconds()
    return max(0, int(offset // window_seconds))


def _event_set_hash(
    process_events: Iterable[ProcessEventLike], runtime_events: Iterable[RuntimeEventLike]
) -> str:
    identities = [f"process:{event.event_id}" for event in process_events]
    identities.extend(f"runtime:{event.event_id}" for event in runtime_events)
    return hashlib.sha256("\n".join(sorted(identities)).encode("utf-8")).hexdigest()


def _support_aware_temporal_features(
    *,
    start_at: datetime,
    end_at: datetime,
    window_seconds: int,
    process_windows: list[list[ProcessEventLike]],
    runtime_windows: list[list[RuntimeEventLike]],
    process_events: list[ProcessEventLike],
) -> tuple[list[dict[str, Any]], bool]:
    """Build bounded event-bearing subwindows; these are not independent runs."""

    if sum(map(len, process_windows)) + sum(map(len, runtime_windows)) > MAX_TEMPORAL_EVENTS:
        return [], True
    segments = min(MAX_TEMPORAL_SEGMENTS_PER_WINDOW, max(1, window_seconds // 5))
    segment_seconds = window_seconds / segments
    by_id = {event.event_id: event for event in process_events}
    documents: list[dict[str, Any]] = []
    for window_index, (proc_window, runtime_window) in enumerate(
        zip(process_windows, runtime_windows)
    ):
        proc_segments: list[list[ProcessEventLike]] = [[] for _ in range(segments)]
        runtime_segments: list[list[RuntimeEventLike]] = [[] for _ in range(segments)]
        window_start = start_at.timestamp() + window_index * window_seconds
        for event in proc_window:
            offset = event.occurred_at.timestamp() - window_start
            segment_index = min(max(int(offset // segment_seconds), 0), segments - 1)
            proc_segments[segment_index].append(event)
        for event in runtime_window:
            offset = event.occurred_at.timestamp() - window_start
            segment_index = min(max(int(offset // segment_seconds), 0), segments - 1)
            runtime_segments[segment_index].append(event)

        for segment_index, (proc_items, runtime_items) in enumerate(
            zip(proc_segments, runtime_segments)
        ):
            if not proc_items and not runtime_items:
                continue
            process_name_counts: Counter[str] = Counter()
            executable_counts: Counter[str] = Counter()
            parent_child_counts: Counter[str] = Counter()
            uid_counts: Counter[str] = Counter()
            runtime_action_counts: Counter[str] = Counter()
            sequence_counts: Counter[str] = Counter()
            command_counts: Counter[str] = Counter()
            command_coverage: Counter[str] = Counter()
            item_ids = {event.event_id for event in proc_items}
            for event in proc_items:
                process_name_counts[_token(event.process_name)] += 1
                executable_counts[_process_token(event)] += 1
                parent_child_counts[
                    f"{_parent_token(event)} -> {_process_token(event)}"
                ] += 1
                uid_counts[str(event.user_uid) if event.user_uid is not None else _UNKNOWN] += 1
                shapes, coverage = command_shape_coverage(
                    getattr(event, "command_line", None)
                )
                command_counts.update(shapes)
                command_coverage[coverage] += 1
                parent = by_id.get(getattr(event, "parent_event_id", None))
                if parent is None or parent.event_id not in item_ids or parent is event:
                    continue
                scope_fields = ("container_id", "docker_host_id", "sensor_instance_id")
                if not all(
                    getattr(event, field, None)
                    and getattr(event, field, None) == getattr(parent, field, None)
                    for field in scope_fields
                ):
                    continue
                if parent.occurred_at > event.occurred_at:
                    continue
                sequence_counts[
                    f"{_process_token(parent)} -> {_process_token(event)}"
                ] += 1
            for event in runtime_items:
                runtime_action_counts[f"{event.event_type}:{event.action}"] += 1

            counters = {
                "process_name": process_name_counts,
                "executable": executable_counts,
                "parent_child": parent_child_counts,
                "user_uid": uid_counts,
                "runtime_action": runtime_action_counts,
                "process_sequence_bigram": sequence_counts,
                "command_shape": command_counts,
            }
            segment_start = datetime.fromtimestamp(
                window_start + segment_index * segment_seconds, tz=start_at.tzinfo
            )
            segment_end = datetime.fromtimestamp(
                min(
                    window_start + (segment_index + 1) * segment_seconds,
                    end_at.timestamp(),
                ),
                tz=start_at.tzinfo,
            )
            documents.append(
                {
                    "window_index": window_index,
                    "segment_index": segment_index,
                    "start_at": segment_start.isoformat(),
                    "end_at": segment_end.isoformat(),
                    "process_event_count": len(proc_items),
                    "runtime_event_count": len(runtime_items),
                    "categorical_counts": {
                        family: dict(sorted(counter.items()))
                        for family, counter in counters.items()
                    },
                    "command_coverage": dict(sorted(command_coverage.items())),
                }
            )
            if len(documents) > MAX_TEMPORAL_FEATURE_RECORDS:
                return [], True
    return documents, False


def _support_aware_metadata(
    *,
    categorical_counts: dict[str, Counter[str]],
    process_event_count: int,
    runtime_event_count: int,
    command_coverage: Counter[str],
    family_event_counts: dict[str, int],
    temporal_windows: list[dict[str, Any]],
    temporal_limit_exceeded: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    family_support: dict[str, Any] = {}
    for family, counter in categorical_counts.items():
        total = sum(counter.values())
        unknown = sum(
            value
            for token, value in counter.items()
            if token == _UNKNOWN
            or token.startswith("syntax:oov-")
            or token.startswith(_UNKNOWN + " ->")
            or token.endswith(" -> " + _UNKNOWN)
        )
        if family == "command_shape":
            missing = command_coverage.get("unavailable", 0)
        elif family == "parent_child":
            missing = sum(
                value
                for token, value in counter.items()
                if token.startswith(_UNKNOWN + " ->")
            )
        else:
            missing = counter.get(_UNKNOWN, 0)
        family_support[family] = {
            "raw_count": total,
            "contributing_event_count": family_event_counts.get(family, 0),
            "token_mass": total,
            "missing_count": missing,
            "unknown_count": unknown,
            "unknown_fraction": round(unknown / total, 12) if total else None,
        }
    denominator = process_event_count
    coverage = {
        "process_events": denominator,
        "command_present_events": sum(
            command_coverage.get(key, 0) for key in ("usable", "fallback")
        ),
        "command_usable_events": command_coverage.get("usable", 0),
        "command_fallback_events": command_coverage.get("fallback", 0),
        "command_unavailable_events": command_coverage.get("unavailable", 0),
        "command_present_fraction": round(
            (command_coverage.get("usable", 0) + command_coverage.get("fallback", 0))
            / denominator,
            12,
        )
        if denominator
        else 0.0,
        "command_usable_fraction": round(
            command_coverage.get("usable", 0) / denominator, 12
        )
        if denominator
        else 0.0,
        "runtime_events": runtime_event_count,
        "temporal_window_count": len(temporal_windows),
        "temporal_limit_exceeded": temporal_limit_exceeded,
        "windows_are_independent_runs": False,
    }
    return family_support, coverage


def build_profile_document(
    *,
    image_digest: str,
    start_at: datetime,
    end_at: datetime,
    window_seconds: int,
    process_events: list[ProcessEventLike],
    runtime_events: list[RuntimeEventLike],
    minimum_process_events: int,
    minimum_nonempty_windows: int,
    feature_schema_version: str = FEATURE_SCHEMA_VERSION,
    include_temporal_windows: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    """Build a deterministic digest-bound behavioural profile.

    The function deliberately performs no anomaly scoring. It converts an explicitly
    approved training interval into distributions, observed sets, per-window numeric
    summaries, a quality report, and a reproducibility manifest.
    """

    if feature_schema_version not in SUPPORTED_FEATURE_SCHEMAS:
        raise ValueError("Unsupported feature schema")

    duration_seconds = (end_at - start_at).total_seconds()
    if duration_seconds <= 0:
        raise ValueError("end_at must be after start_at")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    window_count = max(1, math.ceil(duration_seconds / window_seconds))
    if feature_schema_version == SUPPORT_AWARE_SCHEMA:
        window_count = validate_support_aware_bounds(
            start_at,
            end_at,
            window_seconds,
            process_event_count=len(process_events),
            runtime_event_count=len(runtime_events),
        )
        if any(
            event.occurred_at < start_at or event.occurred_at >= end_at
            for event in process_events
        ) or any(
            event.occurred_at < start_at or event.occurred_at >= end_at
            for event in runtime_events
        ):
            raise ValueError("Support-aware events must lie within the selected interval")
    process_windows: list[list[ProcessEventLike]] = [[] for _ in range(window_count)]
    runtime_windows: list[list[RuntimeEventLike]] = [[] for _ in range(window_count)]

    process_name_counts: Counter[str] = Counter()
    executable_counts: Counter[str] = Counter()
    parent_child_counts: Counter[str] = Counter()
    uid_counts: Counter[str] = Counter()
    runtime_action_counts: Counter[str] = Counter()
    sequence_bigram_counts: Counter[str] = Counter()
    processes_by_container: dict[str, list[ProcessEventLike]] = defaultdict(list)

    container_ids: set[str] = set()
    process_times: list[datetime] = []
    runtime_times: list[datetime] = []

    for event in process_events:
        index = min(_window_index(event.occurred_at, start_at, window_seconds), window_count - 1)
        process_windows[index].append(event)
        process_name_counts[_token(event.process_name)] += 1
        executable_counts[_process_token(event)] += 1
        parent_child_counts[f"{_parent_token(event)} -> {_process_token(event)}"] += 1
        uid_counts[str(event.user_uid) if event.user_uid is not None else _UNKNOWN] += 1
        process_times.append(event.occurred_at)
        if event.container_id:
            container_ids.add(event.container_id)
            processes_by_container[event.container_id].append(event)

    for event in runtime_events:
        index = min(_window_index(event.occurred_at, start_at, window_seconds), window_count - 1)
        runtime_windows[index].append(event)
        runtime_action_counts[f"{event.event_type}:{event.action}"] += 1
        runtime_times.append(event.occurred_at)
        if event.container_id:
            container_ids.add(event.container_id)

    command_counts: Counter[str] = Counter()
    command_events = 0
    lineage_edges = 0
    support_command_coverage: Counter[str] = Counter()
    if feature_schema_version in (COMMAND_LINEAGE_SCHEMA, SUPPORT_AWARE_SCHEMA):
        for event in process_events:
            if feature_schema_version == SUPPORT_AWARE_SCHEMA:
                shapes, coverage = command_shape_coverage(
                    getattr(event, "command_line", None)
                )
                support_command_coverage[coverage] += 1
            else:
                shapes = command_shape_counts(getattr(event, "command_line", None))
            command_counts.update(shapes)
            if shapes:
                command_events += 1
        # Only observed direct ancestry, in the same source/host/container/window,
        # supports a causal pair. Session membership is not direct ancestry.
        by_id = {event.event_id: event for event in process_events}
        for child in process_events:
            parent = by_id.get(getattr(child, "parent_event_id", None))
            if parent is None or parent is child:
                continue
            scope_fields = ("container_id", "docker_host_id", "sensor_instance_id")
            if not all(
                getattr(child, field, None)
                and getattr(child, field, None) == getattr(parent, field, None)
                for field in scope_fields
            ):
                continue
            if parent.occurred_at > child.occurred_at:
                continue
            if _window_index(parent.occurred_at, start_at, window_seconds) != _window_index(
                child.occurred_at, start_at, window_seconds
            ):
                continue
            sequence_bigram_counts[f"{_process_token(parent)} -> {_process_token(child)}"] += 1
            lineage_edges += 1
    else:
        for events in processes_by_container.values():
            ordered = sorted(events, key=lambda item: (item.occurred_at, item.event_id))
            tokens = [_process_token(item) for item in ordered]
            for left, right in zip(tokens, tokens[1:]):
                sequence_bigram_counts[f"{left} -> {right}"] += 1
    process_rate: list[float] = []
    runtime_rate: list[float] = []
    distinct_processes: list[float] = []
    root_ratios: list[float] = []
    shell_ratios: list[float] = []
    nonempty_windows = 0
    minutes_per_window = window_seconds / 60.0

    for proc_window, runtime_window in zip(process_windows, runtime_windows):
        if proc_window or runtime_window:
            nonempty_windows += 1
        process_rate.append(len(proc_window) / minutes_per_window)
        runtime_rate.append(len(runtime_window) / minutes_per_window)
        distinct_processes.append(float(len({_process_token(event) for event in proc_window})))
        if proc_window:
            root_ratios.append(sum(event.user_uid == 0 for event in proc_window) / len(proc_window))
            shell_ratios.append(
                sum(
                    (event.process_name or "").lower() in _SHELL_NAMES
                    or _process_token(event).rsplit("/", 1)[-1].lower() in _SHELL_NAMES
                    for event in proc_window
                )
                / len(proc_window)
            )
        else:
            root_ratios.append(0.0)
            shell_ratios.append(0.0)

    features = {
        "schema_version": feature_schema_version,
        "categorical_distributions": {
            "process_name": _normalise(process_name_counts),
            "executable": _normalise(executable_counts),
            "parent_child": _normalise(parent_child_counts),
            "user_uid": _normalise(uid_counts),
            "runtime_action": _normalise(runtime_action_counts),
            "process_sequence_bigram": _normalise(sequence_bigram_counts),
        },
        "observed_sets": {
            "process_names": sorted(process_name_counts),
            "executables": sorted(executable_counts),
            "parent_child_edges": sorted(parent_child_counts),
            "user_uids": sorted(uid_counts),
            "runtime_actions": sorted(runtime_action_counts),
            "process_sequence_bigrams": sorted(sequence_bigram_counts),
        },
        "numeric_summaries": {
            "process_events_per_minute": _summary(process_rate),
            "runtime_events_per_minute": _summary(runtime_rate),
            "distinct_processes_per_window": _summary(distinct_processes),
            "root_process_ratio": _summary(root_ratios),
            "shell_process_ratio": _summary(shell_ratios),
        },
    }

    if feature_schema_version in (COMMAND_LINEAGE_SCHEMA, SUPPORT_AWARE_SCHEMA):
        features["extractor_contract_sha256"] = _sha256_json(command_lineage_contract())
        features["categorical_distributions"]["command_shape"] = _normalise(command_counts)
        features["observed_sets"]["command_shapes"] = sorted(command_counts)
        features["observation_coverage"] = {
            "command_events": command_events,
            "command_event_fraction": round(command_events / len(process_events), 12)
            if process_events
            else 0.0,
            "verified_lineage_edges": lineage_edges,
        }

    temporal_windows: list[dict[str, Any]] = []
    support_coverage: dict[str, Any] | None = None
    if feature_schema_version == SUPPORT_AWARE_SCHEMA:
        support_counters = {
            "process_name": process_name_counts,
            "executable": executable_counts,
            "parent_child": parent_child_counts,
            "user_uid": uid_counts,
            "runtime_action": runtime_action_counts,
            "process_sequence_bigram": sequence_bigram_counts,
            "command_shape": command_counts,
        }
        temporal_limit_exceeded = False
        if include_temporal_windows:
            temporal_windows, temporal_limit_exceeded = _support_aware_temporal_features(
                start_at=start_at,
                end_at=end_at,
                window_seconds=window_seconds,
                process_windows=process_windows,
                runtime_windows=runtime_windows,
                process_events=process_events,
            )
        family_support, support_coverage = _support_aware_metadata(
            categorical_counts=support_counters,
            process_event_count=len(process_events),
            runtime_event_count=len(runtime_events),
            command_coverage=support_command_coverage,
            family_event_counts={
                "process_name": len(process_events),
                "executable": len(process_events),
                "parent_child": len(process_events),
                "user_uid": len(process_events),
                "runtime_action": len(runtime_events),
                "process_sequence_bigram": lineage_edges,
                "command_shape": support_command_coverage.get("usable", 0),
            },
            temporal_windows=temporal_windows,
            temporal_limit_exceeded=temporal_limit_exceeded,
        )
        features["extractor_contract_sha256"] = _sha256_json(support_aware_contract())
        features["categorical_counts"] = {
            family: dict(sorted(counter.items()))
            for family, counter in support_counters.items()
        }
        features["categorical_distributions"]["command_shape"] = _normalise(command_counts)
        features["observed_sets"]["command_shapes"] = sorted(command_counts)
        features["feature_support"] = {
            "families": family_support,
            "process_event_count": len(process_events),
            "runtime_event_count": len(runtime_events),
            "fitted_window_count": window_count,
            "nonempty_window_count": nonempty_windows,
            "windows_are_independent_runs": False,
        }
        features["observation_coverage"] = support_coverage
        features["temporal_windows"] = temporal_windows

    checks = {
        "minimum_process_events": {
            "required": minimum_process_events,
            "actual": len(process_events),
            "passed": len(process_events) >= minimum_process_events,
        },
        "minimum_nonempty_windows": {
            "required": minimum_nonempty_windows,
            "actual": nonempty_windows,
            "passed": nonempty_windows >= minimum_nonempty_windows,
        },
        "immutable_image_digest": {
            "required": True,
            "actual": bool(image_digest),
            "passed": bool(image_digest),
        },
    }
    if feature_schema_version == COMMAND_LINEAGE_SCHEMA:
        checks["command_line_coverage"] = {
            "required": MIN_COMMAND_COVERAGE,
            "actual": features["observation_coverage"]["command_event_fraction"],
            "passed": features["observation_coverage"]["command_event_fraction"]
            >= MIN_COMMAND_COVERAGE,
        }
    if feature_schema_version == SUPPORT_AWARE_SCHEMA:
        usable_fraction = support_coverage["command_usable_fraction"]
        checks["support_aware_minimum_events"] = {
            "required": MIN_SUPPORT_AWARE_BASELINE_EVENTS,
            "actual": len(process_events),
            "passed": len(process_events) >= MIN_SUPPORT_AWARE_BASELINE_EVENTS,
        }
        checks["usable_command_coverage"] = {
            "required": MIN_COMMAND_COVERAGE,
            "actual": usable_fraction,
            "passed": usable_fraction >= MIN_COMMAND_COVERAGE,
        }
    warnings: list[str] = []
    if len(container_ids) < 2:
        warnings.append(
            "Training data contains fewer than two distinct containers; host-specific behaviour may be overrepresented."
        )
    if not runtime_events:
        warnings.append("No Docker lifecycle events were present in the approved interval.")
    if len(sequence_bigram_counts) == 0:
        warnings.append(
            "No process-sequence bigrams were observed; sequence modelling will have no baseline support."
        )

    quality = {
        "passed": all(check["passed"] for check in checks.values()),
        "checks": checks,
        "warnings": warnings,
    }

    manifest = {
        "feature_schema_version": feature_schema_version,
        "image_digest": image_digest,
        "training_start": start_at.isoformat(),
        "training_end": end_at.isoformat(),
        "duration_seconds": round(duration_seconds, 6),
        "window_seconds": window_seconds,
        "window_count": window_count,
        "nonempty_window_count": nonempty_windows,
        "process_event_count": len(process_events),
        "runtime_event_count": len(runtime_events),
        "container_count": len(container_ids),
        "container_ids": sorted(container_ids),
        "first_process_event_at": min(process_times).isoformat() if process_times else None,
        "last_process_event_at": max(process_times).isoformat() if process_times else None,
        "first_runtime_event_at": min(runtime_times).isoformat() if runtime_times else None,
        "last_runtime_event_at": max(runtime_times).isoformat() if runtime_times else None,
        "selected_event_ids_sha256": _event_set_hash(process_events, runtime_events),
    }

    if feature_schema_version == COMMAND_LINEAGE_SCHEMA:
        manifest["feature_contract"] = command_lineage_contract()
        manifest["observation_coverage"] = features["observation_coverage"]
        manifest["feature_document_sha256"] = _sha256_json(features)
    elif feature_schema_version == SUPPORT_AWARE_SCHEMA:
        manifest["feature_contract"] = support_aware_contract()
        manifest["observation_coverage"] = support_coverage
        manifest["feature_document_sha256"] = _sha256_json(features)

    model_hash = _sha256_json(
        {
            "image_digest": image_digest,
            "features": features,
            "quality": quality,
            "manifest": manifest,
        }
    )
    return features, quality, manifest, model_hash
