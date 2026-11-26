"""Support-aware scoring for the descriptive support-aware feature contract."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any


def _validated_counts(document: dict[str, Any], config: dict[str, Any]) -> dict[str, dict[str, int]]:
    from porygon_api.scoring import sha256_json

    if document.get("extractor_contract_sha256") != sha256_json(
        config["feature_extractor_contract"]
    ):
        raise ValueError("Unsupported support-aware extractor contract")
    raw = document.get("categorical_counts")
    feature_support = document.get("feature_support")
    if not isinstance(feature_support, dict):
        raise ValueError("Support-aware feature support is unavailable")
    support = feature_support.get("families")
    if not isinstance(raw, dict) or not isinstance(support, dict):
        raise ValueError("Support-aware feature counts are unavailable")
    expected_families = set(config["categorical_weights"])
    if set(raw) != expected_families or set(support) != expected_families:
        raise ValueError("Support-aware feature families are incompatible")
    validated: dict[str, dict[str, int]] = {}
    for family in sorted(expected_families):
        family_counts = raw[family]
        family_support = support[family]
        if not isinstance(family_counts, dict) or not isinstance(family_support, dict):
            raise ValueError("Support-aware family counts are malformed")
        counts: dict[str, int] = {}
        for token, count in family_counts.items():
            if not isinstance(token, str) or isinstance(count, bool):
                raise ValueError("Support-aware family counts are malformed")
            if not isinstance(count, (int, float)) or not math.isfinite(float(count)):
                raise ValueError("Support-aware family counts must be finite")
            if count < 0 or int(count) != count:
                raise ValueError("Support-aware family counts must be non-negative integers")
            counts[token] = int(count)
        token_mass = sum(counts.values())
        for field in ("token_mass", "raw_count", "missing_count", "unknown_count", "contributing_event_count"):
            value = family_support.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("Support-aware family support is invalid")
        if family_support.get("token_mass") != token_mass or family_support.get("raw_count") != token_mass:
            raise ValueError("Support-aware feature support does not match token counts")
        validated[family] = counts
    distributions = document.get("categorical_distributions")
    if not isinstance(distributions, dict):
        raise ValueError("Support-aware feature distributions are malformed")
    for family in sorted(expected_families):
        counts = validated[family]
        family_support = support[family]
        token_mass = family_support["token_mass"]
        expected_distribution = (
            {token: round(count / token_mass, 12) for token, count in sorted(counts.items())}
            if token_mass
            else {}
        )
        if distributions.get(family) != expected_distribution:
            raise ValueError("Support-aware distribution does not match feature counts")
    return validated


def _support_events(document: dict[str, Any], family: str) -> int:
    support = document["feature_support"]["families"][family]
    value = support.get("contributing_event_count")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Support-aware contributing-event count is invalid")
    return value


def _js_components(
    baseline_counts: dict[str, int],
    observed_counts: dict[str, int],
    *,
    alpha: float,
    max_support: int,
) -> tuple[float, list[dict[str, Any]]]:
    baseline_total = sum(baseline_counts.values())
    observed_total = sum(observed_counts.values())
    if baseline_total <= 0 or observed_total <= 0:
        raise ValueError("Jensen-Shannon comparison requires positive support")
    union_tokens = set(baseline_counts) | set(observed_counts)
    baseline_tokens = sorted(
        union_tokens,
        key=lambda token: (
            -(baseline_counts.get(token, 0) + observed_counts.get(token, 0)),
            token,
        ),
    )[:max_support]
    positions = {token: index for index, token in enumerate(baseline_tokens)}
    p_counts = [0] * (len(baseline_tokens) + 1)
    q_counts = [0] * (len(baseline_tokens) + 1)
    for token, count in baseline_counts.items():
        p_counts[positions.get(token, len(baseline_tokens))] += count
    for token, count in observed_counts.items():
        q_counts[positions.get(token, len(baseline_tokens))] += count

    # A fixed-total uniform prior is mixed with empirical mass. Tokens outside
    # the retained top-K union are pooled into OTHER, preserving their observed
    # mass without letting attacker-controlled vocabulary grow the prior.
    categories = len(p_counts)
    prior_weight = alpha / (min(baseline_total, observed_total) + alpha)
    empirical_weight = 1.0 - prior_weight
    uniform_prior = 1.0 / categories
    p = [
        empirical_weight * (count / baseline_total) + prior_weight * uniform_prior
        for count in p_counts
    ]
    q = [
        empirical_weight * (count / observed_total) + prior_weight * uniform_prior
        for count in q_counts
    ]
    midpoint = [(left + right) / 2.0 for left, right in zip(p, q)]
    divergence_parts = [
        0.5 * left * math.log2(left / middle)
        + 0.5 * right * math.log2(right / middle)
        for left, right, middle in zip(p, q, midpoint)
    ]
    divergence = max(0.0, min(1.0, sum(divergence_parts)))
    rows = []
    for index, (left, right, contribution) in enumerate(zip(p, q, divergence_parts)):
        token = baseline_tokens[index] if index < len(baseline_tokens) else "other (bounded tail)"
        rows.append(
            {
                "token": token,
                "baseline_probability": round(left, 12),
                "observed_probability": round(right, 12),
                "probability_delta": round(right - left, 12),
                "divergence_contribution": round(max(0.0, contribution), 12),
            }
        )
    rows.sort(key=lambda row: (-row["divergence_contribution"], row["token"]))
    return round(math.sqrt(divergence), 12), rows[:12]


def _novelty_mass(baseline: dict[str, int], observed: dict[str, int]) -> tuple[float, list[dict[str, Any]]]:
    total = sum(observed.values())
    if total <= 0:
        return 0.0, []
    rows = [
        {"token": token, "proportion": round(count / total, 12)}
        for token, count in observed.items()
        if token not in baseline and count > 0
    ]
    rows.sort(key=lambda row: (-row["proportion"], row["token"]))
    return round(sum(row["proportion"] for row in rows), 12), rows[:25]


def _score_temporal_windows(
    *,
    baseline_counts: dict[str, dict[str, int]],
    baseline_support: dict[str, Any],
    observation: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    from porygon_api.scoring import _weighted_average

    coverage = observation.get("observation_coverage", {})
    if coverage.get("temporal_limit_exceeded") is True:
        return {
            "status": "insufficient_support",
            "reason": "temporal_feature_record_limit_exceeded",
            "peak_score": None,
            "supported_window_count": 0,
            "rejected_window_count": 0,
            "peak": None,
            "uncalibrated_maximum": True,
        }
    temporal_rows = observation.get("temporal_windows", [])
    if not isinstance(temporal_rows, list):
        raise ValueError("Support-aware temporal windows are malformed")
    if len(temporal_rows) > config["maximum_temporal_feature_records"]:
        raise ValueError("Support-aware temporal feature record bound was exceeded")
    feature_support = observation.get("feature_support", {})
    process_total = feature_support.get("process_event_count")
    runtime_total = feature_support.get("runtime_event_count")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (process_total, runtime_total)
    ):
        raise ValueError("Support-aware temporal document event counts are invalid")
    if process_total + runtime_total > config["maximum_temporal_events"] and not coverage.get("temporal_limit_exceeded"):
        raise ValueError("Support-aware temporal event bound was not recorded")
    for row in temporal_rows:
        if not isinstance(row, dict):
            raise ValueError("Support-aware temporal window is malformed")
        for field in ("process_event_count", "runtime_event_count"):
            value = row.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("Support-aware temporal event count is invalid")
    if not coverage.get("temporal_limit_exceeded") and temporal_rows:
        if sum(row.get("process_event_count", 0) for row in temporal_rows) != process_total:
            raise ValueError("Support-aware temporal process counts do not reconcile")
        if sum(row.get("runtime_event_count", 0) for row in temporal_rows) != runtime_total:
            raise ValueError("Support-aware temporal runtime counts do not reconcile")
    eligible_windows = []
    rejected_windows = 0
    minimum_family_events = config["temporal_minimum_family_events"]
    for row in temporal_rows:
        if not isinstance(row, dict):
            raise ValueError("Support-aware temporal window is malformed")
        event_count = row.get("process_event_count")
        if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 0:
            raise ValueError("Support-aware temporal event count is invalid")
        try:
            start_at = datetime.fromisoformat(row["start_at"])
            end_at = datetime.fromisoformat(row["end_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Support-aware temporal time bounds are invalid") from exc
        if end_at <= start_at:
            raise ValueError("Support-aware temporal window must have positive duration")
        if event_count < config["minimum_observed_process_events"]:
            rejected_windows += 1
            continue
        counts_by_family = row.get("categorical_counts")
        if not isinstance(counts_by_family, dict) or set(counts_by_family) != set(config["categorical_weights"]):
            raise ValueError("Support-aware temporal families are incompatible")
        command_coverage = row.get("command_coverage")
        if not isinstance(command_coverage, dict):
            raise ValueError("Support-aware temporal command coverage is malformed")
        coverage_counts = [
            command_coverage.get("usable", 0),
            command_coverage.get("fallback", 0),
            command_coverage.get("unavailable", 0),
        ]
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in coverage_counts
        ) or sum(coverage_counts) != event_count:
            raise ValueError("Support-aware temporal command coverage is inconsistent")
        values: dict[str, float] = {}
        details = []
        for family, weights in config["categorical_weights"].items():
            window_counts = counts_by_family[family]
            if not isinstance(window_counts, dict):
                raise ValueError("Support-aware temporal family counts are malformed")
            normalized_counts: dict[str, int] = {}
            for token, count in window_counts.items():
                if not isinstance(token, str) or isinstance(count, bool):
                    raise ValueError("Support-aware temporal family counts are malformed")
                if not isinstance(count, int) or count < 0:
                    raise ValueError("Support-aware temporal family counts are invalid")
                normalized_counts[token] = count
            if _support_events_from_record(baseline_support.get(family, {})) < config["minimum_baseline_family_events"]:
                continue
            family_events = (
                coverage_counts[0]
                if family == "command_shape"
                else sum(window_counts.values())
            )
            if family_events < minimum_family_events:
                continue
            score, tokens = _js_components(
                baseline_counts[family],
                normalized_counts,
                alpha=config["dirichlet_smoothing_alpha"],
                max_support=config["max_baseline_support_tokens"],
            )
            values[family] = score
            details.append({"family": family, "distance": score, "top_token_contributions": tokens[:5]})
        if len(values) < config["minimum_eligible_families"]:
            rejected_windows += 1
            continue
        score, effective = _weighted_average(values, config["categorical_weights"])
        eligible_windows.append(
            {
                "score": score,
                "start_at": row.get("start_at"),
                "end_at": row.get("end_at"),
                "window_index": row.get("window_index"),
                "segment_index": row.get("segment_index"),
                "process_event_count": event_count,
                "eligible_families": sorted(values),
                "effective_family_weights": effective,
                "families": sorted(details, key=lambda item: (-item["distance"], item["family"])),
            }
        )
    eligible_windows.sort(
        key=lambda item: (-item["score"], item["start_at"] or "", item["end_at"] or "", item["window_index"], item["segment_index"])
    )
    if not eligible_windows:
        return {
            "status": "insufficient_support",
            "peak_score": None,
            "supported_window_count": 0,
            "rejected_window_count": rejected_windows,
            "peak": None,
            "uncalibrated_maximum": True,
        }
    return {
        "status": "supported",
        "peak_score": eligible_windows[0]["score"],
        "supported_window_count": len(eligible_windows),
        "rejected_window_count": rejected_windows,
        "peak": eligible_windows[0],
        "uncalibrated_maximum": True,
    }


def _support_events_from_record(support: dict[str, Any]) -> int:
    value = support.get("contributing_event_count")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def score_support_aware_feature_documents(
    *,
    baseline_features: dict[str, Any],
    observation_features: dict[str, Any],
    config: dict[str, Any],
) -> tuple[float | None, str, dict[str, Any], dict[str, Any]]:
    from porygon_api.scoring import _numeric_deviation, _round, _weighted_average, score_band

    baseline_counts = _validated_counts(baseline_features, config)
    observation_counts = _validated_counts(observation_features, config)
    baseline_support = baseline_features["feature_support"].get("families", {})
    observation_support = observation_features["feature_support"].get("families", {})
    baseline_feature_support = baseline_features["feature_support"]
    observation_feature_support = observation_features["feature_support"]
    baseline_process_events = baseline_feature_support.get("process_event_count")
    observation_process_events = observation_feature_support.get("process_event_count")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (baseline_process_events, observation_process_events)
    ):
        raise ValueError("Support-aware process-event support is invalid")
    baseline_coverage = baseline_features.get("observation_coverage", {})
    observation_coverage = observation_features.get("observation_coverage", {})
    for coverage in (baseline_coverage, observation_coverage):
        if not isinstance(coverage, dict):
            raise ValueError("Support-aware command coverage is malformed")
        fraction = coverage.get("command_usable_fraction")
        if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not math.isfinite(float(fraction)) or not 0.0 <= fraction <= 1.0:
            raise ValueError("Support-aware command coverage is invalid")
        process_count = coverage.get("process_events")
        count_fields = (
            "command_present_events",
            "command_usable_events",
            "command_fallback_events",
            "command_unavailable_events",
        )
        if isinstance(process_count, bool) or not isinstance(process_count, int) or process_count < 0:
            raise ValueError("Support-aware process coverage is invalid")
        counts = [coverage.get(field) for field in count_fields]
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise ValueError("Support-aware command coverage counts are invalid")
        present, usable, fallback, unavailable = counts
        if present != usable + fallback or process_count != usable + fallback + unavailable:
            raise ValueError("Support-aware command coverage counts are inconsistent")
        expected_usable_fraction = round(usable / process_count, 12) if process_count else 0.0
        if round(float(fraction), 12) != expected_usable_fraction:
            raise ValueError("Support-aware command coverage fraction is inconsistent")
        if process_count != (
            baseline_process_events
            if coverage is baseline_coverage
            else observation_process_events
        ):
            raise ValueError("Support-aware command coverage does not match process support")
    missing_reasons = []
    if baseline_process_events < config["minimum_baseline_process_events"]:
        missing_reasons.append("baseline_process_support_below_minimum")
    if observation_process_events < config["minimum_observed_process_events"]:
        missing_reasons.append("observation_process_support_below_minimum")
    if baseline_coverage["command_usable_fraction"] < config["minimum_command_coverage"]:
        missing_reasons.append("baseline_usable_command_coverage_below_minimum")
    if observation_coverage["command_usable_fraction"] < config["minimum_command_coverage"]:
        missing_reasons.append("observation_usable_command_coverage_below_minimum")

    category_values: dict[str, float] = {}
    novelty_values: dict[str, float] = {}
    family_details: dict[str, Any] = {}
    novelty_details: dict[str, Any] = {}
    contribution_rows = []
    eligible_count = 0
    minimum_baseline_family_events = config["minimum_baseline_family_events"]
    minimum_observed_family_events = config["minimum_observed_family_events"]
    for family in config["categorical_weights"]:
        base_events = _support_events_from_record(baseline_support.get(family, {}))
        observed_events = _support_events_from_record(observation_support.get(family, {}))
        base_tokens = baseline_counts[family]
        observed_tokens = observation_counts[family]
        available = (
            base_events >= minimum_baseline_family_events
            and observed_events >= minimum_observed_family_events
            and sum(base_tokens.values()) > 0
            and sum(observed_tokens.values()) > 0
        )
        distance = None
        token_contributions = []
        if available:
            distance, token_contributions = _js_components(
                base_tokens,
                observed_tokens,
                alpha=config["dirichlet_smoothing_alpha"],
                max_support=config["max_baseline_support_tokens"],
            )
            category_values[family] = distance
            novelty, unseen = _novelty_mass(base_tokens, observed_tokens)
            novelty_values[family] = novelty
            eligible_count += 1
            contribution_rows.extend(
                {
                    "kind": "categorical_distance",
                    "feature": family,
                    **item,
                }
                for item in token_contributions
            )
            novelty_details[family] = {
                "available": True,
                "unseen_probability_mass": novelty,
                "unseen": unseen,
            }
        else:
            novelty_details[family] = {
                "available": False,
                "unseen_probability_mass": None,
                "unseen": [],
            }
        family_details[family] = {
            "available": available,
            "distance": distance,
            "baseline_support": baseline_support.get(family, {}),
            "observation_support": observation_support.get(family, {}),
            "bounded_support_size": min(
                len(set(base_tokens) | set(observed_tokens)),
                config["max_baseline_support_tokens"],
            )
            + 1,
            "token_contributions": token_contributions,
        }

    categorical_score, categorical_weights = _weighted_average(
        category_values, config["categorical_weights"]
    )
    novelty_score, novelty_weights = _weighted_average(
        novelty_values, config["categorical_weights"]
    )

    baseline_numeric = baseline_features.get("numeric_summaries", {})
    observed_numeric = observation_features.get("numeric_summaries", {})
    baseline_nonempty_windows = baseline_feature_support.get("nonempty_window_count")
    if (
        isinstance(baseline_nonempty_windows, bool)
        or not isinstance(baseline_nonempty_windows, int)
        or baseline_nonempty_windows < 0
    ):
        raise ValueError("Support-aware fitted-window support is invalid")
    numeric_supported = (
        baseline_nonempty_windows
        >= config["minimum_baseline_nonempty_windows_for_numeric"]
    )
    numeric_values: dict[str, float] = {}
    numeric_details: dict[str, Any] = {}
    for feature_name in config["numeric_weights"]:
        detail = (
            _numeric_deviation(
                feature_name,
                baseline_numeric.get(feature_name, {}),
                observed_numeric.get(feature_name, {}),
                config=config,
            )
            if numeric_supported
            else None
        )
        if detail is not None:
            numeric_values[feature_name] = detail["score"]
            numeric_details[feature_name] = detail
        else:
            numeric_details[feature_name] = {
                "available": False,
                "reason": (
                    None
                    if numeric_supported
                    else "baseline_nonempty_window_support_below_minimum"
                ),
            }
    numeric_score, numeric_weights = _weighted_average(numeric_values, config["numeric_weights"])

    temporal = _score_temporal_windows(
        baseline_counts=baseline_counts,
        baseline_support=baseline_support,
        observation=observation_features,
        config=config,
    )
    if eligible_count < config["minimum_eligible_families"]:
        missing_reasons.append("too_few_supported_feature_families")
    aggregate_groups = {
        name: value
        for name, value in {
            "categorical_distance": categorical_score,
            "novelty": novelty_score,
            "numeric_deviation": numeric_score,
        }.items()
        if value is not None
    }
    aggregate_score, group_weights = _weighted_average(aggregate_groups, config["top_level_weights"])
    if aggregate_score is None:
        missing_reasons.append("no_supported_aggregate_groups")
    if missing_reasons:
        components = {
            "status": "insufficient_data",
            "reason_codes": sorted(set(missing_reasons)),
            "aggregate_score": aggregate_score,
            "temporal": temporal,
            "categorical_distance": {
                "score": categorical_score,
                "effective_family_weights": categorical_weights,
                "families": family_details,
            },
            "novelty": {
                "score": novelty_score,
                "effective_family_weights": novelty_weights,
                "families": novelty_details,
            },
            "numeric_deviation": {
                "score": numeric_score,
                "effective_feature_weights": numeric_weights,
                "features": numeric_details,
            },
        }
        explanation = {
            "band": "insufficient_data",
            "interpretation": "The observation did not meet the support contract; this is not evidence of normal behaviour.",
            "abstention_reasons": sorted(set(missing_reasons)),
            "top_contributors": [],
            "temporal": temporal,
        }
        return None, "insufficient_data", components, explanation

    temporal_score = temporal["peak_score"] if temporal["status"] == "supported" else None
    total_score = max(aggregate_score, temporal_score) if temporal_score is not None else aggregate_score
    band = score_band(total_score, config)
    component_contributors = []
    for family, value in category_values.items():
        weighted = group_weights.get("categorical_distance", 0.0) * categorical_weights.get(family, 0.0) * value
        component_contributors.append(
            {"kind": "categorical_distance", "feature": family, "raw_score": _round(value), "weighted_contribution": _round(weighted)}
        )
    for family, value in novelty_values.items():
        weighted = group_weights.get("novelty", 0.0) * novelty_weights.get(family, 0.0) * value
        component_contributors.append(
            {"kind": "novelty", "feature": family, "raw_score": _round(value), "weighted_contribution": _round(weighted)}
        )
    for name, value in numeric_values.items():
        weighted = group_weights.get("numeric_deviation", 0.0) * numeric_weights.get(name, 0.0) * value
        component_contributors.append(
            {"kind": "numeric_deviation", "feature": name, "raw_score": _round(value), "weighted_contribution": _round(weighted)}
        )
    component_contributors.sort(key=lambda item: (-item["weighted_contribution"], item["kind"], item["feature"]))
    contribution_rows.sort(key=lambda item: (-item["divergence_contribution"], item["feature"], item["token"]))

    components = {
        "status": "scored",
        "aggregate_score": aggregate_score,
        "temporal": temporal,
        "categorical_distance": {
            "score": categorical_score,
            "effective_family_weights": categorical_weights,
            "families": family_details,
        },
        "novelty": {
            "score": novelty_score,
            "effective_family_weights": novelty_weights,
            "families": novelty_details,
        },
        "numeric_deviation": {
            "score": numeric_score,
            "effective_feature_weights": numeric_weights,
            "features": numeric_details,
        },
        "effective_group_weights": group_weights,
        "score_aggregation": config["temporal_aggregation"],
    }
    explanation = {
        "band": band,
        "interpretation": "The score is behavioral distance evidence. The temporal maximum is uncalibrated and must be reviewed with event evidence.",
        "top_contributors": component_contributors[:12],
        "top_token_divergence_contributions": contribution_rows[:25],
        "temporal": temporal,
        "support": {
            "baseline_process_events": baseline_process_events,
            "observation_process_events": observation_process_events,
            "baseline_command_coverage": baseline_coverage["command_usable_fraction"],
            "observation_command_coverage": observation_coverage["command_usable_fraction"],
            "eligible_families": sorted(category_values),
            "missing_families": sorted(set(config["categorical_weights"]) - set(category_values)),
        },
    }
    return _round(total_score), band, components, explanation
