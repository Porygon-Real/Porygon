"""Calibrate decision tree ensemble temperature for Porygon runtime security.

Fits softmax temperature parameter on split == 'calibration' by minimizing
negative log likelihood (cross-entropy), computes Expected Calibration Error (ECE)
across T=0.35, T=1.0, and fitted T, updates model_metadata statuses to 'trained'
and 'validated', and reseals the artifact with canonical sha256_document digest.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scipy.optimize import minimize_scalar

from porygon_api.ml_classifier import (
    CLASSES,
    FEATURE_CONTRACT,
    FEATURE_NAMES,
    INPUT_DOCUMENT_SCHEMA,
    PorygonThreatClassifier,
    _softmax,
)
from porygon_api.model_registry import sha256_document


def extract_raw_probabilities(
    classifier: PorygonThreatClassifier,
    X: pd.DataFrame,
) -> list[list[float]]:
    """Compute unweighted average class probabilities across ensemble trees before softmax."""
    num_classes = len(CLASSES)
    num_trees = len(classifier.trees)
    raw_probs_list: list[list[float]] = []
    feat_names = list(getattr(classifier, "features", FEATURE_NAMES))

    for _, row in X.iterrows():
        x_vec = [float(row[f]) for f in feat_names]
        tree_probs = [0.0] * num_classes
        for tree in classifier.trees:
            probs, _ = classifier._traverse_tree(tree, x_vec)
            for c in range(num_classes):
                tree_probs[c] += probs[c] / num_trees
        raw_probs_list.append(tree_probs)

    return raw_probs_list


def compute_nll(
    raw_probs_list: list[list[float]],
    y_true: list[str],
    temperature: float,
) -> float:
    """Compute average Negative Log-Likelihood (cross entropy) at given temperature."""
    total_nll = 0.0
    for raw, label in zip(raw_probs_list, y_true):
        scores = _softmax(raw, temperature=temperature)
        class_idx = CLASSES.index(label)
        p = max(1e-12, scores[class_idx])
        total_nll -= math.log(p)
    return total_nll / len(y_true)


def fit_temperature_parameter(
    raw_probs_list: list[list[float]],
    y_true: list[str],
    bounds: tuple[float, float] = (0.05, 5.0),
) -> float:
    """Find scalar temperature that minimizes log loss on calibration set."""
    def objective(t: float) -> float:
        return compute_nll(raw_probs_list, y_true, t)

    res = minimize_scalar(objective, bounds=bounds, method="bounded")
    if not res.success:
        raise RuntimeError(f"Temperature optimization failed: {res.message}")
    return float(res.x)


def compute_expected_calibration_error(
    raw_probs_list: list[list[float]],
    y_true: list[str],
    temperature: float,
    n_bins: int = 10,
) -> dict[str, Any]:
    """Calculate Expected Calibration Error (ECE) with equal-width probability bins."""
    confidences: list[float] = []
    accuracies: list[float] = []

    for raw, label in zip(raw_probs_list, y_true):
        scores = _softmax(raw, temperature=temperature)
        pred_idx = scores.index(max(scores))
        pred_class = CLASSES[pred_idx]
        conf = scores[pred_idx]
        confidences.append(conf)
        accuracies.append(1.0 if pred_class == label else 0.0)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    n_samples = len(confidences)
    ece = 0.0
    bin_stats: list[dict[str, Any]] = []

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        if i == n_bins - 1:
            in_bin = [bin_lower <= c <= bin_upper for c in confidences]
        else:
            in_bin = [bin_lower <= c < bin_upper for c in confidences]

        bin_count = sum(in_bin)
        if bin_count > 0:
            bin_acc = sum(acc for acc, b in zip(accuracies, in_bin) if b) / bin_count
            bin_conf = sum(c for c, b in zip(confidences, in_bin) if b) / bin_count
            ece += (bin_count / n_samples) * abs(bin_acc - bin_conf)
            bin_stats.append({
                "bin_index": i,
                "range": [round(float(bin_lower), 2), round(float(bin_upper), 2)],
                "count": int(bin_count),
                "accuracy": round(float(bin_acc), 4),
                "confidence": round(float(bin_conf), 4),
            })

    return {
        "temperature": round(float(temperature), 4),
        "nll": round(compute_nll(raw_probs_list, y_true, temperature), 4),
        "ece": round(float(ece), 4),
        "bin_details": bin_stats,
    }


def calibrate_and_seal_artifact(
    artifact_path: Path | str,
    windows_csv_path: Path | str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fit temperature on calibration split, update statuses, and recompute SHA-256."""
    with open(artifact_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    df = pd.read_csv(windows_csv_path)
    df_cal = df[df["split"] == "calibration"].copy()
    if len(df_cal) < 30:
        raise ValueError(f"Calibration split has only {len(df_cal)} windows.")

    features_to_use = artifact.get("features", list(FEATURE_NAMES))
    classifier = PorygonThreatClassifier(trees=artifact["trees"], temperature=1.0, features=features_to_use)
    raw_probs = extract_raw_probabilities(classifier, df_cal[list(features_to_use)])
    y_cal = df_cal["label"].tolist()

    # Fit optimal temperature
    fitted_temp = fit_temperature_parameter(raw_probs, y_cal)

    # Compute ECE comparisons
    ece_heuristic = compute_expected_calibration_error(raw_probs, y_cal, temperature=0.35)
    ece_uncalibrated = compute_expected_calibration_error(raw_probs, y_cal, temperature=1.0)
    ece_fitted = compute_expected_calibration_error(raw_probs, y_cal, temperature=fitted_temp)

    cal_results = {
        "calibration_windows": len(df_cal),
        "calibration_runs": int(df_cal["run_id"].nunique()),
        "fitted_temperature": round(fitted_temp, 4),
        "evaluations": {
            "heuristic_temperature_0_35": ece_heuristic,
            "unscaled_temperature_1_0": ece_uncalibrated,
            "fitted_temperature": ece_fitted,
        },
    }

    # Reseal artifact with fitted temperature and validated statuses
    canonical_doc = {
        "classes": artifact["classes"],
        "features": artifact["features"],
        "feature_contract": artifact.get("feature_contract", FEATURE_CONTRACT),
        "input_document_schema": artifact.get("input_document_schema", INPUT_DOCUMENT_SCHEMA),
        "trees": artifact["trees"],
        "score_transform": {
            "method": "log_probability_softmax",
            "temperature": round(fitted_temp, 4),
        },
    }
    digest = sha256_document(canonical_doc)

    artifact["score_transform"] = canonical_doc["score_transform"]
    artifact["model_metadata"]["calibration_status"] = "validated"
    artifact["model_metadata"]["training_status"] = "trained"
    artifact["model_metadata"]["model_artifact_sha256"] = digest
    artifact["calibration_summary"] = cal_results

    return artifact, cal_results


def main() -> None:
    """Entry point for CLI calibration execution."""
    base_dir = Path(__file__).resolve().parent
    artifact_path = base_dir / "models" / "trained_ensemble.json"
    csv_path = base_dir / "windows.csv"

    print(f"Calibrating model artifact: {artifact_path}")
    updated_artifact, cal_results = calibrate_and_seal_artifact(artifact_path, csv_path)

    with open(artifact_path, "w", encoding="utf-8") as f:
        json.dump(updated_artifact, f, indent=2)

    print(f"Calibration successful.")
    print(f"Fitted Temperature T* = {cal_results['fitted_temperature']}")
    print(f"ECE before (T=0.35): {cal_results['evaluations']['heuristic_temperature_0_35']['ece']}")
    print(f"ECE before (T=1.00): {cal_results['evaluations']['unscaled_temperature_1_0']['ece']}")
    print(f"ECE after  (T*={cal_results['fitted_temperature']}): {cal_results['evaluations']['fitted_temperature']['ece']}")
    print(f"Updated Artifact SHA-256: {updated_artifact['model_metadata']['model_artifact_sha256']}")


if __name__ == "__main__":
    main()
