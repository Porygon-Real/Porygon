"""Train, calibrate, and evaluate the 10-feature no-baseline Porygon ML Classifier.

Trained strictly on fit split (without unseen_executable_ratio and jensen_shannon_drift),
calibrated on calibration split via temperature scaling, and evaluated once on test split
with 95% bootstrap confidence intervals resampled by run_id.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Add backend/src to path
SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

from porygon_api.ml_classifier import (
    CLASSES,
    NOBASELINE_FEATURE_NAMES,
    PorygonThreatClassifier,
    _softmax,
)
from porygon_api.model_registry import sha256_document
from train import (
    convert_forest_to_porygon_trees,
    load_training_dataset,
    train_random_forest,
    validate_fit_split,
)
from calibrate import calibrate_and_seal_artifact


def run_nobaseline_pipeline(
    csv_path: Path | str,
    output_artifact_path: Path | str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute no-baseline training, calibration, and test evaluation."""
    csv_path = Path(csv_path)
    output_artifact_path = Path(output_artifact_path)
    output_artifact_path.parent.mkdir(parents=True, exist_ok=True)

    df = load_training_dataset(csv_path)
    df_fit = df[df["split"] == "fit"].copy()
    counts = validate_fit_split(df_fit, min_windows_per_class=30)

    features = list(NOBASELINE_FEATURE_NAMES)
    X_fit = df_fit[features]
    y_fit = df_fit["label"]

    rf = train_random_forest(X_fit, y_fit, n_estimators=5, max_depth=4, random_state=42)
    trees = convert_forest_to_porygon_trees(rf)

    training_summary = {
        "n_estimators": 5,
        "max_depth": 4,
        "class_weight": "balanced",
        "random_state": 42,
        "fit_windows_total": int(len(df_fit)),
        "fit_runs_total": int(df_fit["run_id"].nunique()),
        "fit_class_counts": counts,
        "features": features,
    }

    # Initial uncalibrated artifact
    canonical_doc = {
        "classes": list(CLASSES),
        "features": features,
        "feature_contract": "porygon.ml.features.exec-taxonomy",
        "input_document_schema": "porygon.behaviour.v1",
        "trees": trees,
        "score_transform": {
            "method": "log_probability_softmax",
            "temperature": 0.35,
        },
    }
    digest = sha256_document(canonical_doc)
    artifact = {
        **canonical_doc,
        "model_metadata": {
            "model_kind": "tree_ensemble",
            "training_status": "trained",
            "calibration_status": "unvalidated",
            "explanation_method": "tree_path_delta",
            "explanation_output_space": "raw_ensemble_probability",
            "feature_contract": "porygon.ml.features.exec-taxonomy",
            "input_document_schema": "porygon.behaviour.v1",
            "model_artifact_sha256": digest,
        },
        "training_summary": training_summary,
    }

    # Save intermediate uncalibrated artifact for calibration step
    with open(output_artifact_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    # Calibrate on calibration split
    calibrated_artifact, cal_results = calibrate_and_seal_artifact(
        output_artifact_path, csv_path
    )

    # Save calibrated & sealed artifact
    with open(output_artifact_path, "w", encoding="utf-8") as f:
        json.dump(calibrated_artifact, f, indent=2)

    # Evaluate once on test split
    df_test = df[df["split"] == "test"].copy()
    classifier = PorygonThreatClassifier.from_artifact(output_artifact_path)

    y_test = df_test["label"].tolist()
    y_pred: list[str] = []
    for _, row in df_test.iterrows():
        fvec = {f: float(row[f]) for f in features}
        res = classifier.predict_vector(fvec, model_variant="no_baseline")
        y_pred.append(res.predicted_class)

    labels = list(CLASSES)
    p, r, f1, sup = precision_recall_fscore_support(
        y_test, y_pred, labels=labels, zero_division=0
    )
    macro_f1 = float(np.mean(f1))

    # Bootstrap 95% CI resampled by run_id
    run_ids = df_test["run_id"].unique()
    rng = np.random.RandomState(42)
    boot_f1s: list[float] = []
    for _ in range(1000):
        sample_runs = rng.choice(run_ids, size=len(run_ids), replace=True)
        sample_df = pd.concat([df_test[df_test["run_id"] == rid] for rid in sample_runs])
        sample_preds: list[str] = []
        for _, row in sample_df.iterrows():
            fvec = {f: float(row[f]) for f in features}
            res = classifier.predict_vector(fvec, model_variant="no_baseline")
            sample_preds.append(res.predicted_class)
        _, _, sf1, _ = precision_recall_fscore_support(
            sample_df["label"].tolist(), sample_preds, labels=labels, zero_division=0
        )
        boot_f1s.append(float(np.mean(sf1)))

    ci_low, ci_high = np.percentile(boot_f1s, [2.5, 97.5])

    eval_results = {
        "test_windows": len(df_test),
        "test_runs": int(df_test["run_id"].nunique()),
        "macro_f1": round(macro_f1, 4),
        "bootstrap_ci_95": [round(float(ci_low), 4), round(float(ci_high), 4)],
        "fitted_temperature": cal_results["fitted_temperature"],
        "model_artifact_sha256": calibrated_artifact["model_metadata"]["model_artifact_sha256"],
        "per_class": {
            cls_name: {
                "precision": round(float(p[i]), 4),
                "recall": round(float(r[i]), 4),
                "f1": round(float(f1[i]), 4),
                "support": int(sup[i]),
            }
            for i, cls_name in enumerate(labels)
        },
    }

    calibrated_artifact["test_evaluation"] = eval_results
    with open(output_artifact_path, "w", encoding="utf-8") as f:
        json.dump(calibrated_artifact, f, indent=2)

    return calibrated_artifact, eval_results


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    csv_path = base_dir / "windows.csv"
    output_path = base_dir / "models" / "trained_ensemble_nobaseline.json"

    print("Running no-baseline training, calibration, and test evaluation...")
    artifact, eval_results = run_nobaseline_pipeline(csv_path, output_path)

    print("\n--- No-Baseline Model Results ---")
    print(f"Artifact: {output_path}")
    print(f"SHA-256: {artifact['model_metadata']['model_artifact_sha256']}")
    print(f"Fitted Temperature T*: {eval_results['fitted_temperature']}")
    print(f"Test Macro-F1: {eval_results['macro_f1']}")
    print(f"95% Bootstrap CI: {eval_results['bootstrap_ci_95']}")
    for cls_name, metrics in eval_results["per_class"].items():
        print(f"  {cls_name:22s}: P={metrics['precision']:.4f}, R={metrics['recall']:.4f}, F1={metrics['f1']:.4f}")


if __name__ == "__main__":
    main()
