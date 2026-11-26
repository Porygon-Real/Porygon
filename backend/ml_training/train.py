"""Train decision tree ensemble for Porygon runtime container security.

Trains RandomForestClassifier (n_estimators=5, max_depth=4, class_weight='balanced')
strictly on the fit split of windows.csv, maps decision trees into the canonical
Porygon dictionary format, validates class order preservation, and produces the
initial uncalibrated model artifact.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from porygon_api.ml_classifier import (
    CLASSES,
    FEATURE_CONTRACT,
    FEATURE_NAMES,
    INPUT_DOCUMENT_SCHEMA,
)
from porygon_api.model_registry import sha256_document


def load_training_dataset(csv_path: Path | str) -> pd.DataFrame:
    """Load and validate the windows telemetry dataset."""
    df = pd.read_csv(csv_path)
    expected_cols = list(FEATURE_NAMES) + ["label", "image", "run_id", "split"]
    missing = set(expected_cols) - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {sorted(missing)}")
    return df


def validate_fit_split(df_fit: pd.DataFrame, min_windows_per_class: int = 30) -> dict[str, int]:
    """Ensure every threat class has sufficient training windows on fit split."""
    counts = df_fit["label"].value_counts().to_dict()
    for cls_name in CLASSES:
        count = counts.get(cls_name, 0)
        if count < min_windows_per_class:
            raise ValueError(
                f"Class '{cls_name}' has {count} fit windows, which is below minimum "
                f"threshold of {min_windows_per_class}."
            )
    return counts


def train_random_forest(
    X_fit: pd.DataFrame,
    y_fit: pd.Series,
    n_estimators: int = 5,
    max_depth: int = 4,
    random_state: int = 42,
) -> RandomForestClassifier:
    """Train Random Forest classifier with balanced class weighting on fit split only."""
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        random_state=random_state,
    )
    rf.fit(X_fit, y_fit)
    return rf


def convert_sklearn_tree_to_dict(estimator: Any, rf_classes: list[str]) -> dict[str, Any]:
    """Convert a single scikit-learn DecisionTreeClassifier tree into Porygon dict format.

    Crucially reorders node class counts from rf_classes (lexicographical)
    into canonical CLASSES order so reconnaissance and privilege_escalation are never inverted.
    """
    tree_ = estimator.tree_
    rf_class_indices = [rf_classes.index(c) for c in CLASSES]

    def _convert_node(node_id: int) -> dict[str, Any]:
        raw_counts = tree_.value[node_id][0]
        reordered_counts = [float(raw_counts[idx]) for idx in rf_class_indices]
        total = sum(reordered_counts)
        if total > 0:
            probs = [round(c / total, 6) for c in reordered_counts]
        else:
            probs = [round(1.0 / len(CLASSES), 6)] * len(CLASSES)
        
        # Ensure exact probability sum of 1.0
        delta = round(1.0 - sum(probs), 6)
        probs[0] = round(probs[0] + delta, 6)

        is_leaf = tree_.children_left[node_id] == -1 and tree_.children_right[node_id] == -1
        if is_leaf:
            return {
                "is_leaf": True,
                "probs": probs,
            }

        feature_idx = int(tree_.feature[node_id])
        threshold = round(float(tree_.threshold[node_id]), 6)
        left_child = _convert_node(int(tree_.children_left[node_id]))
        right_child = _convert_node(int(tree_.children_right[node_id]))

        return {
            "is_leaf": False,
            "feature_idx": feature_idx,
            "threshold": threshold,
            "probs": probs,
            "left": left_child,
            "right": right_child,
        }

    return _convert_node(0)


def convert_forest_to_porygon_trees(rf: RandomForestClassifier) -> list[dict[str, Any]]:
    """Convert all trees in a trained RandomForestClassifier to Porygon dict format."""
    rf_classes = list(rf.classes_)
    return [convert_sklearn_tree_to_dict(est, rf_classes) for est in rf.estimators_]


def build_model_artifact(
    trees: list[dict[str, Any]],
    temperature: float = 0.35,
    features: list[str] | tuple[str, ...] | None = None,
    training_status: str = "trained",
    calibration_status: str = "unvalidated",
    training_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build canonical model artifact document and sign with sha256_document."""
    features_list = list(features) if features is not None else list(FEATURE_NAMES)
    canonical_doc = {
        "classes": list(CLASSES),
        "features": features_list,
        "feature_contract": FEATURE_CONTRACT,
        "input_document_schema": INPUT_DOCUMENT_SCHEMA,
        "trees": trees,
        "score_transform": {
            "method": "log_probability_softmax",
            "temperature": round(float(temperature), 4),
        },
    }
    digest = sha256_document(canonical_doc)

    artifact = {
        **canonical_doc,
        "model_metadata": {
            "model_kind": "tree_ensemble",
            "training_status": training_status,
            "calibration_status": calibration_status,
            "explanation_method": "tree_path_delta",
            "explanation_output_space": "raw_ensemble_probability",
            "feature_contract": FEATURE_CONTRACT,
            "input_document_schema": INPUT_DOCUMENT_SCHEMA,
            "model_artifact_sha256": digest,
        },
        "training_summary": training_summary or {},
    }
    return artifact


def run_training_pipeline(
    csv_path: Path | str,
    output_artifact_path: Path | str | None = None,
    output_joblib_path: Path | str | None = None,
    features: list[str] | tuple[str, ...] | None = None,
) -> tuple[dict[str, Any], RandomForestClassifier]:
    """Execute training workflow and return generated artifact and trained RF model."""
    df = load_training_dataset(csv_path)
    df_fit = df[df["split"] == "fit"].copy()
    counts = validate_fit_split(df_fit, min_windows_per_class=30)

    features_to_use = list(features) if features is not None else list(FEATURE_NAMES)
    X_fit = df_fit[features_to_use]
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
        "features": features_to_use,
    }

    artifact = build_model_artifact(
        trees=trees,
        temperature=0.35,
        features=features_to_use,
        training_status="trained",
        calibration_status="unvalidated",
        training_summary=training_summary,
    )

    return artifact, rf


def main() -> None:
    """Entry point for CLI training execution."""
    base_dir = Path(__file__).resolve().parent
    csv_path = base_dir / "windows.csv"
    models_dir = base_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = base_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = models_dir / "trained_ensemble.json"
    joblib_path = artifacts_dir / "rf_fit.joblib"

    print(f"Loading telemetry dataset from: {csv_path}")
    artifact, rf = run_training_pipeline(csv_path, artifact_path, joblib_path)

    # Save artifact JSON
    with open(artifact_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)
    print(f"Model artifact saved to: {artifact_path}")
    print(f"Model artifact SHA-256: {artifact['model_metadata']['model_artifact_sha256']}")

    # Save sklearn RF object for downstream reference & SHAP comparisons
    joblib.dump(rf, joblib_path)
    print(f"Trained RandomForest saved to: {joblib_path}")


if __name__ == "__main__":
    main()
