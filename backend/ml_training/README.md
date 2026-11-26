# Porygon ML Threat Classification Module

This directory contains the training, calibration, evaluation pipeline, and serialized model artifacts for Porygon's runtime threat classifier (Project Phase II, 23CSE498).

## 1. Directory Structure

```text
backend/ml_training/
├── artifacts/              # Intermediate binary artifacts (.gitignored, e.g. rf_fit.joblib)
├── models/
│   ├── trained_ensemble.json             # 12-feature model (SHA: 9327513b...)
│   └── trained_ensemble_nobaseline.json  # 10-feature model (SHA: c434fb5e...)
├── notebooks/
│   └── classifier_report.ipynb          # Self-contained executed evaluation report
├── results/
│   ├── metrics.json                     # Complete test metrics & bootstrap CIs
│   └── summary.md                       # Comprehensive evaluation summary
├── workload/
│   └── Dockerfile                       # Pinned recipe for porygon-training-workload:latest
├── runs.csv                             # Trial registry (220 container trials)
├── windows.csv                          # 633 qualified 60-second tumbling windows
├── train.py                             # Random forest training & JSON tree exporter
├── calibrate.py                         # Post-hoc softmax temperature calibration (T*)
├── train_nobaseline.py                  # 10-feature model trainer & calibrator
├── evaluate.py                          # Held-out test evaluation, baselines, & ablations
├── export_windows.py                    # Window extractor from raw telemetry events
└── requirements-training.txt            # Training dependencies (scikit-learn, shap, etc.)
```

## 2. Pipeline Execution Commands

Run from the `Porygon/` workspace root:

```bash
# Set Python path to include backend source
export PYTHONPATH="backend/src:backend"

# 1. Train 12-feature ensemble and export JSON artifact
python backend/ml_training/train.py

# 2. Calibrate softmax temperature on calibration split
python backend/ml_training/calibrate.py

# 3. Train and calibrate 10-feature no-baseline fallback model
python backend/ml_training/train_nobaseline.py

# 4. Evaluate all models, baselines, and ablations on held-out test split
python backend/ml_training/evaluate.py
```

## 3. Production Environment Variables & Artifact Hashes

The backend loads models at startup or per-request using canonical JSON documents verified by SHA-256 digest:

| Model Variant | Feature Count | Environment Variable | Canonical SHA-256 Digest |
|---|:---:|---|---|
| Baseline Model | 12 | `PORYGON_ML_MODEL_PATH` | `9327513b1c3bfb6be3ed0e9916eb37aa69888961720e49373352fdea7ba7e548` |
| No-Baseline Fallback | 10 | `PORYGON_ML_MODEL_NOBASELINE_PATH` | `c434fb5ef16bbc04a58d0e805f6398a46fb7d17fd667071df51a86ab853689de` |

- **Selection Rule**: The 12-feature model runs only when both `baseline_features` and `drift_score` exist. Otherwise, the runtime falls back to the 10-feature model.
- **Fail-Safe Integrity**: Setting either environment variable to a nonexistent or tampered file raises an HTTP 500 error; silent degradation to uncalibrated defaults is strictly prohibited. When both environment variables are unset, the hand-authored heuristic ensemble remains active.

## 4. Key Performance Highlights

- **12-Feature Model**: Held-out test Macro-F1 = **0.9664**, Benign FPR = **0.00%** (0 false alarms across 13 benign test trials).
- **10-Feature Fallback Model**: Held-out test Macro-F1 = **0.8619**, Benign Recall = **0.4103**, Reconnaissance Precision = **0.6034** (high attack recall across all threats with higher benign false alarm rate).
- **Ablation Insight**: Removing baseline drift features (`unseen_executable_ratio` and `jensen_shannon_drift`) lowers test Macro-F1 by ~0.10, partly because benign baseline profiles were constructed from the same script suite.

## 5. Documented Limitations

1. **Single Workload Image**: All trials ran on `porygon-training-workload:latest` (Alpine with diagnostic packages).
2. **Command Overlap**: Administrative and reconnaissance workloads share tools (`whoami`, `id`, `ps`, `netstat`).
3. **Correlated Windows**: Mitigated by `GroupKFold` on `run_id` during fit and trial-clustered bootstrap on test.
4. **Shim Execution**: Canary scripts injected via `docker exec` elevate `parent_shim_ratio`.
5. **Constant Features**: `root_ratio` was constant (1.0) because trials executed as root.
6. **Shell Scenarios**: Interactive shell invocations were concentrated in `shell_escape`.
7. **Minimum Events**: Telemetry slices require 3+ process events; otherwise `insufficient_data` is returned.
8. **Sample Size**: Held-out test split comprises ~12 independent trials per class (61 total).
9. **No-Baseline Recall**: Fallback model has lower benign recall (0.41) in environments lacking behavioral baselines.
10. **Heuristic Transferability**: Hand-set thresholds failed on real telemetry (0.4159 Macro-F1, 76.92% benign false alarms).
