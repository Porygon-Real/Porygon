# Heuristic Threat Classifier

Component: `backend/src/porygon_api/ml_classifier.py`. The historical identifier `porygon.ml.rf.v1` is retained for replay compatibility. The default implementation consists of five hand-authored specialist decision trees, averaged in raw class-output space, followed by a fixed score transform.

## 1. Model metadata and provenance

Every prediction, its `to_dict()` representation used in stored score explanations, and the model-info API expose the same `model_metadata` contract:

| Field | Default value |
|---|---|
| `model_kind` | `heuristic` |
| `training_status` | `hand_authored` |
| `calibration_status` | `unvalidated` |
| `explanation_method` | `tree_path_delta` |
| `explanation_output_space` | `raw_ensemble_probability` |
| `feature_contract` | `porygon.ml.features.exec-taxonomy` |
| `input_document_schema` | `porygon.behaviour.v1` |
| `model_artifact_sha256` | Canonical SHA-256 of ensemble, classes, ordered feature names, contract and score transform |

Custom supplied trees report `model_kind=tree_ensemble` and `training_status=unspecified`; supplying tree data alone does not establish training or validation provenance. Metadata is immutable for a returned prediction. The content hash is independent of dictionary key ordering and changes when tree contents change.

## 2. The 12 Runtime Window Features

The classifier derives 12 numerical features from supplied process events or a compatible feature document. API callers choose the event set; the classifier does not schedule a rolling window itself.

| # | Feature Name | Computation Formula / Meaning | Associated MITRE Tactic |
|---|---|---|---|
| 1 | `shell_ratio` | $\frac{\text{count}(exec \in \text{SHELL\_BINARIES})}{\text{total\_events}}$ | Execution / Shell Escape |
| 2 | `root_ratio` | $\frac{\text{count}(uid == 0)}{\text{total\_events}}$ | Privilege Escalation |
| 3 | `recon_ratio` | $\frac{\text{count}(exec \in \text{RECON\_BINARIES})}{\text{total\_events}}$ (`whoami`, `id`, `uname`, `ip`) | Discovery / Reconnaissance |
| 4 | `tooling_ratio` | $\frac{\text{count}(exec \in \text{SUSPICIOUS\_TOOLS})}{\text{total\_events}}$ (`curl`, `wget`, `nc`, `nmap`) | Ingress Tool Transfer |
| 5 | `priv_escalation_ratio` | Basename matches such as `sudo`, `su`, `chmod` and `nsenter`; arguments do not affect this ratio | Privilege Escalation |
| 6 | `compiler_miner_ratio` | Executions of `gcc`, `make`, `xmrig`, `minerd` | Defense Evasion / Impact |
| 7 | `distinct_proc_count` | Number of distinct executable basenames in supplied events | Anomaly Indicator |
| 8 | `event_count` | Total volume of process events in window | Burst / Flood Indicator |
| 9 | `unseen_executable_ratio` | Fraction of distinct observed executable/name strings absent from baseline support | Statistical Novelty |
| 10| `parent_shim_ratio` | Recognized runtime-shim parent names | Escape / Lateral Movement |
| 11| `suspicious_sequence_ratio`| Adjacent input-record transitions matching fixed name categories | Attack Pipeline |
| 12| `jensen_shannon_drift` | Statistical divergence $D_{JS}$ from baseline distribution | Process Drift |


## 3. Classification and score transform

Each tree selects one leaf using fixed feature thresholds. The engine averages leaf values for the five operational labels: benign, reconnaissance, privilege escalation, shell escape and suspicious tooling. The existing `class_probabilities` mapping applies a log-probability softmax with a fixed temperature of 0.35; `confidence` is the largest transformed class score. These API names and numeric values remain compatible with historical outputs.

The transform is fixed score sharpening. No calibration fit or training dataset is attached to the default trees. Operational labels provide a repeatable heuristic comparator for later model evaluation. Existing response approval rules operate separately.

The implementation uses standard Python for inference. Runtime latency and resource claims require a benchmark identifying the event set and hardware.

## 4. Tree-path feature deltas

At each traversed split, the algorithm assigns the difference between the child and parent class-output vectors to the split feature. It then averages these deltas across trees. For each class:

$$f_c^{\mathrm{raw}}(x) = b_c + \sum_{i=1}^{12} \Delta_{i,c}(x)$$

Here `b_c` is the average root value, and each delta is the change along the path actually traversed. The response includes all three parts:

- `explanation_base_values`: one raw base value per class;
- `raw_output_values`: average leaf outputs before sharpening;
- `full_feature_contributions`: every feature's raw delta for every class.

The equation reconstructs the raw output. It does not reconstruct the transformed `class_probabilities` values. The method is tree-path decomposition rather than Shapley-value estimation; it does not evaluate feature coalitions. `top_contributing_features` keeps the existing rounded top-five display and is a partial view of the full raw decomposition.

## 5. Dashboard and API integration

The dashboard labels the implementation **Heuristic Trees + Path Deltas**, the transformed values **Class Score**, and the contribution table **Top Raw-space Drivers**. It displays existing class/risk values without relabelling them as validated attack probabilities.

The `/api/v1/ml/model-info`, `/api/v1/ml/classify`, `/api/v1/ml/classify-container/{container_id}` and `/api/v1/ml/classify-features` routes carry consistent model metadata. The legacy feature-document schema remains accepted; incompatible document contracts continue to be rejected. Separate calibrated-rarity APIs retain their own documented semantics.

## 6. Verification

`backend/tests/test_model_contracts.py` characterizes unchanged scores for benign, shell, reconnaissance, privilege and tooling fixtures. It verifies immutable provenance, canonical artifact hashes, custom-tree unknown provenance, raw-space additivity and consistent metadata in every API constructor and serialized explanation. Existing classifier tests retain feature-extraction and class behavior coverage.
