# Plan 003: Build causal evidence detection and validate every model claim

> Executor: read the whole plan, execute the steps in order, and stop at the named boundaries. The plan is a specification, not authorization to publish changes. Update this plan's status in `plans/README.md` after its done criteria pass.

## Status

- Priority: P1
- Effort: L: approximately 5–8 focused weeks including dataset work
- Risk: HIGH: new features can invent causality or degrade precision
- Depends on: 001; 002 for unattended evaluation and explicit profile contracts
- Category: correctness / architecture / direction
- Planned at: commit `b04aaea` plus the working tree, 2026-10-26
- Status: IN PROGRESS — remaining engineering source batch; all execution checks deferred until combined source freeze

## Execution reconciliation — 2026-10-27

The user explicitly requested completing all remaining engineering before testing. The sole executor works in `/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work`. Source reads, repository searches, installed capability inventory and official documentation review are allowed during implementation; test suites, checker scripts, CLI smoke tests, lint, builds, benchmarks and live acceptance wait until the combined003–005 source freeze. The prior accepted identity/continuous increment remains the baseline. No primary source edits, commits, merge, push or publication are authorized.

The advisor reread current classifier feature extraction, process/kernel models, incident grouping, sensor normalizers/spools/Compose configuration, study split consumption and the unconditional confirmatory refusal. Expected changes from the accepted earlier plans require explicit contract reconciliation rather than replacing evidence hashes. Current process/kernel rows lack persisted lifetime/epoch metadata, so new causal paths must be additive and abstain for legacy/missing metadata. Installed pinned Falco's read-only field inventory supports process/parent epoch-start timestamps, PID namespace start, executable writable and memfd provenance. See the [official supported fields](https://falco.org/docs/reference/rules/supported-fields/) and [metrics documentation](https://falco.org/docs/concepts/metrics/); runtime validation still waits until the final acceptance window.

The research executor must preserve the frozen stratified, preconstructed assignment policy and comparator matrix. Existing modulo pilot assignment is a distinct historical convenience, not an interchangeable confirmatory policy. Engineering tools can be completed now; independent measured training/evaluation, a three-node capacity result and seven-day soak remain empirical gates requiring actual collection. No synthetic fixture or software check can mark those gates complete.

## Why this matters

The default classifier is a hand-authored five-tree heuristic ensemble, not a demonstrated trained random forest. Its explanations sum differences along one traversed tree path, while returned confidences are transformed afterward; that does not establish exact TreeSHAP explanations of the displayed value. Binary-name features and adjacent list transitions also miss renamed tooling and can imply sequences between unrelated processes. Preserve this heuristic as a transparent comparator and build evidence-based detection with measured uncertainty.

## Current state and verified excerpts

`backend/src/porygon_api/ml_classifier.py:351` (working-tree snapshot):

```text
351: def _softmax(probs: list[float], temperature: float = 0.35) -> list[float]:
352:     logits = [math.log(max(1e-6, p)) / temperature for p in probs]
353:     max_l = max(logits)
354:     exp_l = [math.exp(val - max_l) for val in logits]
355:     s = sum(exp_l) or 1.0
356:     return [round(e / s, 4) for e in exp_l]
357: 
358: 
359: class PorygonThreatClassifier:
360:     """Explainable Random Forest ensemble for container runtime attack classification."""
361: 
362:     def __init__(self, trees: list[dict[str, Any]] | None = None) -> None:
363:         self.trees = trees or self._build_default_ensemble()
364: 
365:     def _build_default_ensemble(self) -> list[dict[str, Any]]:
366:         """Calibrated 5-tree specialist ensemble with exact decision splits."""
367:         # 1. Shell Escape Specialist
368:         tree_shell = {
369:             "is_leaf": False,
370:             "feature_idx": 0,  # shell_ratio
371:             "threshold": 0.30,
372:             "probs": [0.2, 0.2, 0.2, 0.2, 0.2],
373:             "right": {"is_leaf": True, "probs": [0.01, 0.02, 0.02, 0.93, 0.02]},
```

`backend/src/porygon_api/ml_classifier.py:510` (working-tree snapshot):

```text
510:     def _traverse_tree(
511:         self, tree: dict[str, Any], x: list[float]
512:     ) -> tuple[list[float], list[list[float]]]:
513:         """Traverse a decision tree and calculate exact local feature contributions."""
514:         num_features = len(FEATURE_NAMES)
515:         num_classes = len(CLASSES)
516:         contribs = [[0.0] * num_classes for _ in range(num_features)]
517: 
518:         curr = tree
519:         while not curr["is_leaf"]:
520:             f = curr["feature_idx"]
521:             p_curr = curr["probs"]
522:             thresh = curr["threshold"]
523:             if x[f] <= thresh:
524:                 curr = curr["left"]
525:             else:
526:                 curr = curr["right"]
527:             p_next = curr["probs"]
528:             for c in range(num_classes):
529:                 contribs[f][c] += p_next[c] - p_curr[c]
530: 
531:         return curr["probs"], contribs
```

`backend/src/porygon_api/ml_classifier.py:541` (working-tree snapshot):

```text
541:         raw_probs = [0.0] * num_classes
542:         all_contribs = [[0.0] * num_classes for _ in range(num_features)]
543:         tree_count = len(self.trees) or 1
544: 
545:         for tree in self.trees:
546:             probs, contribs = self._traverse_tree(tree, x)
547:             for c in range(num_classes):
548:                 raw_probs[c] += probs[c] / tree_count
549:                 for f in range(num_features):
550:                     all_contribs[f][c] += contribs[f][c] / tree_count
551: 
552:         calibrated_probs = _softmax(raw_probs, temperature=0.35)
553:         pred_idx = calibrated_probs.index(max(calibrated_probs))
554:         predicted_class = CLASSES[pred_idx]
555:         confidence = calibrated_probs[pred_idx]
```

`backend/src/porygon_api/ml_classifier.py:186` (working-tree snapshot):

```text
186:         token = _basename(exec_path or pname)
187:         unique_procs.add(token)
188:         if exec_path:
189:             observed_execs.add(exec_path)
190:         if pname:
191:             observed_execs.add(pname)
192: 
193:         if token in SHELL_BINARIES or _basename(pname) in SHELL_BINARIES:
194:             shells += 1
195:         if uid == 0:
196:             roots += 1
197:         if token in RECON_BINARIES or _basename(pname) in RECON_BINARIES:
198:             recons += 1
199:         if token in SUSPICIOUS_TOOLS or _basename(pname) in SUSPICIOUS_TOOLS:
200:             tools += 1
201:         if token in PRIVILEGE_BINARIES or _basename(pname) in PRIVILEGE_BINARIES:
202:             privs += 1
203:         if token in COMPILER_MINER_BINARIES or _basename(pname) in COMPILER_MINER_BINARIES:
204:             compilers += 1
205: 
206:         parent_base = _basename(parent)
207:         if parent_base in SHIM_PARENTS:
208:             shims += 1
209: 
210:         # Check sequence transitions (e.g. web/daemon -> shell, shell -> curl, curl -> chmod)
211:         if prev_token:
212:             if (prev_token not in SHELL_BINARIES and token in SHELL_BINARIES) or (
213:                 prev_token in SHELL_BINARIES and (token in SUSPICIOUS_TOOLS or token in PRIVILEGE_BINARIES)
214:             ):
215:                 suspicious_seqs += 1
```

`backend/src/porygon_api/models.py:212` (working-tree snapshot):

```text
212:     event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
213:     sensor_instance_id: Mapped[str] = mapped_column(String(128), nullable=False)
214:     sensor_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
215:     source: Mapped[str] = mapped_column(String(32), nullable=False)
216:     rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
217:     priority: Mapped[str] = mapped_column(String(32), nullable=False)
218:     occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
219:     time_nano: Mapped[int] = mapped_column(BigInteger, nullable=False)
220:     event_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
221:     event_type: Mapped[str] = mapped_column(String(64), nullable=False)
222:     runtime_action: Mapped[str] = mapped_column(String(32), nullable=False)
223:     return_value: Mapped[int] = mapped_column(BigInteger, nullable=False)
224:     reported_docker_host_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
225:     reported_container_id: Mapped[str] = mapped_column(String(128), nullable=False)
226:     docker_host_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
227:     container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
228:     container_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
229:     image_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
230:     image_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
231:     image_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
232:     correlation_status: Mapped[str] = mapped_column(String(32), nullable=False)
233:     process_pid: Mapped[int] = mapped_column(BigInteger, nullable=False)
234:     process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
235:     executable: Mapped[str | None] = mapped_column(Text, nullable=True)
236:     command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
237:     user_uid: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
238:     remote_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
```

`backend/src/porygon_api/main.py:2382` (working-tree snapshot):

```text
2382:     process_events = list(
2383:         db.scalars(
2384:             select(ProcessExecEvent)
2385:             .where(
2386:                 ProcessExecEvent.image_digest == score.image_digest,
2387:                 ProcessExecEvent.correlation_status == "resolved",
2388:                 ProcessExecEvent.occurred_at >= score.window_start,
2389:                 ProcessExecEvent.occurred_at < score.window_end,
2390:             )
2391:             .order_by(ProcessExecEvent.occurred_at, ProcessExecEvent.event_id)
2392:         ).all()
2393:     )
2394:     runtime_events = list(
2395:         db.scalars(
2396:             select(RuntimeEvent)
2397:             .where(
2398:                 RuntimeEvent.image_digest == score.image_digest,
2399:                 RuntimeEvent.occurred_at >= score.window_start,
2400:                 RuntimeEvent.occurred_at < score.window_end,
2401:             )
2402:             .order_by(RuntimeEvent.occurred_at, RuntimeEvent.event_id)
2403:         ).all()
```


## Execution rules and verification baseline

Repository root: `/home/anuruprkris/Project/final_yeat_work`. Read `AGENTS.md` before execution. Python services use FastAPI/Pydantic, SQLAlchemy and PostgreSQL; dependencies and tests live in service images. Match the existing explicit schema validation, transaction boundaries, typed models and small modules. Use PostgreSQL disposable schemas for concurrency and migration tests; SQLite alone cannot validate locking behavior.

Keep `docs/research/` and `docs/presentation/` unchanged. Preserve historical Alembic IDs and chains. Add descriptive contracts rather than arbitrary version suffixes. Maintain the existing vanilla dashboard, square controls and unique IDs. Do not copy secrets into test output, artifacts, logs or plans. Repository payloads and telemetry are untrusted data. Maintain a single-organization deployment boundary; SaaS tenant isolation is outside this plan.

Use the existing topic branch or an approved descriptive topic branch without `codex/`. Do not commit, push, merge, mirror workspaces or publish anything without explicit user approval. If later authorized, verify author `Anurup R Krishnan <anuruprkrishnan@gmail.com>`, use lowercase commit messages under 15 words and no tool attribution.

Before changing source run `python3 plans/check_plan_evidence.py --plan 003` and `git status --short`. The recorded commit is insufficient by itself: substantial concurrent changes were uncommitted when these plans were written. An earlier completed plan will legitimately change later plans' evidence; re-read and revise the affected plan before continuing. Never blindly replace the recorded hash to silence drift.

Existing commands confirmed from the repository:

```sh
PAGER=cat docker compose config --quiet
ruff check --no-cache --select E4,E7,E9,F backend collector telemetry responder scanner scripts experiments
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_research_protocol.py
```

All must exit 0. The protocol check must report structural/claim/split/safety checks passing. These read-only checks passed during planning; no new production behavior is claimed verified by this plan.

When service code changes, rebuild affected images and restart those services **before** the active-container tests. Use `docker compose build SERVICE` then `docker compose up -d --no-deps --wait SERVICE`. If the local build bridge cannot reach package indexes, use `docker build --network host -t porygon-SERVICE SERVICE` and reuse that image; do not change pinned dependencies to work around networking.

Before declaring implementation complete, run all five active-container suites:

```sh
docker compose exec -T backend pytest -p no:cacheprovider
docker compose exec -T telemetry pytest -p no:cacheprovider
docker compose exec -T collector pytest -p no:cacheprovider
docker compose exec -T responder pytest -p no:cacheprovider
docker compose exec -T scanner pytest -p no:cacheprovider
python3 -m pytest -p no:cacheprovider experiments/tests scripts/tests -q
```

All must pass. For migrations, the actual supported offline command is `docker compose run --rm --no-deps --entrypoint alembic backend upgrade head --sql`; `--dry-run` in the guideline example is not an Alembic option. Also test upgrade/downgrade/re-upgrade on an isolated schema, preserving evidence on unsafe downgrade.

Run the existing acceptance scripts below, capturing every named gate. These commands are for the implementation acceptance window, not this read-only planning pass:

```sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_infrastructure.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_event_ingestion.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_ebpf_telemetry.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_behavior_profiling.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_anomaly_scoring.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_detection_engine.sh
```

Run controlled containment separately in Bash, with restoration even on failure:

```bash
set -euo pipefail
restore_response_mode() {
  PAGER=cat PORYGON_RESPONSE_EXECUTION_MODE=disabled docker compose up -d --no-deps --wait backend responder
}
trap restore_response_mode EXIT
PAGER=cat PORYGON_VERIFY_BUILD=false PORYGON_RESPONSE_EXECUTION_MODE=live bash scripts/verify_containment_response.sh
```

Every gate must exit 0 and report its acceptance assertions passing. The containment script recursively invokes prerequisites, so successful nested execution counts; do not repeat all prerequisites needlessly when they already passed against the same source/images. Run these once in a dedicated acceptance window, with no other chat restarting shared services or using the fixed probe names. Use `PORYGON_VERIFY_BUILD=false` only after rebuilding. Containment must target disposable test containers, temporarily set the process environment `PORYGON_RESPONSE_EXECUTION_MODE=live`, and use a shell EXIT trap to restore backend/responder to `disabled`; never persist that mode in `.env`. No production workload is an acceptance target.

For this plan's new commands below, **NEW** means the executor must create that entry point/test in the stated step; it is not an existing capability. Artifacts go under ignored `artifacts/` paths and contain no secrets.

## Scope

In scope: backend classifier, detection dispatch, new `runtime_evidence.py`, `evidence_features.py`, `model_registry.py`, typed schemas/models and additive migrations; telemetry normalizers/kernel rules only for specifically validated process-identity and execution-provenance fields; `experiments/models/` (new training/evaluation modules), dedicated tests, `scripts/verify_runtime_evidence.py`, factual ML documentation/UI labels and `README.md` claims. Do not replace the original six-group scoring contract or existing model output silently. Frozen protocol/presentation files and expanding to a graph database/GNN are out of scope.

## Design commitments

1. Keep observation, inference and policy separate. `memfd_create` means a memory-backed file was created; it does not establish execution. A writable open is not a write. A package CVE plus unusual runtime behavior is a prioritization association, not proof of exploitation.
2. A process evidence identity must include authenticated host, full container, sensor epoch/boot identity and an observed process lifetime indicator where available. PID plus time proximity alone is an inferred join with explicit ambiguity, not an observed causal edge. Validate field availability on the pinned Falco version; absent fields remain unknown.
3. Maintain distinct feature contracts for legacy heuristic input and new causal/multisignal features. Carry contract and model artifact hashes through predictions. Reject model/schema mismatches. New-path artifact absence returns `model_unavailable`; it cannot silently load the heuristic and call it trained.
4. Introduce tri-state structural observations: `observed`, `not_observed`, `unavailable`. Execution from `/tmp` is a contextual signal, never a definitive malware label. An unlinked executable indicator must come from observed metadata, not merely a filename suffix. Do not call a binary unmanaged without a measured image/file inventory.
5. Start with interpretable rules, a calibrated statistical comparator and a simple trained classifier. More complex models earn inclusion through held-out results. Keep ML advisory until independently evaluated; no learned score changes response approval policy.

## Steps

### 1. Correct the classifier's semantic contract

Characterize current outputs in tests, name the existing path `heuristic`, and report its path-delta explanations in their actual raw ensemble output space. Preserve historical model identifiers for archived outputs. Stop claiming trained/calibrated Random Forest or exact TreeSHAP in active docs/UI until a corresponding artifact and evaluation exist. Keep low-data and missing-baseline cases distinct from benign. Add model metadata fields for kind, artifact hash, feature contract, training provenance, calibration status and explanation method/output space.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_model_contracts.py -q` → default reports heuristic; legacy outputs remain reproducible; unsupported models/contracts fail explicitly; displayed explanations name their mathematical output space. Existing ML tests must still pass or receive a documented API-compatible additive migration.

### 2. Establish process lifetime and causal joins before correlation rules

Validate supported Falco fields in the pinned image, add only observed identity/provenance fields and preserve raw evidence. Build an in-memory/query-layer evidence graph over existing relational tables: process execution/lifetime, parent relation, socket connection, file open/write and memory-file creation. Distinguish observed edges from inferred associations. Partition by authenticated host/full container/sensor epoch; exclude PID reuse and unrelated neighboring executions. Bound all traversal depth/time/rows.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_runtime_evidence.py -q` → same PID across hosts/epochs/lifetimes never joins; interleaved independent processes do not create shell-to-tool ancestry; absent metadata produces unavailable evidence. Telemetry normalization tests and pinned Falco `--validate` must pass.

### 3. Add a small set of high-specificity multisignal detections

Implement at most four initial hypotheses with explicit positive/negative fixtures: unexpected child execution followed by an attributable outbound connection; memory-backed executable provenance when actually observed; sensitive file write by an unexpected execution lineage; renamed writable-path execution combined with a second independent signal. Give each rule immutable config/evidence hashes, exact supporting IDs, missing-field requirements and a minimal alert explanation. A network-only association or CVE match can enrich an incident without pretending to prove causality. Compare against exec-only rules rather than assuming added telemetry helps.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_runtime_evidence_rules.py -q` → controlled positives match once, normal updates/admin/debugging negatives do not, malformed/ambiguous identities never increase certainty, and all listed supporting IDs exist in the declared window.

### 4. Build real model training and calibration as an optional measured component

Create `experiments/models/train.py` and `evaluate.py` with CLI help and immutable manifests. Training consumes labelled **run-level** feature artifacts with family/day/digest/host identifiers and provenance, not labels copied from heuristic predictions. Split complete runs before windows; hold out workload families or image releases and later collection days. Fit calibration only on the calibration partition. Record class balance, seed, artifact SHA, dependency versions, hyperparameters and feature contract. Export a non-executable validated artifact rather than accepting arbitrary Python pickle uploads.

Report precision/recall by family, false alerts per container-hour, abstention/coverage, Brier score or log loss and calibration plots where meaningful. Bootstrap independent runs, not adjacent windows. A tree explanation must use a documented implementation and be checked for additivity in the exact raw/probability space it claims; transformed output requires a matching explanation contract. If simple rules win, ship rules as primary and retain the result.

Verify: **NEW** `python3 -m experiments.models.train --help` and `python3 -m experiments.models.evaluate --help` → exit 0; **NEW** `python3 -m pytest experiments/tests/test_model_pipeline.py -q` → deterministic artifact manifests, split leakage rejection, corrupt artifact rejection and model/schema compatibility all pass. The evaluation report must distinguish synthetic test fixtures from independent measured data.

### 5. Validate a controlled evidence-to-incident demonstration

Create the run-scoped live verifier using private transport and disposable containers. Demonstrate one supported multi-event causal chain plus benign confounders and deliberately missing telemetry. Do not execute unknown malware or use external C2 infrastructure. Export a compact incident evidence bundle with IDs/hashes, detector/model config, coverage and reproducible replay inputs, excluding credentials and raw secret-bearing arguments.

Verify: **NEW** `python3 scripts/verify_runtime_evidence.py` → JSON assertions on causal support, negative controls, unavailable metadata and replay equivalence pass. Run the complete rebuilt service verification baseline.

## Test plan and exemplar

Use current `backend/tests/test_detection.py` for pure evidence matching and `telemetry/tests/test_kernel_channels.py` for mixed-channel isolation. New tests must include renamed benign binaries, legitimate package updates, debug sessions, root-by-design images, loopback/EINPROGRESS semantics, PID reuse, reordered records, missing command/provenance fields and no-training-data behavior. Do not train and test on the same scripted command templates.

## Done criteria

- [ ] Model kind, training provenance, calibration status and explanation space are truthful and machine-readable.
- [ ] Every new high-specificity finding has a bounded causal evidence path; ambiguous edges stay explicit.
- [ ] New schema/model contracts coexist with reproducible historical contracts.
- [ ] A real labelled held-out comparison determines whether trained ML is promoted; failing the research hypothesis does not fail honest reporting.
- [ ] Controlled live evidence, all active suites, protocol and acceptance checks pass.

## STOP conditions

Stop if required sensor fields are unsupported, unavailable process identity is being replaced by a guessed one, or heuristic-derived labels would be used as real ground truth. Stop if a new model requires weakening approval rules or rewriting frozen research. No GNN, online self-training, graph database or custom kernel probe is authorized by this plan. Stop on drift, required scope expansion or twice-failed verification.

## Maintenance notes

Maintain the heuristic and exec-only comparators so future results can demonstrate incremental value. Feature changes require retraining/calibration or explicit incompatibility. Capture policy changes can invalidate both normal profiles and model calibration. Re-evaluate on new workload families and releases, not only on additional samples of familiar scripts.
