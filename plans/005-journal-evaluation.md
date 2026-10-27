# Plan 005: Create a falsifiable study and reproducible journal evidence

> Executor: read the whole plan, execute the steps in order, and stop at the named boundaries. The plan is a specification, not authorization to publish changes. Update this plan's status in `plans/README.md` after its done criteria pass.

## Status

- Priority: P1
- Effort: L: 6–10 focused weeks after design freeze, plus collection/review time
- Risk: HIGH: leakage or post-hoc redesign can invalidate the main conclusions
- Depends on: 002 and 003 for implementation freeze; 004 for capture/overhead evidence; design work may start now
- Category: research / correctness / tests / documentation
- Planned at: commit `b04aaea` plus the working tree, 2026-10-26
- Status: IN PROGRESS — remaining engineering source batch; all execution checks deferred until combined source freeze

## Execution reconciliation — 2026-10-27

The user explicitly requested completing all remaining engineering before testing. The sole executor works in `/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work`. Source reads, repository searches, installed capability inventory and official documentation review are allowed during implementation; test suites, checker scripts, CLI smoke tests, lint, builds, benchmarks and live acceptance wait until the combined003–005 source freeze. The prior accepted identity/continuous increment remains the baseline. No primary source edits, commits, merge, push or publication are authorized.

The advisor reread current classifier feature extraction, process/kernel models, incident grouping, sensor normalizers/spools/Compose configuration, study split consumption and the unconditional confirmatory refusal. Expected changes from the accepted earlier plans require explicit contract reconciliation rather than replacing evidence hashes. Current process/kernel rows lack persisted lifetime/epoch metadata, so new causal paths must be additive and abstain for legacy/missing metadata. Installed pinned Falco's read-only field inventory supports process/parent epoch-start timestamps, PID namespace start, executable writable and memfd provenance. See the [official supported fields](https://falco.org/docs/reference/rules/supported-fields/) and [metrics documentation](https://falco.org/docs/concepts/metrics/); runtime validation still waits until the final acceptance window.

The research executor must preserve the frozen stratified, preconstructed assignment policy and comparator matrix. Existing modulo pilot assignment is a distinct historical convenience, not an interchangeable confirmatory policy. Engineering tools can be completed now; independent measured training/evaluation, a three-node capacity result and seven-day soak remain empirical gates requiring actual collection. No synthetic fixture or software check can mark those gates complete.

## Why this matters

The repository already has a useful frozen profile-scope question, sample-size machinery and conformance checks. However, the confirmatory command explicitly refuses even after review approval, and the convenience study analysis records split labels but selects all-but-last runs as fit data rather than using those labels. Treat current study outputs as pilot evidence. Build a genuine confirmatory path and a separate prospective extension for new runtime evidence before collecting paper results.

## Current state and verified excerpts

`experiments/run.py:463` (working-tree snapshot):

```text
463: def confirmatory(protocol: Path) -> None:
464:     """Always refuse. No confirmatory runner exists; this only reports exactly why
465:     collection is not currently permitted.
466: 
467:     The refusal reason comes from `scripts/review_gate.py:gate_state()` -- the single
468:     source of truth for whether the protocol is frozen and both independent human
469:     reviews are in -- rather than a generic string-grep against the protocol text, so
470:     every specific blocking reason it names (per-role approval problems, reviewer
471:     independence) is surfaced. `gate_state()` always reads the canonical protocol
472:     document at its own fixed path; `protocol` is accepted for CLI/signature
473:     compatibility but does not change what is checked.
474:     """
475:     from experiments.sample_size import _load_review_gate
476: 
477:     review_gate = _load_review_gate()
478:     state = review_gate.gate_state()
479: 
480:     if state.get("confirmatory_permitted"):
481:         # The review gate itself is satisfied, but this codebase still has no real
482:         # confirmatory collection path -- that is a separate, deliberate gap, not
483:         # something this function is implementing.
484:         raise ArtifactError(
485:             "confirmatory runner is intentionally gated until the approved workload matrix "
486:             "is implemented; the review gate reports confirmatory_permitted=true, but no "
487:             "real confirmatory collection path exists in this codebase yet"
```

`experiments/study.py:254` (working-tree snapshot):

```text
254: def stage_splits(ctx: dict) -> dict:
255:     trials = ctx.get("trials", [])
256:     # A run is the independent unit. Every trial inside one run inherits that run's split.
257:     records = [{"run_id": t["trial_id"], "split": assign_split(t["trial_id"])} for t in trials]
258:     check_split_isolation(records)
259:     ctx["splits"] = {r["run_id"]: r["split"] for r in records}
260:     counts: dict[str, int] = {}
261:     for record in records:
262:         counts[record["split"]] = counts.get(record["split"], 0) + 1
263:     return {
264:         "unit_of_analysis": "complete container run",
265:         "assignment": "deterministic from the run identifier, computed before analysis",
```

`experiments/study.py:323` (working-tree snapshot):

```text
323:     outcomes = []
324:     for digest, group in by_digest.items():
325:         group.sort(key=lambda t: t["timeline"]["setup_started_at_utc"])
326:         if len(group) < 2:
327:             outcomes.append({"image": digest, "status": "insufficient_runs",
328:                              "reason": "a held-out window requires at least two runs"})
329:             continue
330:         fit, held_out = group[:-1], group[-1]
331:         start = min(t["timeline"]["setup_started_at_utc"] for t in fit)
332:         end = max(t["timeline"]["cleanup_finished_at_utc"] for t in fit)
333:         try:
334:             profile = _post(base, "/internal/v1/baselines/build", {
335:                 "image_digest": digest,
336:                 "training_start": start,
337:                 "training_end": end,
338:                 "window_seconds": ctx["window_seconds"],
339:                 "minimum_process_events": 20,
340:                 "minimum_nonempty_windows": 3,
341:                 "approved_by": "study-orchestrator",
342:                 "approval_reference": f"experiments.study run={ctx['run_id']}",
```

`experiments/study.py:425` (working-tree snapshot):

```text
425: def _run_evidence_class(run_dir: Path | None) -> tuple[str, bool]:
426:     """Derive the study's evidence class from the pilot run's own recorded facts.
427: 
428:     `stage_protocol` reports whether the *protocol document* currently permits
429:     confirmatory collection, but that is independent of what the *run actually is*.
430:     A confirmatory label requires the run itself having gone through real confirmatory
431:     collection (`run.json`'s own `research_eligible` flag) AND, as a second, stricter
432:     gate, the run's own directory passing every frozen-protocol conformance check
433:     (`experiments/conformance.py:check_run_conformance`). Either condition failing
434:     narrows the label to pilot -- neither can ever widen it.
435: 
436:     No confirmatory collection path exists yet -- `stage_collect` only ever calls
437:     `run_pilot`, whose run.json always records `kind: "real_container_pilot"` /
438:     `research_eligible: false` -- so in practice this always resolves to pilot/False for
439:     any run this pipeline produces today, and the conformance check below is never even
440:     reached, regardless of protocol status, until a real confirmatory runner exists (see
441:     run.py's `confirmatory`, which is an intentional stub). The conformance gate is
442:     defense-in-depth for whenever that changes: it cannot be observed to do anything
```

`docs/research/research-protocol.md:11` (working-tree snapshot):

```text
11: ## Problem statement and contribution
12: 
13: Container runtime behaviour varies across workloads, image versions, replicas,
14: load, maintenance, and deployment security context. A profile that is too broad
15: may hide useful deviations; a profile that is too narrow may fragment its data
16: and fail on ordinary change. Porygon tests where that trade-off lands for its
17: current Docker lifecycle and process-execution evidence.
18: 
19: Behavioural profiling is prior art. The proposed contribution is a reproducible
20: profile-scope comparison, with explicit insufficient-profile outcomes, against
21: global, mutable-tag, digest-only, and digest-plus-context arms. The experiment
22: does not preselect a winning arm.
23: 
24: Primary research question (`RQ-001`): **Does conditioning runtime behavioural
25: profiles on immutable image identity plus deployment context reduce benign
26: false alarms while preserving controlled-scenario detection compared with
27: global, mutable tag, and digest-only baselines?**
28: 
29: Secondary questions test calibration/version drift (`RQ-002`) and whether the
30: measured capture path and overhead are acceptable for a single-host research
31: sensor (`RQ-003`).
```

`docs/research/claims-boundaries.md:7` (working-tree snapshot):

```text
7: Behaviour profiling is prior art. Falco, eBPF telemetry, immutable image
8: digests, calibrated rarity methods, deterministic rules, and the compared
9: statistical components are not Porygon inventions. The proposed contribution
10: is the falsifiable, reproducible comparison of global, mutable-tag, digest-only,
11: and digest-plus-context profile scopes under the frozen protocol.
12: 
13: ## Claims allowed before confirmatory evaluation
14: 
15: - `CLM-A001`: Porygon is a Docker-first research prototype that records Docker
16:   lifecycle/exec evidence and Falco process-execution evidence.
17: - `CLM-A002`: The current implementation can build versioned digest-bound
18:   profiles, persist explainable distance evidence, apply deterministic rules,
19:   and retain an auditable incident lifecycle.
20: - `CLM-A003`: Event ingestion acceptance measured equality from Docker's retained event
21:   API to PostgreSQL for its bounded canary; eBPF telemetry measured equality from the
22:   Falco JSON file to PostgreSQL for its bounded canary. Neither result proves
23:   zero loss before those measured boundaries.
24: - `CLM-A004`: Anomaly outputs are rarity/distance evidence and are **not an
25:   attack probability**. Deterministic matches are evidence, **not proof** of
26:   compromise. Scanner findings show package matches and are **not proof** of
```

`experiments/artifacts.py:80` (working-tree snapshot):

```text
80:         return sha256_bytes(existing)
81:     with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
82:         temporary = Path(handle.name)
83:         handle.write(encoded)
84:         handle.flush()
85:         os.fsync(handle.fileno())
86:     os.replace(temporary, path)
```


## Execution rules and verification baseline

Repository root: `/home/anuruprkris/Project/final_yeat_work`. Read `AGENTS.md` before execution. Python services use FastAPI/Pydantic, SQLAlchemy and PostgreSQL; dependencies and tests live in service images. Match the existing explicit schema validation, transaction boundaries, typed models and small modules. Use PostgreSQL disposable schemas for concurrency and migration tests; SQLite alone cannot validate locking behavior.

Keep `docs/research/` and `docs/presentation/` unchanged. Preserve historical Alembic IDs and chains. Add descriptive contracts rather than arbitrary version suffixes. Maintain the existing vanilla dashboard, square controls and unique IDs. Do not copy secrets into test output, artifacts, logs or plans. Repository payloads and telemetry are untrusted data. Maintain a single-organization deployment boundary; SaaS tenant isolation is outside this plan.

Use the existing topic branch or an approved descriptive topic branch without `codex/`. Do not commit, push, merge, mirror workspaces or publish anything without explicit user approval. If later authorized, verify author `Anurup R Krishnan <anuruprkrishnan@gmail.com>`, use lowercase commit messages under 15 words and no tool attribution.

Before changing source run `python3 plans/check_plan_evidence.py --plan 005` and `git status --short`. The recorded commit is insufficient by itself: substantial concurrent changes were uncommitted when these plans were written. An earlier completed plan will legitimately change later plans' evidence; re-read and revise the affected plan before continuing. Never blindly replace the recorded hash to silence drift.

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

In scope: `experiments/run.py`, `study.py`, `conformance.py`, `analysis.py`, `sample_size.py`, `artifacts.py` only for justified implementation and strict dispatch; new `experiments/confirmatory.py`, `protocols/runtime-evidence-study.json`, `validate_study_plan.py`, comparator adapters and experiment tests; `scripts/validate_paper_evidence.py`; new `docs/studies/runtime-evidence-study.md` and `docs/studies/related-work-matrix.md`. Treat `docs/research/` and `docs/presentation/` as read-only. Do not edit the paper, choose a journal or claim novelty/superiority in this plan. Publishing data or submitting a paper remains a separate user-authorized action.

## Research choice

Keep the existing frozen study as the **profile-scope comparison** it actually specifies: global, mutable tag, digest, digest-plus-context under its defined exec/lifecycle evidence and fixed comparator settings. Implement its missing runner faithfully if still worth completing. Do not insert new kernel features, thresholds or ML into the frozen experiment.

Proposed extension for 2027: **Can deployment-scoped behavioral profiles combined with causal multi-event evidence reduce false alerts on benign maintenance and unseen releases, while preserving detection and honestly abstaining under incomplete telemetry?** This is a hypothesis to test, not a novelty claim. A focused systems evaluation with negative results is preferable to an unsupported claim of universal threat classification.

Separate three questions: profile identity under change; incremental value of causal/multisignal evidence; behavior when telemetry/metadata are incomplete. Choose one primary contrast and endpoint for the extension before data collection; other contrasts are secondary or exploratory with an explicit multiplicity policy. Preserve the original study's own primary endpoints unchanged.

## Steps

### 1. Close the literature and claims gap before locking the extension

Build `related-work-matrix.md` from original papers and official project documentation for runtime rules, behavioral anomaly detection, provenance/causal correlation and calibrated abstention. Record source/date, threat assumptions, telemetry, dataset availability, split unit, false-positive measurement, overhead and comparison feasibility. Include Falco and at least one maintained alternative sensor/detector as practical baselines where compatible. Claim no invention of eBPF, digests, behavioral profiles or explanation algorithms. Compare the intended contribution to closest work; stop and redesign the question if it is only an untested feature combination.

Verify: **NEW** `python3 -m experiments.validate_study_plan --plan experiments/protocols/runtime-evidence-study.json --check-sources` → every planned claim has a cited primary source or explicit empirical test. Implement the validator in this plan; do not fabricate source coverage to satisfy it.

### 2. Fix split consumption and build two explicitly separate runners

Change `stage_analysis` to select fit/calibration/test inputs from the actual assignment manifest, with benign-only approved fit data and no interval spanning held-out collection. A requested run may fail for insufficient eligible fit data; do not quietly backfill from test runs. Write regression fixtures proving that a test run earlier in chronological order cannot enter fitting.

Implement `experiments/confirmatory.py` for the existing frozen workload/arm matrix using current review/sample-size/conformance gates. Replace `confirmatory()`'s unconditional refusal only after the runner exists and dry-run planning verifies the exact matrix. Do not mark pilot records eligible by toggling JSON flags. Add a separate descriptive protocol dispatcher for the new extension, with its own artifact namespaces and validators. Keep the frozen protocol loader/checksum untouched.

Verify: **NEW** `python3 -m pytest experiments/tests/test_split_consumption.py experiments/tests/test_confirmatory_execution.py -q` → split contamination refused; missing approvals/sample-size lock stop before launching containers; correct plans enumerate every required cell; pilot evidence cannot be relabelled confirmatory. Existing `test_study_conformance.py` refusal tests must be deliberately replaced with stronger runner/gate tests, not simply deleted.

### 3. Specify workload diversity, labels and deployment change

The prospective matrix must include services from several distinct workload families, at least two image releases for selected families, benign startup/steady/burst/backup/update/admin/debug intervals, and controlled threat scenarios matched to actual observed capabilities. Include renamed tools, legitimate writable-path execution, root-by-design images, independent process interleaving, missing parent metadata, capture loss and delayed delivery. Use harmless local reproductions, no public C2 or unreviewed malware. Ground truth comes from the controlled scenario controller and corroborating evidence, never from the detector's own labels.

Assign complete independent collection runs before window extraction. Keep family/release/host/day grouping explicit. Use family-held-out and forward-in-time evaluations where the claims require them; retain a separate calibration set. Record attack scenario prevalence; do not present experimental precision as real-world deployment precision. Use fit-only contamination experiments with declared injection levels and independent ground truth. Freeze every workload image by digest and archive configuration/resource context.

Verify: **NEW** `python3 -m experiments.validate_study_plan --plan experiments/protocols/runtime-evidence-study.json` → no overlapping groups, missing labels, mutable image references or undefined endpoints; every scenario has a negative control and required sensor-field checklist.

### 4. Lock comparators, budgets, sample size and analysis

Compare rules-only; existing distance/profile methods; the legacy heuristic; new causal rules; and trained ML only if plan 003 produced a real artifact. Ablate causal linkage, structural features and kernel channels separately rather than treating the whole project as one opaque intervention. Run sensor/configuration controls so differing capture cost is not hidden. Freeze thresholds from fit/calibration evidence only.

Measure false alerts per container-hour and run-level FPR, recall by scenario/family, time-to-first evidence and incident, abstention/coverage, loss per observed boundary, CPU/RSS/disk and workload throughput/tail-latency overhead. For the frozen comparison use its exact prescribed tests/intervals. For the extension derive sample size from an independent pilot and lock it before test collection; if the available budget cannot reach power, narrow the question or report an exploratory study. Do not count neighboring windows as independent replicates. Record the planned handling of failures, missingness, exclusions and multiple comparisons in advance.

Verify: **NEW** `python3 -m pytest experiments/tests/test_study_design.py experiments/tests/test_analysis_replay.py -q` → incomplete lock/metric definitions fail, grouping is respected, missing captures cannot improve recall/FPR denominators, and deterministic replay produces identical tables from the same inputs.

### 5. Freeze, collect once, and release an auditable artifact

After exploratory development, record source/tree hashes, clean release artifacts, protocol/analysis hashes, model/profile hashes, environment and pilot/test split manifest. Future fixes produce an explicit deviation/new collection cohort; they do not silently rewrite the locked test analysis. Re-run paper evaluation after any detection-semantic change. Collect failed/excluded trials as first-class records. Ask an independent reviewer to reproduce the artifact on another Linux host if available; record self-reproduction honestly if no reviewer is available.

Package code, executable environment recipe, fixtures, raw de-identified event subsets or a justified access procedure, ground truth, locked design, full result tables and a one-command offline replay. Honor the user's CC BY 4.0 choice for dataset material whose rights permit that license; inventory third-party image/software/content licenses separately. Remove secret-bearing arguments before public export while retaining declared feature semantics and an audited transformation manifest. Do not publish automatically.

Verify: **NEW** `python3 scripts/validate_paper_evidence.py --run-dir "$PORYGON_STUDY_RUN_DIR"` → all claim-to-result links, hashes, split/lock times, comparator completeness, loss boundaries and exclusions validate; **NEW** `python3 -m experiments.confirmatory replay "$PORYGON_STUDY_RUN_DIR"` → regenerates declared analysis without network access and matches recorded table hashes. Add these entry points in scope. The existing `python3 experiments/validate_artifacts.py "$PORYGON_STUDY_RUN_DIR"` must continue to pass for its supported artifact contract.

## Test plan and exemplar

Use the existing pure conformance tests and `experiments/artifacts.py` atomic artifact pattern. Include chronology-vs-assigned-split disagreement, missing calibration partition, same family across held-out groups, incomplete sample-size lock, malformed model metadata, altered raw artifacts, excluded trial missing from accounting, protocol change mid-study, and unsupported observational claims. Synthetic fixtures validate software only; they do not support scientific detection claims.

## Done criteria

- [ ] Current study analysis consumes assigned splits; no held-out/attack-labelled run can enter benign fitting.
- [ ] The frozen confirmatory path implements its full approved matrix and gates; extension studies have separate prospective contracts.
- [ ] Locked comparators, primary contrast, sample size, missingness and analysis policy predate test collection.
- [ ] At least one complete measured study replays offline with matching hashes and explicit negative results where applicable.
- [ ] Every paper claim maps to a validated result or is removed; no window-level pseudoreplication.
- [ ] All experiment tests, frozen protocol integrity and the full implementation acceptance baseline pass before collection freeze.

## STOP conditions

Stop if implementing the extension requires editing frozen protocol files, if test outcomes have informed thresholds/model choices, or if raw labels merely repeat detector predictions. Stop if available resources cannot support the locked design: reduce scope prospectively or publish exploratory results, never silently shrink the sample. No journal acceptance, novelty or production safety guarantee follows from passing this plan. Stop on drift, scope expansion or repeated gate failures.

## Maintenance notes

The 2027 submission date is a planning horizon, not a deadline for manufacturing a favorable result. A revised core design requires a new prospective design and collection cohort. Preserve the frozen profile study as a historical comparison even if a different operational detector becomes the recommended product path. Source/licensing/data transformations must remain reproducible independently of the dashboard or AI auditor.
