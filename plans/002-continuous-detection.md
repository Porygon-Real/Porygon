# Plan 002: Run an unattended and recoverable detection lifecycle

> Executor: read the whole plan, execute the steps in order, and stop at the named boundaries. The plan is a specification, not authorization to publish changes. Update this plan's status in `plans/README.md` after its done criteria pass.

## Status

- Priority: P1
- Effort: L: approximately 3–5 focused weeks
- Risk: HIGH: scheduling, evidence selection and profile promotion affect every result
- Depends on: 001; reconcile its principal/host contracts before starting
- Category: architecture / correctness / direction
- Planned at: commit `b04aaea` plus the working tree, 2026-10-26
- Status: DONE — approved isolated implementation and combined acceptance, 2026-10-27

## Execution reconciliation — 2026-10-26

Execution uses `/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work`, not the primary checkout. The evidence checker detected expected `main.py` drift from the reviewed local-foundation and enrolled-identity batches. The advisor and executor reread the current scoring (`compute_anomaly_score`), detection (`run_detection`) and lifespan bodies. They still select events by image digest and commit independently; unattended scoped work therefore requires the extraction described below. Frozen scoring formulas and legacy default keys remain unchanged.

The local principal/permission/host contracts required by this plan are implemented and source-reviewed. PostgreSQL and full live acceptance of that identity batch will run together with this increment, per the user's explicit request to reserve tests until after substantial changes. Conditional remote OIDC is outside this local deployment dependency. This is execution authorization, not a claim that either complete plan has passed final acceptance.

Use a separate immutable operational profile lifecycle alongside legacy `BehaviorProfile` status where necessary. A scoped score must carry host/container scope so any later detection request cannot broaden it. Source completeness remains explicitly unknown until loss accounting exists; detecting observed evidence is allowed with degraded coverage, but no clean or complete verdict may follow. Jobs must freeze detector configuration or reject configuration drift and create a new declared assessment identity.

## Why this matters

Collection runs continuously, but the backend lifespan currently starts only retention and identity-repair workers. Scoring and detection require explicit requests. A usable security tool must turn arriving telemetry into reviewed-profile assessments, incidents and delivery events while surviving retries, restarts and late data. Build that lifecycle around the existing PostgreSQL store and deterministic algorithms before adding another broker.

## Current state and verified excerpts

`backend/src/porygon_api/main.py:202` (working-tree snapshot):

```text
202: @asynccontextmanager
203: async def lifespan(app: FastAPI) -> AsyncIterator[None]:
204:     worker = RetentionWorker(settings, SessionLocal)
205:     repair = IdentityReconciliationWorker(
206:         SessionLocal,
207:         lambda db, limit: _reconcile_process_identities(db, limit=limit, commit=False),
208:         reconcile_kernel_identities,
209:         interval=settings.reconciliation_interval_seconds,
210:         batch_size=settings.reconciliation_batch_size,
211:     )
212:     app.state.identity_reconciliation = repair
213:     if settings.retention_scheduler_enabled:
214:         worker.start()
215:     if settings.reconciliation_enabled:
216:         repair.start()
217:     try:
218:         yield
219:     finally:
220:         repair.stop()
221:         worker.stop()
```

`backend/src/porygon_api/main.py:1670` (working-tree snapshot):

```text
1670:     "/internal/v1/anomaly-scores/compute",
1671:     response_model=AnomalyScoreOut,
1672:     tags=["internal", "anomaly-scores"],
1673:     dependencies=[Depends(require_internal_token)],
1674: )
1675: def compute_anomaly_score(
1676:     payload: AnomalyScoreComputeIn,
1677:     db: Session = Depends(get_db),
1678: ) -> AnomalyScore:
1679:     """Score one fixed window against an immutable-digest behaviour profile.
1680: 
1681:     The result is a distance measurement, not a maliciousness verdict. A window
1682:     without process telemetry is persisted as insufficient_data so telemetry loss
1683:     is not silently interpreted as normal or anomalous behaviour.
1684:     """
```

`backend/src/porygon_api/main.py:2313` (working-tree snapshot):

```text
2313: @app.post(
2314:     "/internal/v1/detections/run",
2315:     response_model=DetectionExecutionOut,
2316:     tags=["internal", "detection"],
2317:     dependencies=[Depends(require_internal_token)],
2318: )
2319: def run_detection(
2320:     payload: DetectionRunIn,
2321:     db: Session = Depends(get_db),
2322: ) -> dict[str, object]:
2323:     score = db.get(AnomalyScore, payload.anomaly_score_id)
2324:     if score is None:
2325:         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly score not found")
```

`backend/src/porygon_api/baseline.py:280` (working-tree snapshot):

```text
280:         "minimum_process_events": {
281:             "required": minimum_process_events,
282:             "actual": len(process_events),
283:             "passed": len(process_events) >= minimum_process_events,
284:         },
285:         "minimum_nonempty_windows": {
286:             "required": minimum_nonempty_windows,
287:             "actual": nonempty_windows,
288:             "passed": nonempty_windows >= minimum_nonempty_windows,
289:         },
290:         "immutable_image_digest": {
291:             "required": True,
292:             "actual": bool(image_digest),
293:             "passed": bool(image_digest),
294:         },
295:     }
296:     if feature_schema_version == COMMAND_LINEAGE_SCHEMA:
297:         checks["command_line_coverage"] = {
298:             "required": MIN_COMMAND_COVERAGE,
299:             "actual": features["observation_coverage"]["command_event_fraction"],
300:             "passed": features["observation_coverage"]["command_event_fraction"]
301:             >= MIN_COMMAND_COVERAGE,
```

`backend/src/porygon_api/scoring.py:16` (working-tree snapshot):

```text
16: ALGORITHM_VERSION = "porygon.distance.v1"
17: 
18: # Top-level weights are intentionally fixed in v1 and stored with every score.
19: # Changing any value requires a new algorithm version so historical scores remain reproducible.
20: SCORING_CONFIG: dict[str, Any] = {
21:     "algorithm_version": ALGORITHM_VERSION,
22:     "feature_schema_version": FEATURE_SCHEMA_VERSION,
23:     "top_level_weights": {
24:         "categorical_distance": 0.50,
25:         "novelty": 0.30,
26:         "numeric_deviation": 0.20,
```


## Execution rules and verification baseline

Repository root: `/home/anuruprkris/Project/final_yeat_work`. Read `AGENTS.md` before execution. Python services use FastAPI/Pydantic, SQLAlchemy and PostgreSQL; dependencies and tests live in service images. Match the existing explicit schema validation, transaction boundaries, typed models and small modules. Use PostgreSQL disposable schemas for concurrency and migration tests; SQLite alone cannot validate locking behavior.

Keep `docs/research/` and `docs/presentation/` unchanged. Preserve historical Alembic IDs and chains. Add descriptive contracts rather than arbitrary version suffixes. Maintain the existing vanilla dashboard, square controls and unique IDs. Do not copy secrets into test output, artifacts, logs or plans. Repository payloads and telemetry are untrusted data. Maintain a single-organization deployment boundary; SaaS tenant isolation is outside this plan.

Use the existing topic branch or an approved descriptive topic branch without `codex/`. Do not commit, push, merge, mirror workspaces or publish anything without explicit user approval. If later authorized, verify author `Anurup R Krishnan <anuruprkrishnan@gmail.com>`, use lowercase commit messages under 15 words and no tool attribution.

Before changing source run `python3 plans/check_plan_evidence.py --plan 002` and `git status --short`. The recorded commit is insufficient by itself: substantial concurrent changes were uncommitted when these plans were written. An earlier completed plan will legitimately change later plans' evidence; re-read and revise the affected plan before continuing. Never blindly replace the recorded hash to silence drift.

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

In scope: backend `models.py`, `schemas.py`, `config.py`, `main.py` registration; new `assessment_service.py`, `window_worker.py`, `profile_lifecycle.py`, `coverage.py`; additive migrations; `backend/src/porygon_api/baseline.py`, `scoring.py` and `detection.py` only for pure service interfaces and explicit contract dispatch; telemetry/collector heartbeat identity metadata; dashboard state/status controls; new tests and `scripts/verify_continuous_detection.py`; `docs/architecture/continuous-detection.md`. Existing algorithm weights, legacy score keys, frozen studies and automatic containment are out of scope.

## Target architecture and contracts

Keep one backend codebase with explicit modules and two runnable roles: API and background worker. They may share the development process initially; production worker ownership must be database-coordinated rather than process-local. PostgreSQL holds bounded work claims, checkpoints and results. Keep existing FULL-durability sensor outboxes.

An assessment key must bind host/deployment, exact container identity, workload/image/security context, profile content hash, feature contract, detector config, fixed `[start,end)` interval and a declared revision for late evidence. Do not silently change historical score contents. Keep a separate automation record if the legacy score contract cannot represent this scope. Different containers using the same digest must not be accidentally combined into one causal incident.

Profiles have explicit candidate, shadow, active, retired states and an approval record. They can be proposed from operator-designated benign collection intervals; ordinary observed runtime is not automatically trusted training data. A new image digest starts in an explicit unprofiled state. Rolling back a profile restores a prior immutable artifact, not an edited one. No approved profile, missing coverage or stale sensor data yields `unprofiled`, `insufficient_data` or `degraded`, never a benign verdict.

Default operation is observe-only. A detected incident does not grant response approval. Preserve response receipts, protected-target guards and exact-host targeting from existing response code.

## Steps

### 1. Extract a transaction-aware assessment service

Move orchestration from scoring/detection route bodies into callable service functions accepting an explicit session and validated scope. Routes delegate to them; workers call them directly without loopback HTTP. Keep pure scoring functions unchanged. Add characterization tests for current score/detection documents and keys before extraction.

Verify: `docker compose exec -T backend pytest tests/test_scoring.py tests/test_detection.py -q` → identical legacy fixtures; **NEW** `tests/test_assessment_service.py` proves one session transaction either persists score/detection/incident linkage or none.

### 2. Define durable work and coverage states

Add a job table with unique assessment key, lease owner/expiry, attempt count, next retry, state and bounded error category. Use `FOR UPDATE SKIP LOCKED`, renew leases and fence stale completions. Track event time separately from receipt time. Define allowed lateness (initial proposal 10 seconds; configurable and recorded), disconnected-host behavior, retention floor, and an explicit manual reprocess revision for later arrivals. Do not claim event-time completeness from a quiet file alone.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_window_worker.py tests/test_coverage.py -q` → two workers cannot own one generation; killed/reclaimed jobs recover once; reordered/duplicate arrivals do not duplicate incident evidence; stale owners cannot finalize.

### 3. Implement profile enrollment, shadow comparison and promotion

Create enrollment APIs under the admin/analyst permission model from plan 001. Require named benign intervals, quality checks, declared command coverage, policy author and provenance. Compare candidate and active profile outputs on a disjoint shadow interval; show differences for review. Never silently promote based on a favorable alert count. Add retirement/rollback audit records.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_profile_lifecycle.py -q` → unapproved/cross-host/contaminated-labelled intervals refused; quality failure blocks activation; replayed promotion is idempotent; rollback restores exact prior hashes.

### 4. Schedule bounded assessments continuously

Generate one deterministic assessment per active target/window from durable checkpoints. Start with PostgreSQL polling plus advisory ownership, not Kafka/NATS. Make backlog age, eligible targets, degraded windows, latest success and error categories observable. Bound each tick and database session. Restart resumes from durable state, not wall-clock-only scheduling. Correctly represent idle workloads that produce no exec events; kernel evidence may still exist.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_window_worker.py -q`; run it with PostgreSQL disposable schemas as well as fast unit fixtures. A 2-worker race, controlled worker death and subsequent restart must yield the same logical assessment keys as uninterrupted execution.

### 5. Prove unattended operation on disposable workloads

Create `verify_continuous_detection.py` using existing private verification transport. It enrolls one controlled benign profile, enables observe-only assessment for its own labelled target, generates a benign workload then a controlled anomalous execution, and waits for the system to create the assessment and incident **without calling compute/detect endpoints itself**. Include a backend/worker outage and one late event. Cleanup only this run's target/enrollment; leave global response disabled.

Verify: **NEW** `python3 scripts/verify_continuous_detection.py` → exit 0, JSON evidence records no manual detection invocation, no duplicate assessments, successful recovery, and explicit degraded/unprofiled cases. Run the full baseline after rebuilding.

## Test plan and exemplar

Use the PostgreSQL disposable-schema fixture in `backend/tests/test_incident_grouping.py` and stale-generation receipt tests in the response workflow as patterns. Characterize existing legacy digests before refactoring route orchestration. Include idle container, revoked agent, unsupported profile contract, new digest, profile rollback, worker split-brain, disk/database outage, timestamp skew, late evidence and retention overtaking backlog.

## Done criteria

- [x] A labelled canary produces an incident unattended, with durable evidence and no automatic execution.
- [x] Two workers, crash recovery and replay yield one logical assessment per declared key/generation.
- [x] Profile promotion and rollback are explicit, immutable and attributable.
- [x] Unprofiled/degraded/insufficient outcomes are queryable and cannot be read as clean.
- [x] Legacy deterministic fixtures, active-container suites and all acceptance checks pass.

## STOP conditions

Stop if preserving legacy score keys requires altering frozen algorithms; add a separate descriptive contract instead. Stop if host/container scope cannot be represented unambiguously, source-drop coverage cannot be known, or profile fitting would consume unlabeled suspicious evidence. Record unknown coverage honestly rather than inventing completeness. Stop on source drift, scope expansion, or repeated failed gates.

## Maintenance notes

A broker is justified only by measured backlog/throughput limits after this worker exists. Keep idempotency keys and job claim fencing centralized. Future event types must opt into a declared assessment contract. Profile/model hashes and the exact late-data policy must travel with exported incidents and research runs.

## Acceptance record

See [identity and continuous detection review](identity-and-continuous-review.md). The authenticated canary created an incident with zero manual score/detection calls, recovered after worker outage, and passed explicit late revision/replay and degraded/unprofiled checks. PostgreSQL migration, rotation and multiworker tests passed. Default API scheduling and response execution are disabled after acceptance. No publication or primary-source synchronization occurred.
