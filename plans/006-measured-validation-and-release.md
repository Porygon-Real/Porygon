# Combined measured validation and release plan

Status: LOCAL ENGINEERING ACCEPTED; independent study, fleet capacity and soak gates remain open. Written 2026-10-30 against HEAD `96333df` in `/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work`.

## Baseline and reconciliation

This plan supersedes the remaining execution ordering in plans 003–005; it does not declare their empirical gates complete. Preserve the accepted dirty/untracked work. The previous accepted non-plan source tree hash is `427f59427d6719e1a851c622d5d23656d69a67369cd01a5f26f5d1c4291dbb7e`. See `engineering-acceptance-review.md` for evidence and limitations.

| Earlier work | Actual state | Remaining requirement |
|---|---|---|
| 001 trust | Local scoped service identities accepted | Remote HTTPS/OIDC only when an actual remote deployment needs it |
| 002 unattended detection | Accepted | Regression coverage in final combined battery |
| 003 causal evidence and optional model | Engineering implemented and accepted | Independently labelled run-level data, held-out calibration and promotion review |
| 004 operations | Health, outbox, restore, collector capacity, release tooling accepted locally | Complete durable ingestion receipt; three physical kernel/daemon nodes; real seven-day soak |
| 005 evaluation | Frozen confirmatory runner, split-safe analysis, prospective validator implemented | Independent human reviews, reviewed pilot/power lock, immutable image/run assignments, actual collection |

No new Kubernetes adapter, broker, UI redesign or paper work is needed to close these gates. Do not recreate implemented readiness reporting: `experiments/validate_study_plan.py:118–189` already reports missing locks, image identities and assignments.

## Vetted defects and priority

Leverage uses impact / effort × confidence. Scores below are ordinal triage inputs, not measured performance claims.

| Track | Category | Evidence | Impact / effort / confidence | Priority |
|---|---|---|---|---|
| C | Correctness/security | `experiments/real.py:34,922`; `experiments/study.py:152,176` hardcode primary-project telemetry/Postgres | 5 / 2 / 1 | First prerequisite for any pilot |
| B | Tooling/evidence correctness | `scripts/verify_event_ingestion.sh:315–336` only prints successful saturation; final evidence is written after subsequent failure points; `scripts/verify_all.sh:42–57` lets children inherit caller stdin | 4 / 2 / 1 | Parallel |
| A | Performance/measurement validity | `experiments/benchmarks/lab.py:19–54,601–630` repeatedly fetches and hashes full event ID sets and calculates full-window percentiles | 4 / 3 / 1 | Parallel |

Verified excerpts:

```python
# experiments/real.py:34
TELEMETRY_CONTAINER = "porygon-telemetry-1"
# experiments/real.py:922, inside _falco_observed subprocess argv
            TELEMETRY_CONTAINER,
# experiments/study.py:152, database sampling argv
        "porygon-postgres-1",
```

```python
# experiments/benchmarks/lab.py:34–35, called on each sample
  if sum(counts.values())>2000000:raise ValueError('Persisted identity bound exceeded')
  selected_ids.extend(db.scalars(select(model.event_id).where(*filters).order_by(model.event_id)))
# experiments/benchmarks/lab.py:604
                samples.append(capture(node, start_ns, observed_ns, control))
```

```bash
# scripts/verify_all.sh:48–50
  log "starting ${name}"
  "$@"
  local result=$?
# scripts/verify_event_ingestion.sh:336
pass "Collector recorded saturation and retained exactly 100 queued events without advancing past failures"
```

## Executor rules and isolation

Use separate scoped GPT-6 Luna executors in this existing isolated topic worktree. The advisor edits only plans/. Read AGENTS.md. Search identifiers across the entire repository before changing contracts. Preserve comments, type hints, scientific meaning and historical migration IDs. Never reveal secrets or dump environment/config objects. No commits, push, merge, branch rename, mirror writes, publishing, dependency installation or fabricated review/data. Never modify `docs/research/`, `docs/presentation/`, primary workspace or mirror. Do not touch unrelated accepted edits. Stop and report conflicting concurrent changes rather than overwriting them.

All source edits and test definitions must finish before running tests. Executors report changed files and proposed exact commands, then await the combined verification window. Build/restart only isolated project `porygon-service-trust`; never operate on primary project `porygon`. Keep containment disabled. Use persisted ignored shell wrapper files with stdin `/dev/null` for live verification, not inline-heredoc command streams.

## Track A — bounded benchmark observation

Owner: benchmark executor. Scope: `experiments/benchmarks/lab.py`, directly associated benchmark tests and operations documentation. Do not edit experiments/real.py, study.py, run.py, shell acceptance scripts or backend services.

1. Record observer metrics before changing behavior: full identity-query count, IDs materialized, sample elapsed time and exact final-query count. Attribute overhead to full-window identity/percentile work; do not claim measured production acceleration from a mock.
2. Separate cheap periodic health/counters/resources from exact final reconciliation. Periodic and recovery polls must not materialize event identity sets or calculate full-window percentiles. Final exact event ID set and logical-job duplicate/coverage/latency proof remain mandatory; missing fields remain unknown/failing, never zero-filled success.
3. Recovery should use cheap readiness/count/state polling followed by bounded exact reconciliation. Bound retries and preserve the source-window end and health-freshness checks. No continuous repeat of expensive queries when unchanged.
4. Add observer-cost/query-mode metadata and tests proving zero event-ID materializations in periodic samples, bounded exact calls, failure propagation, exact mismatch rejection and retained final latency proof. Keep existing trace consumers compatible or update all affected consumers within this scope.
5. Document what is measured and the remaining true three-node and soak requirements. No schema, index or broker changes without measured evidence.

Done: relevant benchmark tests pass in final window; exact final proof still fails on mismatched IDs; periodic sampling cost is quantitatively bounded by the regression contract. Any live performance results must state workload and measured cost, separately from test-double counts.

## Track B — durable acceptance evidence

Owner: evidence executor. Scope: `scripts/verify_event_ingestion.sh`, `scripts/verify_all.sh`, new small stdlib receipt helper if needed, directly related scripts tests, operations documentation. Do not edit experiment Python or microservices.

1. Persist private atomic, sanitized, run-bound receipts immediately after successful saturation and after persistence/replay checks, before later steps can fail. Include observed queue cap/current-run canary count, overflow before/after/delta, source host/run binding and script/source digest. Do not include credentials, raw events, payloads or command lines. Preserve earlier receipts on later failure; never label partial evidence complete.
2. Fail closed for missing, empty, stale or mismatched receipts in the ingestion completion path. Preserve existing public manifest contract; additions must be backward-compatible. Keep generic static checks distinct from empirical gates.
3. Prevent aggregate child commands consuming the wrapper's stdin; persist stage outcomes independently of final successful completion. Do not turn exit-zero/no-evidence into empirical acceptance.
4. Add tests for interrupted final stages retaining saturation receipt, mismatched/stale receipt rejection, child stdin isolation and nonzero status propagation.
5. Prepare one full live ingestion run in the final verification window with durable evidence and exact counts; this closes the previous targeted-only closure. Preserve tracked results/manifest baseline bytes if verification scripts update them incidentally.

Done: relevant tests pass; full live ingestion command exits zero and receipts demonstrate positive current-run canaries, positive saturation delta, exact API/PG unique counts, zero replay growth and empty final queue. Any failed command remains recorded as failed even if later targeted diagnostics succeed.

## Track C — explicit experiment runtime binding

Owner: experiment executor. Scope: `experiments/real.py`, `experiments/study.py`, `experiments/run.py`, environment/confirmatory integration and `scripts/private_api.py` plus its tests only where necessary to bind internal API transport to the selected exact backend, associated experiment tests and study documentation. Do not edit lab.py or shell acceptance scripts.

1. Search all hardcoded runtime service/container selectors repository-wide. Resolve experiment services from an explicit Compose project/context or explicit exact IDs. Validate inspected Compose labels/service names, daemon and host binding before workload/image/network creation. No silent fallback to `porygon-*` primary containers.
2. Thread validated binding through pilot source and storage collection, including Postgres/Falco helpers and any confirmatory callers. Record sanitized immutable runtime identity in run/environment artifacts. Reject changed binding on resume before workload launch. Existing artifacts without adequate binding must be explicitly unsupported or exploratory; never restamp old provenance.
3. Add tests for foreign-project/wrong-service/daemon mismatch/missing targets, explicit isolated project selection, resume drift and no subprocess workload launch on preflight failure. Keep protocol eligibility and independent-review gates intact.
4. Prepare a small, bounded exploratory pilot only after binding and regression checks pass. It must use pinned workload images, disposable labelled resources, local endpoints, containment disabled and `research_eligible=false`. Do not call it confirmatory, use it as an independent power pilot by assumption, or promote a model.

Done: targeted tests pass, selectors cannot accidentally read primary project, and a bounded real isolated pilot either produces source-bound exploratory artifacts or reports an exact safe preflight blocker without modifying primary services.

## Combined verification window

After all three executors declare source/test-definition freeze, run one combined host experiment/scripts suite using `.venv/bin/python -m pytest experiments/tests scripts/tests` (first verify directory names and collectability; this venv is Python 3.13). Use minimal synthetic test credentials only where backend imports require them, never print them. Run Ruff critical errors in check mode, shell syntax, `git diff --check` and protocol integrity. Re-run only affected failed tests after corrections.

AGENTS.md full required battery then runs once against explicit isolated Compose project: all five service unit suites, `python3 scripts/check_research_protocol.py`, and seven `scripts/verify_{infrastructure,event_ingestion,ebpf_telemetry,behavior_profiling,anomaly_scoring,detection_engine,containment_response}.sh` checks. Rebuild/restart changed microservice images before tests if any (none planned). Preserve baseline artifacts and disabled response state. A service-suite environmental blocker is reported rather than replaced with an invented success.

The verification owner must read each command's CLI before invoking it and persist sanitized statuses, logs and source identity under ignored `artifacts/local/combined-validation-*`. No inline multi-command heredoc wrapper. Inspect exit codes and evidence rather than relying on empty output. If a suite/fixture needs unsafe primary-project mutation, stop that gate and report its precise blocker.

## Next: empirical dependencies and execution order

1. After A–C and local acceptance, freeze source/release identity and regenerate local five-image/SBOM evidence if the accepted source hash changed. No public release or push is authorized.
2. Obtain two genuinely independent qualified human reviews and a reviewed independent pilot/sample-size lock. `scripts/review_gate.py:368–401` requires frozen status, all approvals and independent reviewers. Existing same-author approvals do not qualify. Keep frozen protocols intact; new approvals/evidence follow established gate inputs.
3. Populate prospective immutable image bindings and whole-run assignments, then run existing study validator in collection mode. Use its actual CLI help. Only collect confirmatory data after every lock passes. Replay analysis from immutable raw data; keep held-out families/days/runs separated. Optional learned-model promotion requires independently reviewed labels and calibration, not merely successful training.
4. Provide two additional explicitly authorized Linux nodes/Docker contexts. Current inventory has one daemon/context; containers are not independent nodes. Validate distinct daemon IDs and kernel boot IDs. Then execute the existing capacity contract: three nodes, 100 selected events/s/node for 60 minutes, five 60-second bursts, p95 assessment latency under 10 seconds after window close, and 30-minute control-plane outage with exact recovery and no logical duplicates.
5. Run a real 604800-second soak with daily bins, endpoint coverage and source-correlated canaries within five seconds. Short traces or simulation cannot satisfy this. Do not fabricate elapsed time, install hypervisors, provision remote machines or start unmanaged week-long background jobs.

External prerequisites are open, not source defects. Stop the dependent empirical stage if independent humans, valid locks, real nodes, pinned images, rights or storage are absent. Continue other independent engineering work and record what is missing. Never make a gate green by weakening thresholds, labels or provenance.

## Acceptance ledger

To be updated by the advisor after executor evidence: source changes, exact commands/statuses, durable artifact coordinates, remaining external prerequisites and review verdict. No completion claim until required local checks have actually run.

## Command appendix and drift check

Executors first compare `git diff --stat 96333df..HEAD -- IN_SCOPE_PATHS` and current excerpts; the accepted dirty baseline is expected, so compare rather than resetting. Stop on an unexplained concurrent edit. Follow the atomic JSON and explicit unknown conventions in `experiments/artifacts.py` and `experiments/environment.py`; match existing pytest fixtures in `experiments/tests/test_real.py` and disposable-script-copy tests in `scripts/tests/test_verification_status.py`.

Run these commands only in the combined verification window, with relevant new tests added to the first command:

```bash
.venv/bin/python -m pytest experiments/tests scripts/tests -q
/home/anuruprkris/.local/bin/ruff check --select E4,E7,E9,F experiments scripts
bash -n scripts/verify_event_ingestion.sh scripts/verify_all.sh
python3 scripts/check_research_protocol.py
git diff --check
```

Expected: zero exit status, except honest source-network unavailability in external citation validation must be separated from structural validation. The host tests may require synthetic `PORYGON_DB_PASSWORD`, distinct internal/operator tokens and `PYTHONPATH=backend/src`; use fixture credentials in the private wrapper and never echo them.

The service unit gate is `docker compose -p porygon-service-trust exec -T SERVICE pytest` for each of backend, telemetry, collector, responder and scanner. The live chain can run infrastructure once and containment→detection→scoring→profiling→eBPF once, then ingestion once: the nested checks cover the seven required scripts without repeating each whole chain. Only during the disposable containment gate may execution mode temporarily be `live`; a persisted wrapper must verify owned targets before enabling it and restore `disabled` on every exit. Outside that gate keep it disabled. Existing private `artifacts/local/live-acceptance-wrapper-20261030.sh` demonstrates these safeguards; prepare a new unique wrapper and evidence directory rather than overwriting old evidence.

Current external readiness commands (do not apply/write review decisions):

```bash
.venv/bin/python scripts/review_gate.py status --json
.venv/bin/python -m experiments.validate_study_plan --plan experiments/protocols/runtime-evidence-study.json
.venv/bin/python -m experiments.validate_study_plan --plan experiments/protocols/runtime-evidence-study.json --for-collection
```

Expected now: status reports independence not satisfied; design validation returns blockers; collection validation refuses incomplete locks. A refusal is correct safety behavior and is not accepted empirical evidence.

After real nodes and an opted-in disposable lab specification exist, measured entry points are:

```bash
.venv/bin/python -m experiments.benchmarks.run --lab-spec "$LAB_SPEC" --scenario sustained --rate 100 --duration 3600 --output "$FRESH_OUTPUT"
.venv/bin/python -m experiments.benchmarks.run --lab-spec "$LAB_SPEC" --scenario control-plane-outage --outage-seconds 1800 --duration 3600 --output "$FRESH_OUTAGE_OUTPUT"
.venv/bin/python -m experiments.benchmarks.run --lab-spec "$LAB_SPEC" --scenario soak --duration 604800 --output "$FRESH_SOAK_OUTPUT"
```

These are not executable substitutes for preparing approved opted-in lab nodes; every output directory must be new. Separate burst traces and required accepted-rate/latency/coverage checks follow the lab contract in `docs/operations/release-and-recovery.md`. Do not run them against this active project, which intentionally lacks lab opt-in labels.

### Execution checkpoint

Subagent usage limits interrupted the first implementation pass. Existing edits were preserved; benchmark and experiment executors resumed after the interruption. The receipt executor could not restart because the collaboration tool reported an agent thread limit, so its remaining review/completion is reassigned to the benchmark executor after that executor finishes Track A. No interrupted pass is counted as verified. All eight isolated services remain healthy; tracked result/verification manifest inputs remain unchanged at this checkpoint.

Track A and Track B subsequently reached source/test/documentation freeze. Track A removes repeated identity-set/percentile work from periodic and recovery polling while retaining one exact final snapshot and honest unknowns. Track B persists run/source-bound private receipts and interrupted aggregate status, enforces matching API/Postgres/replay counts and source-stage consistency, and isolates child stdin. These are implementation reports, not passing verification results; the joint window remains deferred until Track C freeze.

### Initial combined verification

The full host suite ran once: 337 passed, 2 skipped, 7 failed. The failures are assigned to the owning executors for diagnosis and affected-module rechecks; no full-host repetition is authorized without a new reason. Critical Ruff initially found one unused import, removed by the receipt executor. Shell syntax, protocol integrity, diff hygiene and secret-pattern scanning passed.

The five-service battery ran once. Telemetry 48, collector 29, responder 15 and scanner 13 passed. Backend's default SQLite test run reached its 64 MB container `/tmp` capacity (376 passed, 11 skipped, 14 fixture errors), so this attempt is not counted as passing. The exact temporary directory attributable to that run was removed. A justified backend recheck enabled `PORYGON_TEST_POSTGRES=1`, used a fresh `/dev/shm/porygon-combined-validation-20261030` test directory, and passed all 401 tests including PostgreSQL races/migrations. That successful run's temporary directory was also removed. Host filesystem capacity was not the issue. Logs/status JSON are retained privately under `artifacts/local/combined-validation-20261030/`.

### Focused corrections and live handoff

Track C corrected three fixture/assertion mismatches without changing runtime checks: bound Docker context in the benign hard-negative fixture, actual foreign-container error matching, and a valid binding in the fresh-directory confirmatory guard fixture. Its affected modules (`test_real.py`, `test_runtime_binding.py`, `test_study_conformance.py`) passed 73 tests.

Track A corrected the synthetic starting heartbeat and represents unavailable exact evidence as unknown in the summary while preserving explicit trace failure, mismatched IDs and other collection failures as failures. Track B corrected fixture validation time to follow persistence creation rather than falsely appearing future-dated. The affected benchmark reconciliation parametrization and ingestion receipt module passed 13 tests. Narrow critical Ruff passed; the earlier unused import was removed. The original passing tests were not needlessly rerun.

All five service suites now pass (401 backend with PostgreSQL, 48 telemetry, 29 collector, 15 responder, 13 scanner). The reviewed persisted wrapper `artifacts/local/live-acceptance-wrapper-20261030-final.sh` has been handed to the executor for one live acceptance run with stdin closed and fail-closed cleanup. The exploratory pilot remains deferred until that run finishes because acceptance intentionally recreates selected service containers.

External readiness was checked without applying or fabricating reviews: `review_gate.py status --json` exits 0 but reports `confirmatory_permitted=false` and reviewer independence false. Prospective design validation exits 0 with `design_valid=true`, `collection_ready=false`, and four blockers: independent pilot/sample-size lock, reviewed precollection lock, image identity matrix, immutable run assignments. Collection-mode validation exits 1 as intended. Docker context inventory still contains only `default`; fleet measurements and elapsed soak remain open.

### Live-query defect and targeted closure order

The first live wrapper ran at `artifacts/local/live-acceptance-acceptance-20261030T144519Z-933003/`. Infrastructure and the full nested containment chain passed, including approved execution, rollback and chronological audit. Its probe retained 11 observed process rows and 11 Falco records. The wrapper exited 1 before ingestion because the supplemental periodic database query failed; cleanup passed and response execution was restored to disabled. This wrapper is not recorded as an overall successful run.

Read-only diagnosis isolated PostgreSQL `GroupingError`: separately constructed JSON coverage-state expressions in SELECT and GROUP BY compiled as different bound parameters. Both periodic and exact queries were affected; mocked/AST tests had not exposed this database behavior. The benchmark executor is authorized to project coverage state once in the inner query, group/filter its column alias, regression-check the affected benchmark module, then reconcile the existing 11 canary identities with the corrected read-only periodic/exact queries. The closure must retain original raw-source identity and the corrected measurement-source identity separately. Full ingestion will then run once with fresh durable receipts; the passed infrastructure/containment sequence will not be repeated unnecessarily. Pilot execution remains deferred until this closure and its runtime cleanup finish.

### Accepted local live closure

The SQL correction passed the complete affected benchmark module (17 tests) and narrow Ruff. The continuation at `artifacts/local/live-acceptance-continuation-ingestion-continuation-20261030T145755Z-982117/` then exited 0 with cleanup passed. Its comparison explicitly retains the original chain's source `2caf7addab011d425b2834afd6ef6eed5ff20c3c7439bd4de4fea37aca54e1c8` and failed-wrapper status separately from corrected measurement source `6a760ffd61f9dbc6d33eea4aad8a5d8b1a1fce0420a171743545fdb2350901fa`.

The real read-only query reconciled all 11 prior process identities (zero kernel rows). Periodic mode performed zero identity selects/materializations/percentiles; exact mode performed two identity selects and materialized 11 IDs with the exact API-reference hash. One observation took 40.6 ms periodic versus 58.7 ms exact; these are query observations, not a production speedup estimate. No assessment jobs existed in this probe window: p95 is null and completeness false. No fleet latency result is claimed.

Full ingestion ran once under the fresh continuation ID and passed: cap/outbox 100; 79 current-run canaries; overflow delta 5; Docker API = API = PostgreSQL = replay-before = replay-after = 131; final queue depth zero. Both fsynced 0600 receipts are retained under the proof directory's `receipts/`. Parent review read the receipts, comparison JSON, ingestion summary and status file. Cleanup verified cap 100000, response disabled, eight healthy services, no owned residue, byte-restored tracked result/manifest inputs and stable measurement source.

The safe exploratory pilot and local provenance refresh are now authorized sequentially through the experiment executor's reviewed ignored wrappers. They do not authorize publication, model promotion or confirmatory claims.

### Pilot preflight correction

The first exploratory wrapper stopped before pull/network/trial creation because its generated ID ended in uppercase `Z`, violating the new bounded lowercase run-ID validation. Postchecks confirmed unchanged source, eight healthy services, disabled response and no run-label residue; no run directory was created. This is a failed preflight attempt, not pilot evidence. Parent source review also confirmed the normal pilot/study default generators used the same uppercase suffix (`experiments/run.py` default pilot branch and `experiments/study.py` run context). The executor is authorized to correct generated IDs and the two ignored wrapper timestamps, preserve the validator, add affected default-generation regressions and run only the affected tests/lint before a fresh pilot. Packaging must use the resulting final source hash. The accepted ingestion/containment components are unchanged and will not be repeated for a CLI-name correction.

### Completed exploratory pilot

The CLI correction uses shared `timestamp_run_id()` for pilot, study and the necessary tag-drift consumer; ignored wrapper timestamps also use lowercase identifiers. A fresh pilot at `artifacts/local/exploratory-nginx-20261030t150843z-1019443/` completed one pinned WL-NGX-V1 / SCN-EXEC / baseline trial with five workload operations. `research_eligible` remains false in both run and trial records. Parent review read the run/trial status and binding hash; the wrapper additionally verified matching run/environment binding and environment/code hashes, unchanged source, eight healthy services, disabled response and zero owned container/network residue.

Final source after the ID correction is `ad5f3f1b61acffb07d70a3fc1b639eb8c110f3c28faa08cb78fcec70b4ec5b79`. The prior accepted pipeline measurement source remains 6a760ffd; CLI-name changes do not relabel earlier raw evidence. Five-image packaging is running under fresh non-Compose tags with no runtime restart or publication.

Parent comparison of the final source inventory against the accepted ingestion source confirms only five files changed afterward: `experiments/run.py`, `experiments/study.py`, `experiments/tag_drift.py`, `experiments/tests/test_real.py`, and `experiments/tests/test_study_manifest.py`. These implement/test default ID generation. Microservice code, locks, ingestion receipts/verifiers and the corrected benchmark query are unchanged. Thus prior component proofs remain attributable to their actual source identities; the new pilot and final package bind the new complete source identity rather than retroactively restamping old captures.


### Final local provenance and review verdict

The five-image refresh completed under `artifacts/local/remaining-verification/release-validation-20261030t151041z-1026137/`. The source/lock/image-role/SBOM binding validator returned `valid=true` for backend, collector, telemetry, responder and scanner. Parent review independently read the manifest, checked all five SBOM digests and confirmed before/after/current source inventories match final tree `ad5f3f1b61acffb07d70a3fc1b639eb8c110f3c28faa08cb78fcec70b4ec5b79`. Images used fresh `porygon-validation-*` local tags; running services were not restarted by packaging. The manifest keeps empirical acceptance `not-recorded`, since local packaging does not certify the remaining fleet/study/soak gates.

Advisor verdict: local engineering tracks A, B and C accepted with the documented focused corrections and component evidence. Original failed attempts remain retained and identified. No additional engineering refactor is required by this batch. The next execution dependencies are actual independent qualified reviews and reviewed collection locks/data, two additional authorized Linux nodes for the three-node contract, then a real seven-day soak. Do not reopen accepted engineering solely because an older plan contains historical unchecked implementation steps.

No commit, push, merge, mirror synchronization, public dataset/image release or external communication was performed. The primary workspace/project and immutable research/presentation artifacts remain outside this execution scope.

Final executor command evidence: default-ID integration tests ran `.venv/bin/python -m pytest -q experiments/tests/test_real.py experiments/tests/test_study_manifest.py experiments/tests/test_study_conformance.py experiments/tests/test_tag_drift.py` and passed 73 tests; critical Ruff on the changed generator/consumer/test files passed. This is a second, justified focused correction batch, not another full-host run. Both reviewed wrappers (`exploratory-pilot-wrapper-20261030.sh` and `release-provenance-wrapper-20261030.sh`) exited 0 with stdin `/dev/null`. Pilot retry outer log: `artifacts/local/exploratory-pilot-20261030-retry.outer.log`; package outer log: `artifacts/local/release-provenance-20261030.outer.log`. Packaging used Syft 1.55.0 and Docker client/server 29.9.2. Post-package checks retain eight healthy services with response disabled. Parent final runtime reads also confirmed collector cap 100000 and unchanged tracked result/manifest inputs.
