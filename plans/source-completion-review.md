# Remaining engineering source review

Reviewed against externally created commit `96333df` in
`/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work` on 2026-10-29.
This records source review, not validation results. The sole source executor
owns corrections; the advisor edits only plans. No commit, push, merge, mirror,
primary-checkout changes or external publication are authorized.

## Source corrections before the joint freeze

1. Complete the bounded collector in `experiments/benchmarks/lab.py` and its
   report contract in `experiments/benchmarks/run.py`. At the reviewed commit,
   the lab has no orchestration entry point. Its adapter epoch uses a moving
   file offset, its initial EOF cursor is not retained, and assessment jobs
   include historical windows. Use stable counter identity, exact event-time
   boundaries and a shared declared control plane. Separate controller actions,
   selected normalized records and persisted logical identities. Unavailable
   measurements must produce unknown outcomes, not successful zero loss.
   Workload throughput excludes the downstream drain interval. Daily canary
   coverage must include both endpoints of the declared soak interval.
2. Preserve workload identity in public export. At
   `experiments/export_study.py:33`, the field whitelist includes `stratum` but
   omits `workload_id`. At `experiments/frozen_statistics.py:15–16`:
   ```python
   version=by_id[(identifier,'ARM-CONTEXT')].get('workload_id')
   if not version:raise ValueError('Workload/version stratum required for paired interval')
   ```
   A complete paired analysis therefore fails after export projection. Preserve
   the non-sensitive workload identifier and add a complete analysed export and
   offline replay regression, retaining identical declared result tables.
3. Abstain on unknown multicall arguments. At
   `backend/src/porygon_api/evaluation_routes.py:53–56`:
   ```python
   if base in {'busybox','toybox'}:
       applet=_multicall_applet_from_cmdline(getattr(row,argument_field))
       if applet in allowed:item[argument_field]=base+' '+applet
       elif applet is not None:available=False
   ```
   Missing or unparseable arguments leave availability true. The rule comparator
   subsequently treats that projection as observed. Mark every non-whitelisted
   multicall applet unavailable, including `None`; retain valid whitelisted
   applets. Define missing/malformed-argument negative controls.
4. Bound restore execution. `scripts/verify_restore.py` has unbounded subprocess
   operations and an unbounded snapshot-holder `readline()`. Evaluating RTO only
   after completion cannot enforce a deadline. Bound the exported snapshot,
   dump, receipt backup and restore, close the source transaction on timeout,
   and preserve ownership checks during cleanup. Define timeout regressions.
5. Add meaningful guard regressions for quality locks/model promotion, release
   identity tampering and restore safety. Existing basic model-shape tests do
   not establish the new persisted review and precollection-lock guarantees.
   Do not introduce new approval roles or unrelated architecture changes.

## Previously pending fixes present in source

Source reads confirm host-aware health natural-key replay, health retention,
integer-count conditional bootstrap probabilities and the CI host dependency
installation. These are not yet verified by executing this batch.

## Boundaries and acceptance

Frozen files under `docs/research/` and `docs/presentation/` remain untouched.
Measured training/model promotion, independent journal collection, three-node
capacity and a seven-day soak are empirical gates; software fixtures cannot
satisfy them. Stop rather than target active user data or send externally.

The user requires finishing all remaining engineering and regression definitions
before testing. After the executor and advisor agree on the complete source
freeze, rebuild changed isolated images once, then run all five active service
suites (including PostgreSQL integration), host experiment/tooling suites,
protocol integrity, offline migrations and disposable migration round trips,
new local evidence/notification/restore/release gates and the nested live
detection/containment acceptance chain. Record exact results and restore disabled
response mode. Do not claim completion while required gates fail or remain
unexecuted.

## Verification window opened

All engineering source, documentation and regression definitions reached a joint
freeze before testing. Required critical Ruff findings were then corrected,
including an undefined runtime-evidence contract and a missing JSON import;
the complete critical Ruff gate and research-protocol integrity passed.

The first complete host execution reached 288 passes and two skips with six
failures. Corrected causes included obsolete no-runner expectations, package
imports, review-blocker diagnostics and a fixture missing its planned actions.
The affected host group subsequently passed all 58 cases. Collector, telemetry
and responder active-container suites passed 28, 48 and 15 cases respectively.
Backend PostgreSQL execution reached 399 passes and one failure: an omitted
optional floating metric default serialized as integer zero before revalidation
and floating zero afterward, changing its evidence hash. A separate executor
changed the default to `0.0`; narrow critical Ruff and a synthetic hash roundtrip
passed. Rebuilt-backend regression acceptance remains pending at this entry.

The isolated project is `porygon-service-trust`. Its private environment was
reconstructed from that project's existing containers without displaying
credential values. Primary project `porygon` was not restarted or modified.
The scanner's first build failed with a connection error downloading its pinned
Trivy archive; a bounded retry is pending. Remaining local evidence,
notification, migration, restore, release and live acceptance outcomes must be
recorded before declaring the engineering increment accepted.

Per the user's explicit delegation request, separate executors now own the
remaining bounded verification and tool-preparation work; the advisor reviews
results and edits only plans. No commit, push, merge or publication occurred.

## Runtime review — 2026-10-30 (acceptance still pending)

Scanner's retry built successfully and its 13 tests passed. Backend's rebuilt
PostgreSQL regression group passed 30 tests after the floating-default fix.
Local causal replay, loopback signed notification transport and offline Alembic
SQL generation passed. The complete critical static gates passed.

The first restore's empty summaries were invalid proof: the SQL helper omitted
`docker exec -i`, so psql never received the supplied queries. The helper now
attaches stdin and refuses missing application tables, a mismatched dynamically
resolved migration head or an empty heartbeat table. Twelve restore regressions
passed. The meaningful drill at
`artifacts/local/restore-acceptance-20261029-03/report.json` matched all 455,165
rows in 38 tables, including six heartbeats. Snapshot age was 92.945 seconds and
recovery elapsed 93.094 seconds; source objects were preserved and temporary
restore objects removed.

Two early live attempts had zero-byte logs and no attributable canaries; they
are not accepted despite zero exit codes. Harmless controls reproduced quiet
truncation when a child consumed an inline Bash wrapper's stdin. The reviewed
wrapper is therefore persisted at
`artifacts/local/live-acceptance-wrapper-20261030.sh` and executed from a file
with stdin closed. The precise historical cause of both empty attempts was not
established. Separately, the aggregate live-safe verifier could mask an ingestion
failure behind a later successful detector; explicit failure propagation now has
two passing disposable CLI regressions.

The real run at
`artifacts/local/live-acceptance-acceptance-20261030T094002Z-170034/` passed
infrastructure and the nested eBPF/profiling/scoring/detection/containment chain,
including approved pause, rollback and audit evidence. Its ingestion stage
failed because the constrained collector outbox did not reach 100 events. This
is an unresolved acceptance failure, not a passing result. All eight services
were restored healthy with response execution disabled; verifier targets were
absent and both tracked proof files matched their original bytes. Subagents
are diagnosing only this ingestion failure and checking constraint cleanup;
passing earlier suites must not be repeatedly rerun without a new reason.

The five-image final manifest at
`artifacts/local/remaining-verification/release-final-96333dfa-20261030/` passed
for source tree `faf7d03c8ac09a630ab6045280daf98ce8d477df4b60a92cf0bcf02281bf1355`.
The subsequent aggregate-verifier fix changes source identity, so a final
provenance refresh is required after the remaining failure is resolved. No
empirical model promotion, study collection, three-node capacity or seven-day
soak is inferred from these software checks.

## Final disposition

The capacity failure and subsequent verifier predicate were corrected and covered
by focused regressions, the rebuilt collector suite and an explicit live targeted
closure. The current engineering acceptance, exact evidence scope and historical
failed attempts are recorded in [engineering acceptance review](engineering-acceptance-review.md).
That review supersedes pending runtime/provenance statements above; it does not
turn unmeasured research or capacity gates into completed experiments.
