# Engineering acceptance review

Date: 2026-10-30. Workspace:
`/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work`.
Base commit: `96333dfa43efff772c94ca605b43e54ea33026f9`.
Verified source tree:
`427f59427d6719e1a851c622d5d23656d69a67369cd01a5f26f5d1c4291dbb7e`.
Advisor plans are excluded from that identity. Changes remain uncommitted.

## Delivered scope

The remaining engineering components of plans 003–005 are implemented: attributable
runtime evidence and optional validated model administration; host-scoped health,
durable signed notifications, dependency/image provenance and recovery tooling;
and gated, split-safe study collection, offline analysis/replay and rights-aware
dataset export. Existing research protocols and presentation artifacts were not
modified. Empirical model promotion, independent study collection, three-node
capacity measurements and the seven-day soak remain separate measured gates.

Final review corrected real defects rather than changing acceptance targets:

- Public export retains workload identity needed by paired analysis; unavailable
  multicall arguments remain unknown instead of becoming known negatives.
- Omitted floating metric defaults retain canonical hashes on revalidation.
- Restore SQL attaches Docker stdin. Source and restored snapshots must contain
  the expected migration head, core application tables and heartbeat rows.
- Collector batches fill available capacity using atomic prefixes, retaining the
  unpersisted tail and withholding the checkpoint until the entire original batch
  is durable. An out-of-order timestamp and shutdown/replay regression covers this.
- Verification propagates child failures. Ingestion validates a fresh scoped empty
  observation, current-run canaries, the unchanged 100-event cap, overflow,
  persistence and replay; all consumers parse the depth/timestamp result correctly.

## Verification evidence

Tests ran after the combined engineering source freeze. Concrete failures were
fixed and their affected groups were checked; already passing suites were not
repeated without a reason.

| Gate | Observed result |
| --- | --- |
| Backend PostgreSQL suite | 399 passed initially; the one promotion-hash failure was corrected and the rebuilt affected group passed 30 tests, including its added regression |
| Collector | Rebuilt capacity fix passed all 29 tests inside the active collector with the real SDK |
| Telemetry / responder / scanner | 48 / 15 / 13 passed |
| Host experiments/tooling | 288 passed and 2 skipped initially; six failures were corrected and the affected 58-case group passed |
| Additional focused checks | Restore safety: 12 passed; aggregate failure propagation: 2 passed; ingestion snapshot/call-site regressions: 2 passed |
| Causal evidence verifier | Replay, negative controls, missing-metadata abstention and absent optional model passed |
| Notification verifier | Loopback HMAC, stable retry identity and redirect refusal passed; zero external messages |
| Migrations | Offline Alembic SQL passed; disposable PostgreSQL migration checks were included in the backend suite |
| Final static checks | Critical Ruff across all services/scripts/experiments, research protocol integrity, secret-pattern checks, Compose configuration, diff checks and changed shell syntax passed |

Most test/build logs are under `artifacts/local/remaining-verification/`. Counts
from targeted runs overlap earlier suites and must not be added as independent
test totals. Secret-pattern checks are bounded checks, not a blanket secret audit.

## Meaningful restore drill

`artifacts/local/restore-acceptance-20261029-03/report.json` records an exact match
of **455,165 rows across 38 tables**, including six heartbeats and migration head
`model_promotion_review`. Snapshot age was **92.945 seconds** against a 3,600-second
target; recovery elapsed **93.094 seconds** against a 600-second target. Source
container/volume identities were preserved. The receipt database passed its
offline integrity check; restored receipt/intents remain subject to operator
reconciliation. Temporary restore objects were removed.

The earlier empty-summary restore report is invalid proof: the old SQL helper
failed to attach stdin, so it observed no query results. It is retained privately
and is not counted as successful recovery evidence.

## Live acceptance and explicit ingestion closure

The persisted file wrapper at
`artifacts/local/live-acceptance-wrapper-20261030.sh` ran with stdin closed.
The real run in
`artifacts/local/live-acceptance-acceptance-20261030T094002Z-170034/` passed
infrastructure and the nested eBPF, profiling, scoring, detection and containment
gates, including approved pause, rollback, idempotence and audit evidence.

The collector capacity correction was then checked by an ingestion-only run:
`artifacts/local/ingestion-acceptance-acceptance-ingestion-20261030T101415Z-281166/`.
It reached the exact 100-event cap, passed positive current-run canary and overflow
assertions, recovered **131 observed API canaries into 131 distinct PostgreSQL
rows**, and asserted replay growth of zero.

That full command exited 1 at its final *verifier predicate*: a depth/timestamp
pair was compared to scalar `0`, although the reported depth was zero. The
consumer was corrected, regression-tested and closed with the actual current
fresh-zero helper against the live system. No successful full-command exit is
claimed for that historical attempt, and its passing outage/replay stages were
not needlessly regenerated.

The explicit combined-coverage record is:
`artifacts/local/ingestion-targeted-closure-acceptance-ingestion-20261030T101415Z-281166/ingestion-targeted-closure.json`.
It binds the prior log and current verifier hashes, records the 131 unique rows,
zero replay growth and successful fresh post-recovery zero observation. Exact
canary spool and overflow counts were not persisted before the old predicate
failed; only their observed positive assertions are retained. No missing capture
integrity report or exact counter values were invented.

Two earlier zero-output attempts have no attributable canary evidence and remain
unaccepted. Harmless controls demonstrated that an inline Bash wrapper can lose
later commands when a child consumes its stdin; using a persisted wrapper file
with stdin closed removes that hazard. The precise cause of both historical
empty attempts was not established.

## Final packaging and state

`artifacts/local/remaining-verification/release-final-accepted-20261030/` contains
five image SBOMs, binding receipts and a manifest. Both generation validation and
the explicit release verifier passed for the source identity above, each service
role, dependency lock and exact image identity. Source identity remained stable
after generation. This is local packaging proof; the manifest's empirical
acceptance field correctly remains `not-recorded`.

Final runtime observations: all eight isolated services healthy, collector cap
restored to 100,000, response execution disabled, verifier targets/network absent,
and tracked `artifacts/results.json` and `artifacts/verification-manifest.json`
byte-identical to their saved originals. Packaging refreshes did not restart
containers after these checks. The primary project was not modified by this work.
No commit, push, merge, mirror, publication or external notification was performed.
