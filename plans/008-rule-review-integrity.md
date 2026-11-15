# Rule review integrity

Plans 006 and 007 retain the local verification record. Confirmatory collection still requires independent security and methodology reviewers, a pilot and sample-size lock, a reviewed collection lock, an image identity matrix, and immutable run assignments. The three-node capacity check needs two more authorized Linux nodes. The seven-day soak is deferred.

## Correctness and audit findings

In `backend/src/porygon_api/rule_workbench.py`, `_evaluate_preview` commits its receipt before `shadow_rule` records the state transition. If the latter write fails, the receipt persists without its transition. `_activate` independently reads receipts for audit and validation, and expiry is measured from receipt creation alone. Restaging an immutable revision can therefore carry over an earlier review of that revision. `_has_fresh_receipt` also accepts an event-only result when `labeled_outcomes` is absent, although the operations guide describes event previews as exploratory.

## Implementation

Use the existing per-rule PostgreSQL lock for review mutations and keep receipt, state and audit writes in a single transaction. Select the latest preview and shadow for the candidate and validate the same objects whose hashes are stored at activation. Require both to follow the most recent staging audit for that revision, and require passing labelled positive and negative fixtures. Preserve read-only receipt history and event-ID preview for investigation. An immutable revision being restaged needs new review even when its hash was approved previously.

Scope is `backend/src/porygon_api/rule_workbench.py`, the legacy disable handler in `backend/src/porygon_api/main.py`, the rule regression tests, and `docs/operations/rule-workbench.md`. Existing schema, historical run snapshots, research artifacts, telemetry producers and response policy are outside scope. If the existing staging audit cannot establish the candidate boundary, require restaging rather than deriving a timestamp from unrelated rule activity.

## Verification

Rebuild the backend once after the source freezes. Run `docker --context default compose -p porygon-service-trust exec -T -e PORYGON_TEST_POSTGRES=1 backend pytest --basetemp=/dev/shm/porygon-rule-review` and the unchanged service suites. Run the repository research and source checks and the isolated shell battery. Exercise the real draft, preview, shadow, activation, revision replacement, rollback and disable lifecycle with a non-incident rule. After restaging, confirm activation refuses an old preview even when there is a fresh shadow, then passes with both fresh labelled receipts. Use only the isolated project with disabled response outside the owned containment check. Preserve local evidence and verify source identity after builds.

## Local acceptance on 14 November 2026

The rebuilt backend passed 470 tests on PostgreSQL. Collector passed 30, telemetry 48, responder 15 and scanner 13. The host suite passed 357 with two skips. The first backend run was interrupted by the infrastructure restart. A subsequent run found a fixture initialization error, which was corrected before the final rebuild and passing run. The correction changed only the test module. The source inventory comparison confirmed that the shell and live lifecycle checks exercised the same runtime source as the final build.

The live API rejected the preview from before rollback staging even after a new shadow review. A new labelled preview then allowed activation. The test rule ended disabled and retained two immutable revisions. Evidence is in `artifacts/local/rule-review-integrity.Tr59sVpu/lifecycle.log`.

All seven shell checks and cleanup passed. The replay kept 131 lifecycle rows and the collector outbox drained to zero. The proof is `artifacts/local/live-acceptance-acceptance-20261114T061702Z-1362963/proof-summary.json`. All eight services are healthy with response disabled. The pinned Alpine verification profile remains active and retired probe profiles remain in history.

The local release manifest at `artifacts/local/rule-review-final.BGmTEYg2/release-manifest/release-manifest.json` validated five SBOMs against tree `6843ef9f59c4ba6a903944cd6ab6164526c263cfa63495bb750fba2cb6f39802`. Independent study and additional node measurements remain open.
