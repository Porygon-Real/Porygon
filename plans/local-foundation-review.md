# Local foundation execution review

Verdict: **APPROVE** for the bounded slices implemented below. The larger pathway plans remain in progress.

Worktree: `/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work`.
Source base: `b04aaea` plus the user's existing tracked changes, copied before execution. No commits, merges, pushes or primary source edits were made.

## Delivered

- Plan 001 step 1: explicit per-service environment mappings; operator and database credentials excluded from non-backend application services.
- Plan 001 step 4 and minimum local principal plumbing: shared locked incident transitions, bounded bulk resolution, authenticated credential subjects, atomic ordered evidence, caller-actor override prevention and matching dashboard behavior.
- Plan 003 step 1: truthful heuristic provenance, canonical ensemble hash, full raw-output decomposition, matching model-info/classification/stored metadata and active interface/document labels. Numeric legacy predictions and historical model identifiers are preserved.
- Updated detection acceptance to check the authenticated internal subject rather than the caller-provided name. The supplied name remains as a spoofing regression.

## Verification evidence

| Check | Result |
|---|---|
| Rebuilt active backend suite, PostgreSQL enabled | 326 passed |
| Active telemetry / collector / responder / scanner suites | 44 / 28 / 13 / 13 passed |
| Host experiment/tooling suites | 245 passed, 2 skipped |
| Focused PostgreSQL HTTP/lifecycle/model suites | 43 passed; overlaps the service suite |
| Independent comparison with old classifier | 200 seeded vectors retained numeric outputs; raw deltas reconstruct outputs within 1e-12 |
| Static verification, OpenAPI, Alembic offline SQL, Falco validation, protocol integrity | Passed |
| Actual dashboard factory behavior | Bounded request, server refresh, zero count and pending state passed |
| Baked image/source/test hashes | All five services match |
| Running-container credential-kind boundary | Passed without printing values |
| Infrastructure and ingestion/eBPF/profiling/scoring acceptance | Passed |
| Detection acceptance | Passed by validated continuation described below |
| Exact-target containment, repeated approval, verified rollback and audit history | Passed |
| Final response execution mode | disabled |
| Final services | Eight healthy |
| Scope and immutable artifact checks | Passed; 24 approved source/document paths |

The first nested live run reached and persisted acknowledgement/resolution, then failed an old verifier assertion expecting the supplied actor name. The script was corrected to assert `local-internal` and stronger timeline properties. Its previously completed prefix was checked byte-for-byte against the original, and the exact corrected tail ran against the already persisted lifecycle artifacts. A stopped test stack during the pause caused one transport failure; after restarting the same isolated stack, that tail passed. Containment then ran with its existing prerequisite-reuse option and passed. This avoids recollecting unchanged fixtures and does not hide either earlier failure.

Detailed logs and machine-readable results are under `artifacts/local/service-trust-review/`, including `review-summary.json`, the original `live-acceptance.log`, `detection-resumed.log`, `containment.log`, static/unit logs and restoration evidence. Generated tracked verification output was copied into that ignored evidence directory; the original tracked verification manifest was restored. No newly generated artifact is proposed as a source edit.

## Still pending

Plan 001 still needs the route permission matrix, individually attributable users, scoped/enrolled host-bound agents and the conditional remote deployment/OIDC profile. Current local subjects identify shared credentials, not individual people. Existing local service permissions were not broadened or represented as per-service RBAC.

Plan 003 still needs causal runtime evidence, structural feature evaluation and any actual trained/calibrated model. This slice corrects the existing contract; it does not claim to have trained a model or changed detection accuracy.

The continuous assessment worker, notifications/recovery/capacity work and prospective journal study remain separate pathway workstreams. Frozen research and presentation artifacts remain unchanged.
