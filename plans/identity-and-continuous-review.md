# Identity and continuous detection implementation review

Review date: 2026-10-27. Verdict: APPROVE the self-hosted identity increment and plan 002.

Workspace: `/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work`, detached at `b04aaea` with preserved pre-existing changes. Primary source checkout remains unchanged. No commit, merge, push or mirror was performed.

## Reviewed result

Hash-only enrolled credentials provide human roles, service purposes, expiry, revocation, rotation overlap and exact service-instance/host assignment. Authenticated mode rejects shared compatibility credentials and protects reads, raw evidence and documentation. Unclassified handlers fail closed. Verified principals supply audit actors. Response proposals and executions freeze their host; the responder verifies the actual Docker daemon before acting.

Continuous detection uses a shared transaction-aware assessment service and durable PostgreSQL jobs/checkpoints. Each job binds exact host/full container ID, immutable image, security context, profile artifact, detector configuration, fixed window and late revision. Scoped scores freeze selected event IDs. Scoring, detection, incident evidence and completion commit together; lease generations fence stale workers. Configuration drift and unavailable evidence cannot silently change an assessment.

Managed profiles use named operator-designated benign intervals, quality gates, disjoint shadow review, explicit activation and immutable rollback with chronological audit history. The operational lifecycle remains separate from historical digest-wide profiles. Missing/stale observations and unknown capture completeness remain explicit. Scheduling is opt-in; incidents never grant containment approval.

Dashboard credentials remain in tab memory and clear on logout/reload. The local website proxy forwards supplied credentials without implicit operator elevation. The provisioning CLI rejects redirects and remote plaintext HTTP, creates exclusive0600 secret files, and prints metadata only.

## Review corrections

Review corrected included-router authorization, rejected-secret validation echoes, proxy credential injection, mutable response-host targeting, wrong-host lease requeue effects, normalized security-context fields, local mutation authentication, missing retained evidence, detector configuration races, revision lineage, repeated profile-transition audit loss, healthy heartbeat semantics and unprofiled/retention fallback. Shadow comparisons exclude training intervals of both candidate and active comparator. No frozen research/presentation files were changed.

## Verification evidence

Evidence directory: `artifacts/local/service-trust-review/combined/` (ignored, local only).

| Gate | Result | Evidence |
|---|---|---|
| Affected image builds and active-source match | Backend/responder rebuilt; all128 service source/test files across five active services match workspace | `backend-build.log`, `responder-build.log`, `backend-message-build.log`, `baked-sources.json` |
| Backend complete batch with PostgreSQL |375 passed;1 existing authentication-error-text assertion failed, then passed focused recheck after restoring established wording | `backend-tests.log`, `backend-message-recheck.log` |
| Other active service suites | Telemetry44, collector28, responder15, scanner13 passed | corresponding `*-tests.log` |
| Host suites |254 passed,2 skipped | `host-tests.log` |
| Protocol and static checks | Passed, including OpenAPI, offline migration SQL and pinned Falco rule validation | `research-protocol.log`, `static.log`, `static-verification-manifest.json` |
| PostgreSQL new gates | Credential rotation race, additive migration safety/roundtrip and two-worker claim passed as part of backend batch | `backend-tests.log` |
| Infrastructure and nested live chain | Passed ingestion, eBPF, profiling, scoring, detection, lifecycle and controlled containment/rollback | `infrastructure.log`, `containment.log` |
| Authenticated reads | Public health200, anonymous reads/OpenAPI401, enrolled read200 | `auth-read-checks.json` |
| Live permission/host checks | Legacy rejection, denied machine reads/operator actions, wrong-host rejection, viewer read/write/AI boundaries, immediate revocation and healthy enrolled workers all passed | `auth-guards.json` |
| Unattended authenticated canary | Incident with zero manual score/detection calls; worker outage recovery, unique keys, late revision/replay and explicit degraded/unprofiled states passed | `continuous-acceptance.json`, `continuous.log` |
| Cleanup and primary preservation | All checks passed; eight services healthy; temporary credentials revoked/files removed; original local/disabled modes restored;279 tracked primary files unchanged | `auth-cleanup.log`, `final-state.json` |

The unique service-case count is476:375 backend cases in the complete batch plus the corrected case's successful focused recheck, and100 worker-service cases. The full backend suite was not needlessly repeated after the wording-only correction. One earlier recheck transport was interrupted by a service recreation; the recorded final recheck completed with exit0. Host skips remain skips, not passes. Focused executor suites overlap the final batch and are not added to these totals.

The authenticated canary ran on a pinned cached Alpine image and only labelled disposable containers. Its late event was explicitly synthetic verification evidence. Real capture produced the unattended incident. Cleanup disabled only this run's targets and removed only its canaries. Temporary live response mode used an EXIT restoration trap.

## Remaining boundaries

Plan002 is accepted. Plan001's self-hosted bearer scope is accepted; conditional remote HTTPS/OIDC and its deployment-specific verifier remain deferred. Administrative host assignments are not hardware attestation. Source-drop completeness remains unknown. Causal multisignal detection, any trained/calibrated model, notification delivery/recovery/capacity proof and journal evaluation remain their separate plan003–005 workstreams. No performance, accuracy or publication result is inferred from these engineering checks.
