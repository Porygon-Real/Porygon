# Improvement progress

The supplied 18-item audit is an input to verify against current code. Its proposed fixes and severity labels are not assumed correct. Existing evidence, frozen research protocols, presentation files, and concurrent dashboard changes are preserved. Changes remain uncommitted.

## Current implementation pass

- [ ] Close cross-container parent lookup and repair late parent links safely (IMP-01, IMP-04, IMP-05).
- [ ] Prevent shell allowlists from suppressing unrelated tool sequences (IMP-11).
- [ ] Release database connections before external AI requests and bound concurrent audits (IMP-12).
- [ ] Block internal control-plane paths at the gateway (IMP-13).
- [ ] Add an opt-in, bounded retention scheduler with transaction ownership and shutdown handling (IMP-14).
- [ ] Verify existing batching, path matching, idle-window, rollback and rotation improvements (IMP-03, IMP-09, IMP-10, IMP-16, IMP-17).
- [ ] Record accurate status and remaining implementation requirements for all 18 items.
- [ ] Run targeted regressions, static verification, all five service suites, protocol integrity, and live acceptance checks.

## Design constraints

- Missing process telemetry remains `insufficient_data`; zero observations do not prove normality.
- Process-group or session membership is not evidence of direct ancestry. Unobserved forks remain an explicit telemetry boundary.
- Existing scoring/model versions and frozen study artifacts must remain reproducible. Argument-aware scoring and changed numerical transforms need distinct schemas/configuration and validation, rather than silently changing historical scores.
- A Docker config digest is not interchangeable with an OCI repository digest. Local-image scanning needs an explicit identity type end to end.
- SQLite FULL durability is retained for the outbox. Batching amortises commits without weakening the checkpoint durability contract.
- Retention scheduling is disabled by default because deleting retained research evidence must be an explicit deployment configuration choice.

## Other audit items

Detailed status and verification results will be updated as this pass completes. Broader telemetry, feature/model evolution, and local-image identity support require separate implementation work; they are not represented as completed fixes.
