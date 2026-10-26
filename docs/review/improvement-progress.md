# Improvement progress

The supplied 18-item audit is an input to verify against current code. Its proposed fixes and severity labels are not assumed correct. Existing evidence, frozen research protocols, presentation files, and concurrent dashboard changes are preserved. This work does not create commits, pushes, or merges. Concurrent user changes and commits are retained.

## Current implementation pass

- [x] Close cross-container parent lookup and repair late parent links safely (IMP-01, IMP-04, IMP-05).
- [x] Prevent shell allowlists from suppressing unrelated tool sequences (IMP-11).
- [x] Release database connections before external AI requests and bound concurrent audits (IMP-12).
- [x] Block internal control-plane paths at the gateway (IMP-13).
- [x] Add an opt-in, bounded retention scheduler with transaction ownership and shutdown handling (IMP-14).
- [x] Verify existing batching, path matching, idle-window, rollback and rotation improvements (IMP-03, IMP-09, IMP-10, IMP-16, IMP-17).
- [x] Record accurate status and remaining implementation requirements for all 18 items.
- [x] Run targeted regressions, static verification, all five service suites, protocol integrity, and live acceptance checks.

## Design constraints

- Missing process telemetry remains `insufficient_data`; zero observations do not prove normality.
- Process-group or session membership is not evidence of direct ancestry. Unobserved forks remain an explicit telemetry boundary.
- Existing scoring/model versions and frozen study artifacts must remain reproducible. Argument-aware scoring and changed numerical transforms need distinct schemas/configuration and validation, rather than silently changing historical scores.
- A Docker config digest is not interchangeable with an OCI repository digest. Local-image scanning needs an explicit identity type end to end.
- SQLite FULL durability is retained for the outbox. Batching amortises commits without weakening the checkpoint durability contract.
- Retention scheduling is disabled by default because deleting retained research evidence must be an explicit deployment configuration choice.

## Other audit items

| Finding | Current state | Evidence or remaining work |
| --- | --- | --- |
| IMP-01 | Implemented; regression checked | Existing deferred identity reconciliation is retained; matching late lifecycle records repairs unresolved events. |
| IMP-02 | Pending telemetry extension | Exec evidence remains the supported sensor contract. Socket/file/memory event types need separate schemas, retention and collection acceptance before claims expand. |
| IMP-03 | Existing fix verified | File source commits batches and cursor atomically; SQLite WAL with FULL durability is retained. In-memory-only depth counters would need reconciliation across concurrent writers. |
| IMP-04 | Partial improvement | Recorded direct parents arriving out of order are repaired. Unrecorded forks remain missing evidence; group/session guesses are deliberately not represented as ancestry. |
| IMP-05 | Fixed | Unresolved containers cannot use host PID fallback; resolved lookup stays within container/host or sensor bounds. Ancestor traversal also rejects old cross-container links. |
| IMP-06 | Implemented as opt-in contract | Command shapes use a bounded fixed vocabulary without argument values; paired feature/algorithm identities, coverage checks and persisted configuration preserve legacy scoring. New profiles require explicit build/activation. |
| IMP-07 | Pending model work | Existing model input remains compatible. New structural features require observed metadata and model training/validation; path strings alone do not establish permissions or deleted files. |
| IMP-08 | Pending numerical model work | The stated dead zone concerns one numeric component, not necessarily the entire score or rule detector. A changed transform needs a distinct algorithm contract and calibration. |
| IMP-09 | Existing safe handling verified | API persists insufficient-data outcomes for absent process evidence, avoiding a runtime exception without claiming observation-free normality. Verified quiescence would additionally need sensor-coverage evidence. |
| IMP-10 | Fixed, including multicall paths | Explicit and slash-bearing path conditions use raw executable paths with case-sensitive comparisons; basename conditions retain dispatched applet identity. |
| IMP-11 | Fixed | A shell exception cannot suppress its later unknown tools. The concrete shell and tool events must both have explicit approved exceptions before their pair is suppressed; both approval IDs are recorded. Matcher identity changes with this behaviour. |
| IMP-12 | Fixed | Plain audit context is materialised and session closed before provider calls. A bounded per-process admission semaphore rejects excess audits promptly and releases on failure. Incorrect score_value access is corrected to total_score. |
| IMP-13 | Fixed | Gateway denies bare and nested internal prefixes, including percent-decoded variants. Local administrative tools use authenticated Docker-exec transport; no backend port is published. |
| IMP-14 | Implemented, opt-in | Lifespan-managed retention worker owns brief sessions, takes a cross-worker advisory transaction lock, deletes bounded batches, and recovers on a later tick. Disabled by default to preserve retained evidence. No existing tables were repartitioned. |
| IMP-15 | Pending identity contract | Local config IDs must remain distinct from repository digests through API, queue and scan provenance. An unchecked RepoDigests fallback would weaken the existing exact-target guarantee. |
| IMP-16 | Existing fix verified | A newly started batch container may finish with exit code zero; stale prior successful exits cannot satisfy rollback verification. |
| IMP-17 | Existing rotation verified; outage budget remains | Consumed source bytes are renamed/drained before deletion. Rotation protects unread records; it is not a hard disk cap during sustained backend outage. Copy-truncating unread evidence would lose events. |
| IMP-18 | Reporting improved; natural-drift study pending | New tag-drift manifests identify controlled_local_alias_reassignment, pilot eligibility and absence of natural upstream observation. Existing artifacts and frozen protocol bytes remain intact. |

## Operational changes

- Local administrative CLI commands, the dashboard's server-side canary ingestion, and the study harness use `scripts/private_api.py` for internal calls to a local Docker stack. Public reads and explicit remote URLs retain HTTP transport.
- Acceptance scripts create a temporary loopback transport for their child process; service authentication remains required. The public gateway never receives an internal-route exception.
- `PORYGON_VERIFY_BUILD=false` reuses images already built by the caller. Default verification still rebuilds. This permits host-network builds on machines whose Docker build bridge cannot reach the package index.
- Live detection checks inspect their own incident lifecycle and validate cumulative counters without requiring the operator's unrelated incidents or exceptions to disappear. Probe images are digest-pinned and reuse verified local cache entries before requesting a pull.
- The new `process_parent_repair_index` migration adds a concurrent partial index for recently received events lacking parent links. Automatic repair is limited to a recent receipt interval; the explicit reconciliation endpoint can process older retained candidates in bounded batches.

## Previous pass verification

- **483 tests passed:** backend 195; collector 8; telemetry 24; responder 8; scanner 6; experiment and private-transport tests 242.
- **Static verification passed:** Ruff/source checks, Compose configuration, OpenAPI generation, Alembic upgrade SQL and Falco rule validation. Images were built using host networking because the default build bridge could not reach the package index; verification reused them with `PORYGON_VERIFY_BUILD=false`.
- **Research protocol integrity passed.** Frozen source artifacts and presentation decks were preserved.
- **Infrastructure passed:** health/readiness, no backend host-port publication, gateway internal-route denial including percent-encoded paths, and persistence across restart.
- **Complete live workflow passed on rebuilt images:** event ingestion, eBPF telemetry, profile construction, anomaly scoring, detection, approved containment, and rollback. This includes outage recovery, replay idempotence, paired exception matching, and incident transitions.
- Final containment verified separate operator credentials, exact-target approved pause, idempotent approval, unpause rollback, and chronological audit evidence.
- Shared-state counter assumptions and an inventory environment-size limit were corrected during acceptance. Unrelated operator incidents were preserved. Component-only reruns can explicitly set `PORYGON_VERIFY_PREREQUISITES=false`; the final run used the default complete prerequisites.
- **Retention locking passed against PostgreSQL:** a second worker was excluded while the advisory lock was held; a zero-deletion tick completed after release. Automatic pruning remains disabled.
- The concurrent partial index migration is installed at `process_parent_repair_index`.
- All service images match current source/tests. All eight running services are healthy, and response execution is restored to `disabled`.
- Local evidence and source hashes: [`results.json`](../../artifacts/local/improvement-validation/results.json), with command logs beside it. These validation artifacts are intentionally ignored by Git.

## Further backlog implementation

- [x] IMP-20: Put trusted policy in provider system instructions; escape and delimit telemetry JSON. Strictly validate required assessment fields, finite scores, enums, sizes and extra fields. Reject duplicate JSON keys and citations to commands absent from the supplied events. Error messages do not echo provider bodies or request URLs.
- [x] IMP-21: Persist an operation intent before calling Docker and its completion receipt before delivery. Retry saved completions with backoff before claiming new actions. Keep acknowledged receipts for lease recovery, distinguish explicit retry generations, and fail closed after an interrupted action whose outcome is unknown. A shared journal has one active worker; separate filesystems do not share that ownership.
- [x] IMP-23: Lock incident rows before changing status or allocating evidence sequence numbers. Lock response state transitions and bind completion receipts to their original execute/rollback generation.
- [x] IMP-24: Group open/acknowledged incidents by exact host/container set, image, profile and detection configuration. Preserve every run through a link table and evidence provenance. Keep the latest window's assessment coherent, reject stale unapproved recommendations, and create a new episode after closure. Historical incidents are not retroactively merged.
- [x] IMP-19: Batch up to 100 collector events with a roughly 50 ms flush interval. Store event data and monotonic cursor in one FULL-durability transaction; roll back the entire batch on capacity failure. Use a bounded reader queue and spool backpressure; explicitly close SQLite connections.
- [x] Complete rebuilt-image tests, migration checks, and full live acceptance.

The `incident_episode_grouping` migration adds nullable fields and a run-link table, retaining legacy rows and original recommendation identities. New readers accept both `incident_created` and `incident_updated`; the latter means an existing episode received another recorded detection window. Downgrade refuses to remove the schema while grouped detection history exists.

The isolated 500-event SQLite benchmark used three repetitions before and after on this machine. Median time changed from 1.6438 s to 0.02449 s; connections changed from 2,000 to 5, commits from 1,000 to 5, and COUNT queries from 1,000 to 5. Both runs used WAL and synchronous FULL. This measures the spool/cursor path, excluding Docker inspection, normalization, HTTP delivery and ingestion. Benchmark records are in `artifacts/local/backlog-validation/`.

At the end of the preceding pass, remaining work included argument-aware scoring (IMP-06), additional socket/file/memory sensor schemas (IMP-02), unobserved fork lineage (IMP-04), structural ML inputs (IMP-07), a separately calibrated rare-event transform (IMP-08), explicit local-image identity (IMP-15), and causally scoped bigrams (IMP-22). Existing model identities and frozen evidence are preserved for reproducibility.

### Verification of this backlog pass

- **508 tests passed:** backend 212, collector 12, telemetry 24, responder 12, scanner 6, experiment/private-transport 242. The PostgreSQL-specific race test is skipped in the SQLite suite and was executed separately.
- **6 PostgreSQL tests passed** in uniquely named disposable schemas: concurrent windows, concurrent status updates, contiguous evidence sequences, coherent latest-window assessment, closure boundaries, stale approvals, completion generations, and legacy recommendation reuse.
- A fresh full migration upgrade, empty-schema downgrade, and re-upgrade passed in a disposable PostgreSQL schema. Upgrade SQL also passed static verification. The live database is at `incident_episode_grouping`.
- **Static verification, protocol integrity, and infrastructure passed.** A gateway address-cache failure discovered during deployment was repaired with Docker DNS resolution. Acceptance now replaces the backend while retaining the gateway and checks automatic recovery, alongside internal-route denial and database persistence across stack restart.
- **Full live workflow passed:** Docker ingestion, eBPF outage replay and capture integrity, profile construction/activation, scoring, detection, allowlist lifecycle, incident status updates, approved exact-target pause, idempotent approval, rollback and chronological audit evidence. Final containment ran on the final backend image.
- Source and test hashes match all five running service images. Response execution is restored to `disabled`, the responder has no pending completion receipts, and automatic retention remains disabled. All eight services are healthy. No commits, pushes, merges or branch changes were made.
- Logs, source/image hashes, benchmark inputs/results, and migration reproduction code: [`backlog validation results`](../../artifacts/local/backlog-validation/results.json). These local validation artifacts are ignored by Git.

## Command and lineage scoring pass

- [x] High — Add a named opt-in feature/scoring contract for secret-safe command shapes and observed parent-child sequences (IMP-06, IMP-22); preserve legacy profile/hash defaults.
- [x] High — Carry contract selection through profile build, observation scoring, persisted configuration, CLI and public configuration reads; keep incompatible inputs out of the existing ML classifier.
- [x] Medium — Preserve raw BusyBox/Toybox paths independently of applet identity in custom detection rules (IMP-10).
- [x] High — Add regressions for secret leakage, malformed/large commands, interleaved containers/hosts/sensors, absent lineage, hash compatibility, scoring and API integration.
- [x] High — Rebuild affected images and run static, all service suites, protocol integrity, PostgreSQL checks, and the complete live workflow. Record evidence and remaining work.


The opt-in command/lineage contract is implemented end to end; existing default profiles and study outputs retain their original contract. A recorded parent link contributes only when both selected events share the container, host, sensor and fixed window. Newly repaired lineage changes the new-contract score identity through the feature hash. Argument descriptors use a finite vocabulary; values and their hashes are not added to the command-shape family.

BusyBox/Toybox path comparisons now use raw paths, including case-sensitive `contains`; applet basename conditions remain available. The matcher identity records this change. The existing ML classifier selects only its compatible legacy score scale and binds container baseline context to that score's immutable profile. Direct feature-document classification rejects incompatible schemas.

New environment fingerprints include baseline and command-extractor source files. Building or selecting the new schema is explicit through the API or `--feature-schema porygon.behaviour.command-lineage`; the new [scoring guide](../command-lineage-scoring.md) documents extraction, coverage, configuration and model integration.

Remaining backlog after this pass: additional socket/file/memory telemetry (IMP-02), genuinely unobserved fork lineage (IMP-04), trained structural ML inputs (IMP-07), calibrated sparse numeric transforms (IMP-08), explicit local-image scan identity (IMP-15), and a natural upstream tag-drift study (IMP-18). The current command-shape weights do not change existing fixed numeric transforms or train a replacement classifier.


### Verification of command and lineage scoring

- **539 tests passed:** backend 242; collector 12; telemetry 24; responder 12; scanner 6; experiment/private-transport 243. The two PostgreSQL-only cases skipped in the SQLite suite were exercised separately.
- **7 PostgreSQL checks passed** in disposable schemas, including both scoring contracts, explicit profile activation, replay idempotence, insufficient command coverage, repaired-link score identity and compatible ML context selection, alongside incident/response concurrency checks.
- Legacy reference fixtures were captured from the pre-change image and compared against the final image: complete profile documents, model hashes, score components, explanations and observation keys match exactly.
- **Static checks, OpenAPI generation, Alembic upgrade SQL, protocol integrity and infrastructure passed.** Gateway recovery after backend replacement, internal-route denial and database persistence across restart remain valid. The new contract uses existing JSON/schema-identity fields and requires no new migration.
- **Complete live workflow passed:** Docker ingestion, eBPF capture/outage replay, profile construction and activation, scoring, detection, allowlist/incident lifecycle, approved exact-target pause, idempotent approval, rollback and chronological audit evidence.
- Live acceptance also built a quality-passing new-contract draft from real captured telemetry: 11 commands, 100% command coverage and one within-window parent-linked edge. The active legacy profile remained unchanged. The draft was not activated.
- Source/test hashes match all five running service images. All eight services are healthy. Response execution is restored to `disabled`, completion backlog is empty, and automatic retention remains disabled.
- No commits, pushes, merges, branch changes or presentation/research artifact edits were made. Local logs, source hashes, reference comparisons and the captured draft/configuration are in [command-lineage validation results](../../artifacts/local/command-lineage-validation/results.json).
