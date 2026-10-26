# Porygon Architecture & Security Audit: Improvements Backlog

This document establishes the authoritative, evidence-backed improvement backlog for the Porygon container runtime security research platform. It is maintained under the senior advisor protocol defined in [improve skill](file:///.agents/skills/improve/SKILL.md) and [AGENTS.md](file:///AGENTS.md).

All findings cite exact code coordinates verified against active source code. Findings are prioritized by leverage ($\text{Leverage} = \frac{\text{Impact}}{\text{Effort}} \times \text{Confidence}$), with forward-looking product direction avenues isolated separately from defect remediation.

---

## Executive Summary & Priority Matrix

| ID | Title | Category | Impact | Effort | Risk | Confidence | Leverage |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **[SEC-01]** | Guard Unauthenticated Public Access to System LLM Quota on `/api/v1/ai/audit` | Security | HIGH | S | LOW | HIGH | **3.0** |
| **[PERF-01]** | Chunk Parameter Bounds in Data Retention Deletion Queries | Performance | HIGH | S | LOW | HIGH | **3.0** |
| **[PERF-02]** | Bulk-Fetch Vulnerability Intel Records to Eliminate N+1 Ingestion Queries | Performance | HIGH | S | LOW | HIGH | **3.0** |
| **[CORR-01]** | Enforce Temporal Causality and Sensor Scoping in Detection Ancestor Chains | Correctness | MED | S | LOW | HIGH | **2.0** |
| **[TEST-01]** | Add Integration Battery for High-Volume Retention Parameter Limits | Test Coverage | MED | S | LOW | HIGH | **2.0** |
| **[PERF-03]** | Invert Collector Container Cache Checks to Prevent Docker Socket Storms | Performance | HIGH | M | LOW | HIGH | **1.5** |
| **[ARCH-01]** | Augment ML Classifier with Behavioral Path & Inode Indicators (IMP-07) | Architecture | HIGH | M | LOW | HIGH | **1.5** |
| **[SEC-02]** | Expand Falco Rules and Spool Outbox to Multi-Syscall Telemetry (IMP-02) | Security | CRITICAL | L | MED | HIGH | **1.33** |
| **[PERF-04]** | Decouple Synchronous Identity Reconciliation from Ingestion Request Path | Performance | MED | M | LOW | HIGH | **1.0** |

---

## 1. Security

### [SEC-01] Guard Unauthenticated Public Access to System LLM Quota on `/api/v1/ai/audit`

- **Evidence**: [`backend/src/porygon_api/main.py:2686-2716`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py#L2686-L2716) — Route `/api/v1/ai/audit` accepts an optional caller API key, but silently falls back to server-configured `settings.ai_api_key.get_secret_value()` without requiring operator authentication (`require_operator_token`).
- **Impact**: Any unauthenticated client with network access to the API can issue repeated audit requests against arbitrary container IDs, consuming Gemini/OpenAI API quotas, exhausting rate limits, and incurring uncontrolled cloud billing charges.
- **Effort**: S (hours).
- **Risk**: LOW — internal automated callers or dashboard clients must supply `X-Porygon-Operator-Token` when relying on the backend's shared AI credentials.
- **Confidence**: HIGH (verified in route definition).
- **Fix sketch**: Require `require_operator_token` dependency on `/api/v1/ai/audit` whenever the caller does not supply their own explicit `X-Porygon-AI-Key` or payload key.

### [SEC-02] Expand Falco Rules and Spool Outbox to Multi-Syscall Telemetry (IMP-02)

- **Evidence**: [`falco/porygon_rules.yaml:3-6`](file:///home/anuruprkris/Project/final_yeat_work/falco/porygon_rules.yaml#L3-L6) and [`telemetry/src/porygon_telemetry/normalizer.py:82-89`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/src/porygon_telemetry/normalizer.py#L82-L89) — Falco hooks only `execve`/`execveat`, and normalizer strictly rejects any event where `rule != "Porygon Container Process Execution"`.
- **Impact**: Attackers executing in-memory payloads (`memfd_create`), opening outbound network command-and-control sockets (`connect`), elevating capabilities (`capset`, `setuid`), or tampering with critical host configurations (`openat`) bypass process execution telemetry entirely.
- **Effort**: L (multi-day).
- **Risk**: MED — requires schema migrations across telemetry spool database, delivery loop endpoints, and backend batch ingestion.
- **Confidence**: HIGH (verified in Falco rule engine and normalizer drop filter).
- **Fix sketch**: Add Falco rules for non-loopback outbound socket connections, in-memory execution, and sensitive file modification. Update `porygon_telemetry` normalizer and outbox schema to multiplex `runtime_events` alongside `process_events`, posting to `/internal/v1/runtime-events/batch`.

---

## 2. Performance

### [PERF-01] Chunk Parameter Bounds in Data Retention Deletion Queries

- **Evidence**: [`backend/src/porygon_api/retention.py:90-113`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/retention.py#L90-L113) and [`backend/src/porygon_api/config.py:47`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/config.py#L47) — `apply_retention` queries up to `retention_max_delete_batch` (default 50,000) IDs and passes them directly to `ProcessExecEvent.event_id.in_(process_ids)`.
- **Impact**: In SQLite environments, passing 50,000 bound parameters exceeds `SQLITE_MAX_VARIABLE_NUMBER` (32,766 limit), raising `sqlite3.OperationalError: too many SQL variables`. In PostgreSQL, sending 50,000 parameter placeholders (`$1...$50000`) inflates statement payload size to >1.5 MB and triggers severe query planner memory allocation spikes.
- **Effort**: S (hours).
- **Risk**: LOW — bounded chunking or subquery deletion preserves transactional semantics while protecting database drivers.
- **Confidence**: HIGH (verified in retention execution path).
- **Fix sketch**: Chunk `process_ids` into slices of 1,000 IDs per `DELETE` statement, or execute direct subquery deletion via `ProcessExecEvent.event_id.in_(select(ProcessExecEvent.event_id).where(...).limit(...))` where supported by the dialect.

### [PERF-02] Bulk-Fetch Vulnerability Intel Records to Eliminate N+1 Ingestion Queries

- **Evidence**: [`backend/src/porygon_api/main.py:4278-4281`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py#L4278-L4281) — In `/internal/v1/image-scans/{scan_id}/complete`, `for cve_id in sorted(cve_ids): intel = db.get(VulnerabilityIntel, cve_id)` executes an individual synchronous SELECT query for every detected CVE.
- **Impact**: Standard production base images (Ubuntu, Debian, Python) frequently contain 300–800 CVEs. Ingesting scan results performs hundreds of sequential database round-trips inside a single HTTP request, tying up connection pool connections and risking client gateway timeouts.
- **Effort**: S (hours).
- **Risk**: LOW — purely optimizes read retrieval before inserting/updating records in session.
- **Confidence**: HIGH (verified in loop construct).
- **Fix sketch**: Query existing records in a single bulk operation `db.scalars(select(VulnerabilityIntel).where(VulnerabilityIntel.cve_id.in_(cve_ids))).all()`, index them in a Python dictionary by `cve_id`, and instantiate missing models in-memory before flushing.

### [PERF-03] Invert Collector Container Cache Checks to Prevent Docker Socket Storms

- **Evidence**: [`collector/src/porygon_collector/normalizer.py:218-222`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/normalizer.py#L218-L222) and [`collector/src/porygon_collector/docker_source.py:177`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/docker_source.py#L177) — `normalize_event` invokes `build_container_snapshot` synchronously on every raw Docker event, only checking `store.get_cached_container` when Docker API calls raise an exception (`APIError`, `NotFound`).
- **Impact**: Although `_warm_container_cache` populates the SQLite cache on startup, the collector never reads from cache during normal container execution. Under container event bursts (e.g. rapid exec commands or healthchecks), every event triggers two synchronous Docker socket round-trips (`inspect_container` + `inspect_image`), creating backpressure and queuing latency in `docker_source`.
- **Effort**: M (a day-ish).
- **Risk**: LOW — container immutable metadata (`image_digest`, `labels`, `privileged`) remains static; only runtime state (`status`, `running`) mutates.
- **Confidence**: HIGH (verified in normalizer inspection flow).
- **Fix sketch**: Check `store.get_cached_container(container_id)` first. Only re-inspect container state from the Docker daemon on lifecycle transition events (`start`, `die`, `stop`, `destroy`) or after a bounded cache TTL (e.g. 30 seconds).

### [PERF-04] Decouple Synchronous Identity Reconciliation from Ingestion Request Path

- **Evidence**: [`backend/src/porygon_api/main.py:811-812`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py#L811-L812) — In `ingest_process_events`, after committing the batch, `_reconcile_process_identities(db)` is called synchronously within the same HTTP request handler.
- **Impact**: `_reconcile_process_identities` executes two correlated subquery table scans and row-by-row parent correlation queries (`_find_parent_event_id`). Under continuous eBPF telemetry streaming, every POST request incurs multi-second latency while re-evaluating historical unreconciled records.
- **Effort**: M (a day-ish).
- **Risk**: LOW — reconciliation is inherently idempotent and designed to resolve eventually consistent parent-child relationships.
- **Confidence**: HIGH (verified in batch handler lifecycle).
- **Fix sketch**: Move `_reconcile_process_identities` into a background worker task or schedule it periodically (e.g. every 5 seconds or when unreconciled queue depth exceeds a threshold) rather than executing it synchronously inside every incoming ingestion POST.

---

## 3. Correctness & Bugs

### [CORR-01] Enforce Temporal Causality and Sensor Scoping in Detection Ancestor Chains

- **Evidence**: [`backend/src/porygon_api/detection.py:330-351`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/detection.py#L330-L351) vs. [`backend/src/porygon_api/baseline.py:191-199`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/baseline.py#L191-L199) — While `baseline.py` strictly asserts `sensor_instance_id` scoping and `if parent.occurred_at > child.occurred_at: continue`, `detection.py:_ancestor_chain` omits sensor scoping and never checks temporal order between parent and child.
- **Impact**: If telemetry events arrive out-of-order, host sensor clocks skew, or PID recycling occurs across container engine restarts, an event that occurred *after* the child can be linked into `_ancestor_chain`, producing acausal lineage trees and triggering erroneous custom ancestor rule matches (`scope: "ancestor"`).
- **Effort**: S (hours).
- **Risk**: LOW — aligns detection ancestor walking with the established baseline causality invariant.
- **Confidence**: HIGH (verified by comparing `baseline.py` and `detection.py`).
- **Fix sketch**: In `detection.py:_ancestor_chain`, break traversal if `getattr(parent, "sensor_instance_id", None) != getattr(current, "sensor_instance_id", None)` or if `parent.occurred_at > current.occurred_at`.

---

## 4. Test Coverage

### [TEST-01] Add Integration Battery for High-Volume Retention Parameter Limits

- **Evidence**: [`backend/tests/test_retention.py:112-160`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_retention.py#L112-L160) — Test suite exercises `apply_retention` with `max_delete_batch=2` and `max_delete_batch=1000`, but has zero test cases exercising production bounds (`max_delete_batch=50000`) or validating chunking against SQLite / PostgreSQL parameter ceilings.
- **Impact**: Database parameter overflow regressions can pass unit test suites and manifest exclusively in high-throughput production deployments.
- **Effort**: S (hours).
- **Risk**: LOW — purely expands automated regression assertions.
- **Confidence**: HIGH (verified in test fixtures).
- **Fix sketch**: Add parametrized unit test in `test_retention.py` asserting that deleting a batch exceeding parameter chunk bounds executes cleanly without parameter overflow exceptions.

---

## 5. Architecture & Tech Debt

### [ARCH-01] Augment ML Classifier with Behavioral Path & Inode Indicators (IMP-07)

- **Evidence**: [`backend/src/porygon_api/ml_classifier.py:42-81, 186-218`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/ml_classifier.py#L42-L81) — Classification taxonomy uses static basename frozensets (`SHELL_BINARIES`, `SUSPICIOUS_TOOLS`, `RECON_BINARIES`).
- **Impact**: Adversaries routinely evade basename filtering by copying binaries to temporary paths (e.g., `cp /bin/sh /tmp/worker` or `/dev/shm/.x`), setting `token` to an unrecognized basename and reducing all risk category counters to zero.
- **Effort**: M (a day-ish).
- **Risk**: LOW — preserves existing feature vector compatibility while introducing richer behavioral inputs.
- **Confidence**: HIGH (verified in feature extractor loop).
- **Fix sketch**: Add behavioral runtime signals to feature extraction: execution from writable directories (`/tmp`, `/dev/shm`), unlinked executables (`(deleted)` inode suffix), and argument entropy, feeding these directly into Random Forest tree decisions.

---

## 6. Considered and Rejected

Per Senior Advisor protocol, candidate findings investigated and determined to be by-design or low-signal are explicitly recorded to prevent redundant future re-auditing:

1. **Custom Rule Case-Sensitivity on Linux Executable Paths**:
   - *Investigation*: `detection.py:434` evaluates `/path` containment case-sensitively, whereas basename matching is case-insensitive.
   - *Verdict*: **Rejected as by-design**. Linux virtual filesystem paths are strictly case-sensitive (`/usr/bin/python` is distinct from `/USR/BIN/PYTHON`). `backend/tests/test_detection.py:891-896` (`test_explicit_path_contains_is_case_sensitive_and_does_not_invent_missing_paths`) intentionally asserts this behavior under `MATCHER_REVISION = "porygon.detection.matcher.raw-multicall-paths"`.
2. **Unauthenticated Health & Readiness Endpoints**:
   - *Investigation*: `/health/live` and `/health/ready` across all microservices lack token dependencies.
   - *Verdict*: **Rejected as by-design**. Standard container platform orchestrators (Docker healthcheck, Kubernetes kubelet probes) require unauthenticated, zero-overhead HTTP status probes. Sensitive internal state is omitted from public healthcheck schemas.

---

## 7. Product Direction & Future Avenues

*These strategic opportunities represent grounded architecture expansions rather than defect remediation, presented separately for roadmap planning.*

### [DIR-01] Real-Time Containment Push Bus (SSE / WebSocket / gRPC)

- **Evidence**: [`responder/src/porygon_responder/main.py:140-171`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/main.py#L140-L171) — The responder loops on `await asyncio.sleep(settings.poll_seconds)` (default 1s) to poll `/internal/v1/response-executions/claim`.
- **Value**: In active container breach scenarios (ransomware payload staging, credential harvesting), a 1000–2000ms polling latency allows attackers to complete malicious execution before container freeze/pause occurs. Establishing a lightweight Server-Sent Events (SSE) or gRPC push channel from the backend to active responder agents reduces containment latency to sub-50ms.
- **Trade-offs**: Requires persistent streaming connection management and reconnection logic across the internal Docker bridge network; HTTP polling remains necessary as an automatic fallback.
- **Effort**: M (design spike + integration).
- **Confidence**: HIGH (grounded in existing polling architecture).

### [DIR-02] eBPF Network Socket Correlation with Vulnerable Package SBOMs

- **Evidence**: [`scanner/src/porygon_scanner/scanner.py:114-132`](file:///home/anuruprkris/Project/final_yeat_work/scanner/src/porygon_scanner/scanner.py#L114-L132) (rich CycloneDX SBOM and CISA KEV catalog) vs. [`falco/porygon_rules.yaml`](file:///home/anuruprkris/Project/final_yeat_work/falco/porygon_rules.yaml) (lacks outbound network socket telemetry).
- **Value**: Porygon currently computes vulnerability runtime exposure by checking whether container processes executed a binary from a vulnerable package. By extending telemetry to hook network sockets (`connect`), Porygon can correlate outbound public IP connections directly against containers harboring known remote code execution (RCE) vulnerabilities listed in CISA KEV, automatically escalating incidents to critical priority.
- **Trade-offs**: Increases Falco kernel eBPF event volume and requires IP/DNS enrichment; introduces higher telemetry buffer utilization.
- **Effort**: L (multi-service integration).
- **Confidence**: HIGH (grounded in scanner data model and eBPF capabilities).
