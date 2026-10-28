# Porygon Enterprise Pathway & Architecture Audit

This document establishes the authoritative, evidence-backed improvement backlog and architectural transformation roadmap for the **Porygon** container runtime security platform, maintained under the Senior Advisor protocol defined in [Improve](file:///.agents/skills/improve/SKILL.md) and [AGENTS.md](file:///AGENTS.md).

---

## Executive Summary: Bridging the Gap to Production Enterprise Readiness

Porygon possesses strong core security engineering fundamentals:
- **Digest-Bound Identity**: Workloads are cryptographically bound to immutable repository digests (`image_digest`), not mutable tags ([`models.py:77-124`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/models.py#L77-L124)).
- **Modern Kernel eBPF Telemetry**: The platform utilizes Falco's `modern_ebpf` engine rather than legacy kernel modules ([`compose.yaml:376-441`](file:///home/anuruprkris/Project/final_yeat_work/compose.yaml#L376-L441)).
- **Mathematically Grounded Drift Detection**: Jensen-Shannon behavioral distance and calibrated rarity scoring prevent the alert fatigue common to naive allowlists ([`scoring.py:1-120`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/scoring.py#L1-L120)).
- **Idempotent Containment State Machine**: Automated containment actions enforce state preconditions, cryptographic leases, and rollback verifications ([`executor.py:32-151`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/executor.py#L32-L151), [`response.py:1-75`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/response.py#L1-L75)).

However, **Porygon's original baseline was a single-host research system**. No cloud-native enterprise or Fortune 500 platform security team could deploy it in that state without encountering production outages, Kubernetes controller conflicts, or severe telemetry blind spots.

This document details the concrete architectural evolution, tracks the completed multi-syscall and performance implementations landed in commit [`b04aaea`](file:///home/anuruprkris/Project/final_yeat_work), and defines the remaining implementation pathway toward an enterprise-ready Cloud Workload Protection Platform (CWPP).

---

## 1. Verified Remediations (Completed & Landed in Codebase)

The following findings and architectural gaps have been resolved, covered with regression test suites, and verified inside active container environments:

### Multi-Syscall & Asynchronous Architecture (Landed in Commit `b04aaea`)

- **`[SEC-02]` Multi-Syscall Kernel Runtime Telemetry Pipeline (IMP-02)**:
  - *Fix*: Extended [`falco/porygon_rules.yaml`](file:///home/anuruprkris/Project/final_yeat_work/falco/porygon_rules.yaml) with rules for non-loopback outbound socket connections (`connect`), in-memory anonymous execution (`memfd_create`), and sensitive file modifications (`open`, `openat`). Implemented kernel event normalization in [`telemetry/src/porygon_telemetry/kernel.py`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/src/porygon_telemetry/kernel.py), dual-channel outbox spooling and batch draining in [`telemetry/src/porygon_telemetry/spool.py`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/src/porygon_telemetry/spool.py), Alembic database migration [`backend/alembic/versions/kernel_runtime_events.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/alembic/versions/kernel_runtime_events.py), authenticated batch ingestion (`/internal/v1/kernel-events/batch`) and query endpoints in [`backend/src/porygon_api/kernel_events.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/kernel_events.py), and interactive telemetry viewer tabs in [`dashboard/app.js`](file:///home/anuruprkris/Project/final_yeat_work/dashboard/app.js) and [`dashboard/index.html`](file:///home/anuruprkris/Project/final_yeat_work/dashboard/index.html).
  - *Verification*: Verified via [`backend/tests/test_kernel_events.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_kernel_events.py), [`telemetry/tests/test_kernel_channels.py`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/tests/test_kernel_channels.py), and [`scripts/verify_kernel_runtime.py`](file:///home/anuruprkris/Project/final_yeat_work/scripts/verify_kernel_runtime.py). Documented in [`docs/kernel-runtime-telemetry.md`](file:///home/anuruprkris/Project/final_yeat_work/docs/kernel-runtime-telemetry.md).
- **`[PERF-03]` Inverted Collector Container Inspection Cache (Prevents Docker Socket Storms)**:
  - *Fix*: Inverted container metadata inspection logic in [`collector/src/porygon_collector/normalizer.py`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/normalizer.py) to query the SQLite cache first before invoking synchronous Docker socket `inspect` calls. Real-time Docker daemon queries are strictly gated to lifecycle events (`start`, `die`, `stop`, `destroy`) or cache misses, eliminating socket storms during event bursts.
  - *Verification*: Verified via 16 unit tests in [`collector/tests/test_container_cache.py`](file:///home/anuruprkris/Project/final_yeat_work/collector/tests/test_container_cache.py) and documented in [`docs/review/collector-inspection-cache.md`](file:///home/anuruprkris/Project/final_yeat_work/docs/review/collector-inspection-cache.md).
- **`[PERF-04]` Decoupled Identity Reconciliation from Ingestion Request Path**:
  - *Fix*: Removed the synchronous invocation of `_reconcile_process_identities(db)` from `ingest_process_events` in [`backend/src/porygon_api/main.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py). Offloaded identity resolution and parent-process repair to a dedicated background reconciliation worker in [`backend/src/porygon_api/reconciliation.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/reconciliation.py) with endpoints `/api/v1/reconciliation/status` and `/api/v1/reconciliation/trigger`.
  - *Verification*: Verified across backend suite and live acceptance checks.

### Core Security & Query Optimization (Landed in Commit `3270f61`)

- **`[SEC-01]` Operator Authentication on AI Audit Fallback**:
  - *Fix*: Added `X-Porygon-Operator-Token` header verification on `/api/v1/ai/audit` when callers fall back to server-configured AI credentials ([`main.py:2706-2725`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py#L2706-L2725)).
  - *Verification*: Verified in [`backend/tests/test_ai_auditor.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_ai_auditor.py).
- **`[PERF-01]` & `[TEST-01]` Database Retention Chunking**:
  - *Fix*: Implemented query parameter chunking (batches of 500 IDs) for `ProcessExecEvent` and `RuntimeEvent` deletions in `apply_retention` ([`retention.py:90-115`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/retention.py#L90-L115)), eliminating SQLite parameter limit errors and Postgres query planner degradation during high-volume data retention passes.
  - *Verification*: Verified with a 1,200-event batch test in [`backend/tests/test_retention.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_retention.py).
- **`[PERF-02]` Bulk Vulnerability Intelligence Retrieval**:
  - *Fix*: Replaced sequential `db.get(VulnerabilityIntel, cve_id)` lookups with a single `select(...).where(VulnerabilityIntel.cve_id.in_(cve_ids))` bulk fetch in `complete_image_scan` ([`main.py:4288-4315`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py#L4288-L4315)), eliminating 300–800 sequential database round-trips per scanned image.
- **`[CORR-01]` Temporal Causality & Sensor Scoping in Ancestor Trees**:
  - *Fix*: Enforced temporal causality (`parent.occurred_at <= current.occurred_at` and `parent.time_nano <= current.time_nano`) and matching `sensor_instance_id` in `_ancestor_chain` ([`detection.py:344-358`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/detection.py#L344-L358)), preventing clock skew or cross-sensor event mixing from producing acausal lineage trees.
  - *Verification*: Verified in [`backend/tests/test_detection.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_detection.py).

### Continuous Assessment, Scoped Identity & Fenced Webhooks (Landed in Commits `6f845d5`, `9e982f0`, `7d9a211`)

- **`[SEC-03]` Database-Enrolled API Credentials & Scoped Principal RBAC**:
  - *Fix*: Replaced static shared environment variables with database-backed `ApiCredential` records ([`models.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/models.py), [`enrolled_credentials.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/alembic/versions/enrolled_credentials.py)). Implemented scoped principals (`operator`, `service`, `system`), expiration, revocation, strict host-binding checks (`enforce_host`), and fail-closed route authorization matrix ([`permissions.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/permissions.py), [`auth.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/auth.py)). Added administrative CLI [`scripts/porygon_credentials.py`](file:///home/anuruprkris/Project/final_yeat_work/scripts/porygon_credentials.py) and authenticated profile [`compose.authenticated.yaml`](file:///home/anuruprkris/Project/final_yeat_work/compose.authenticated.yaml).
  - *Verification*: Verified via [`test_credentials.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_credentials.py), [`test_agent_identity.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_agent_identity.py), [`test_auth_permissions.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_auth_permissions.py), and [`test_credential_migration.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_credential_migration.py).
- **`[DIR-03]` Fenced Notification Outbox & SSRF-Protected Webhooks**:
  - *Fix*: Implemented durable `NotificationDelivery` outbox table ([`operational_delivery.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/alembic/versions/operational_delivery.py)), asynchronous notification worker ([`notification_worker.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/notification_worker.py)), HMAC-SHA256 payload signing (`X-Porygon-Signature`), and strict SSRF defenses verifying resolved IP addresses against private and non-routable CIDRs.
  - *Verification*: Verified via [`test_notifications.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_notifications.py) and [`test_notification_worker.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_notification_worker.py).
- **`[ARCH-01]` Scientific Honesty & ML Model Governance**:
  - *Fix*: Purged false marketing claims of "Random Forest" and "TreeSHAP" for the hand-crafted 5-rule heuristic in [`ml_classifier.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/ml_classifier.py). Formalized `Heuristic Tree Ensemble` with explicit `ClassifierMetadata` tracking version, training corpus provenance, and raw tree-path deltas. Established reproducible group-split training, Brier score calibration, and promotion gates in [`experiments/models/`](file:///home/anuruprkris/Project/final_yeat_work/experiments/models/).
  - *Verification*: Verified via [`test_ml_classifier.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_ml_classifier.py) and [`test_model_contracts.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_model_contracts.py).
- **`[OPS-02]` Continuous Service Trust & Windowed Assessment Engine**:
  - *Fix*: Built continuous assessment scheduling engine with PostgreSQL `FOR UPDATE SKIP LOCKED` bounded queue claiming (`AssessmentWorker` in [`window_worker.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/window_worker.py)), generational leasing, target registration, temporal window slicing ([`assessment_service.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/assessment_service.py)), and formal profile lifecycle (`draft` -> `candidate` -> `approved` -> `archived`) with explicit approval audits in [`profile_lifecycle.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/profile_lifecycle.py).
  - *Verification*: Verified via [`test_window_worker.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_window_worker.py), [`test_assessment_service.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_assessment_service.py), [`test_profile_lifecycle.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_profile_lifecycle.py), and [`scripts/verify_continuous_detection.py`](file:///home/anuruprkris/Project/final_yeat_work/scripts/verify_continuous_detection.py).
- **`[CORR-02]` Atomic Incident State Machine & Evidence Audit**:
  - *Fix*: Implemented row-locked status transitions (`open` -> `acknowledged` -> `resolved` / `dismissed`) in [`incident_transitions.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/incident_transitions.py), enforcing valid state machine arcs, batch mutations, and append-only `IncidentEvidence` audit logs.
  - *Verification*: Verified via [`test_incident_transitions.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_incident_transitions.py).
- **`[PERF-05]` Kernel Runtime Retention & Verification Harness Hardening**:
  - *Fix*: Added table pruning support for `kernel_runtime_events` inside [`retention.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/retention.py) with chunked deletion queries, preventing unbounded database growth during heavy syscall collection. Hardened [`scripts/verify_kernel_runtime.py`](file:///home/anuruprkris/Project/final_yeat_work/scripts/verify_kernel_runtime.py).
  - *Verification*: Verified in [`backend/tests/test_kernel_events.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/tests/test_kernel_events.py) and [`telemetry/tests/test_kernel_channels.py`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/tests/test_kernel_channels.py).

---

## 2. The 5 Production Chasms: Status & Evolution

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              PRODUCTION GAP EVOLUTION STATUS                           │
├───────────────────────────────┬──────────────────────────────────┬─────────────────────┤
│ PRODUCTION REQUIREMENT        │ INITIAL STATE (BASELINE)         │ CURRENT STATE       │
├───────────────────────────────┼──────────────────────────────────┼─────────────────────┤
│ 1. Multi-Syscall Fabric       │ execve-only; all others dropped  │ [RESOLVED] in b04aa │
│ 2. Collector Efficiency       │ Sync Docker socket query storms  │ [RESOLVED] in b04aa │
│ 3. Background Reconciliation  │ Sync request handler blocking    │ [RESOLVED] in b04aa │
│ 4. SecOps Webhooks & SIEM     │ Incidents trapped in DB tables   │ [RESOLVED] in 7d9a2 │
│ 5. Vulnerability-Threat Corr. │ Detection blind to KEV/EPSS CVEs │ [ACTIVE] Track 02   │
│ 6. Safe K8s Network Isolation │ Destructive Docker pause/stop    │ [ACTIVE] Track 03   │
│ 7. OIDC / RBAC Governance     │ Static shared env tokens         │ [RESOLVED] in 7d9a2 │
│ 8. Kubernetes DaemonSet Agent │ Single-host Docker socket bind   │ [ACTIVE] Track 05   │
└───────────────────────────────┴──────────────────────────────────┴─────────────────────┘
```

### Chasm 1: Node Agent vs. Centralized Fleet Topology
* **Evidence in Code**:
  - [`compose.yaml:163,295,353`](file:///home/anuruprkris/Project/final_yeat_work/compose.yaml#L163) binds the host `/var/run/docker.sock` directly into `collector`, `responder`, and `scanner`.
  - [`collector/src/porygon_collector/docker_source.py:47-70`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/docker_source.py#L47-L70) connects exclusively to the local Docker daemon.
  - [`responder/src/porygon_responder/executor.py:42`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/executor.py#L42) invokes `docker.DockerClient(base_url=base_url)`.
* **Production Reality**:
  - Enterprise workloads run on Kubernetes (EKS, GKE, AKS, OpenShift) where Docker Engine was removed (Dockershim deprecation). The underlying runtime is **`containerd`** or **`CRI-O`** accessed via `/run/containerd/containerd.sock`.
  - Enterprises operate dozens or hundreds of nodes. Running the full Porygon stack on every node is impossible.
* **Target Architecture**:
  - Decouple Porygon into a **Lightweight Node Agent** (`porygon-agent` DaemonSet packaging Falco eBPF + CRI lifecycle stream) and a **Centralized Control Plane** (`porygon-control-plane` deployment running FastAPI, PostgreSQL, and background scoring workers).
  - Agents stream events upstream to the control plane over gRPC with mutual TLS (`mTLS`).

### Chasm 2: Telemetry Depth Beyond `execve` (RESOLVED in `b04aaea`)
* Multi-syscall kernel events (`connect`, `memfd_create`, `openat`) are now normalized, spooled in a durable outbox, ingested via `/internal/v1/kernel-events/batch`, and queryable at `/api/v1/kernel-events`.

### Chasm 3: Safe Cloud-Native Containment & Blast-Radius Governance
* **Evidence in Code**:
  - [`responder/src/porygon_responder/executor.py:158-171`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/executor.py#L158-L171) executes `docker pause` and `docker stop`.
* **Production Reality**:
  - **Pausing Containers in Kubernetes**: Freezing cgroups pauses the application's liveness probe server. Kubelet marks the pod unready, kills it, and schedules a replacement pod.
  - **Stopping Containers in Kubernetes**: Terminating a pod causes the `ReplicaSet` controller to immediately spawn an identical pod, restarting the attacker while destroying volatile memory evidence.
* **Target Architecture**:
  - **Dynamic Kubernetes NetworkPolicy Quarantine**: Instead of terminating pods, apply a dynamic `NetworkPolicy` targeting the pod label (`porygon.io/isolation: isolated`), cutting off ingress/egress while leaving memory intact for live forensic memory acquisition (`gcore`).
  - **Fleet Blast-Radius Rate Limiter**: Enforce limits preventing automated containment from ever isolating more than 1 pod per Deployment or 5% of cluster capacity per hour, with strict blacklisting of system namespaces (`kube-system`, `istio-system`, `porygon`).

### Chasm 4: Ingestion Throughput & Streaming Event Architecture
* With collector cache inversion (`[PERF-03]`) and background reconciliation (`[PERF-04]`) resolved in `b04aaea`, ingestion overhead on the API server dropped dramatically.
* The remaining scale challenge for high-density 100+ node clusters is buffering events between node agents and the API server using Redis Streams or NATS JetStream.

### Chasm 5: Enterprise Governance, Identity (RBAC/OIDC) & Ecosystem Integration (RESOLVED in `7d9a211`)
* Replaced static shared environment variables with database-backed `ApiCredential` records, scoped roles, and fail-closed route permissions.
* Implemented HMAC-SHA256 signed notification webhooks with SSRF guard and exponential backoff retry outbox.

---

## 3. Prioritized Leverage Matrix (Active & Remaining Tracks)

Applying the Senior Advisor formula:
$$\text{Leverage} = \frac{\text{Impact}}{\text{Effort}} \times \text{Confidence}$$

| ID | Title | Category | Impact | Effort | Risk | Confidence | Leverage | Status |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **[SEC-AUTH-01]** | Return 403 Forbidden for Non-Operator Principals in `require_operator_token` | Security / Auth | HIGH | XS | LOW | HIGH | **3.0** | **ACTIVE (High Leverage Bug)** |
| **[DOC-SLOP-01]** | Purge Academic Course Markers from Production Docs (`docs.html:31,763`) | Documentation | HIGH | XS | LOW | HIGH | **2.0** | **ACTIVE (Rule 2.2 Fix)** |
| **[SEC-AUTH-02]** | Salted or HMAC-Peppered API Token Digests in Database | Security / Auth | HIGH | S | LOW | HIGH | **2.0** | **ACTIVE** |
| **[DIR-03]** | Enterprise Incident Webhook & SIEM Forwarding Engine | Direction / DX | HIGH | S | LOW | HIGH | **2.0** | **RESOLVED (`7d9a211`)** |
| **[DIR-02]** | Unified Vulnerability (CISA KEV / EPSS) Threat Correlation | Direction / Det | HIGH | M | LOW | HIGH | **1.5** | **ACTIVE (Next Feature)** |
| **[ARCH-01]** | Scientific ML Model Governance & Heuristic Metadata | Architecture | HIGH | M | LOW | HIGH | **1.5** | **RESOLVED (`7d9a211`)** |
| **[SEC-03]** | Enrolled Database Credentials & Scoped Principal RBAC | Security / Auth | HIGH | M | LOW | HIGH | **1.33** | **RESOLVED (`7d9a211`)** |
| **[PERF-WORKER-01]** | Eliminate Double JSON Decode/Encode in Service Auth Middleware | Performance | MED | S | LOW | HIGH | **1.5** | **ACTIVE** |
| **[CORR-JOB-01]** | Window Worker Cursor Advance Atomicity & Target Starvation Guard | Correctness | MED | S | LOW | HIGH | **1.5** | **ACTIVE** |
| **[DIR-04]** | Kubernetes Dynamic NetworkPolicy Containment & Blast-Radius | Direction / Resp | HIGH | L | MED | HIGH | **1.2** | **ACTIVE** |
| **[ARCH-02]** | Distributed Event Streaming Bus (NATS JetStream / Redis Streams) | Architecture | HIGH | L | MED | MED | **0.8** | **ACTIVE** |
| **[OPS-01]** | Helm Chart Packaging for Multi-Node Kubernetes DaemonSet | Operations | HIGH | L | LOW | HIGH | **0.8** | **ACTIVE** |

---

## 4. Phase-by-Phase Master Engineering Pathway

---

### Phase 1: Telemetry & Threat Fabric

#### Task 1.1: Multi-Syscall Telemetry Pipeline Activation (`[SEC-02]`) — **[COMPLETED in commit `b04aaea`]**
* **Delivered**: Falco rules for network connections, in-memory execution, and sensitive file writes; normalization engine; spool outbox; backend API endpoints.

#### Task 1.2: Unified Vulnerability & Behavioral Threat Correlation (`[DIR-02]`) — **[ACTIVE ROADMAP]**
* **Evidence**: [`backend/src/porygon_api/detection.py:16-80`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/detection.py#L16-L80) evaluates process and runtime anomalies in isolation from vulnerability intelligence in [`vulnerability.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/vulnerability.py).
* **Implementation Blueprint**:
  1. Add rule `POR-DET-008: Exploited Vulnerability Runtime Execution` in `backend/src/porygon_api/detection.py`:
     - Severity: 0.98, Confidence: 0.95.
     - Description: Process or network anomaly detected inside a container image harboring actively exploited CVEs (CISA KEV or EPSS > 0.50).
  2. Enrich detection run context with active `VulnerabilityFinding` records for the container's `image_digest`.
  3. When an anomaly matches a container with an active CISA KEV finding, escalate severity score to critical.
* **Done Criteria**:
  ```bash
  docker compose exec -T backend pytest tests/test_detection.py
  ```

---

### Phase 2: SecOps Ecosystem & Governance

#### Task 2.1: Enterprise Webhook & SIEM Forwarding Engine (`[DIR-03]`) — **[COMPLETED in commit `7d9a211`]**
* **Delivered**: `NotificationDelivery` outbox table, asynchronous `NotificationWorker`, HMAC-SHA256 signature verification, SSRF private IP validation, retry backoff. Verified via `test_notifications.py` and `test_notification_worker.py`.

#### Task 2.2: Enrolled Credentials & Scoped Principal RBAC (`[SEC-03]`) — **[COMPLETED in commit `7d9a211`]**
* **Delivered**: Database-backed `ApiCredential` entity, scoped roles (`operator`, `service`, `system`), strict host binding (`enforce_host`), route permission table (`ROUTE_PERMISSIONS`), fail-closed middleware, and CLI enrollment tool. Verified via `test_credentials.py` and `test_agent_identity.py`.

#### Task 2.3: Security & Correctness Hardening on Auth Layer (`[SEC-AUTH-01]`, `[SEC-AUTH-02]`) — **[ACTIVE ROADMAP]**
* **Evidence**: [`security.py:28-31`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/security.py#L28-L31) returns 401 instead of 403 when authenticated service principals access operator routes. [`auth.py:23-24`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/auth.py#L23-L24) stores unsalted SHA-256 digests.
* **Implementation Blueprint**:
  1. Update `require_operator_token` to raise `HTTPException(403, 'Operator credential required')` when `principal.kind != 'operator'`.
  2. Add pepper or per-credential random salt to `token_digest` calculations to protect database dumps against precomputed rainbow table lookups.
* **Done Criteria**:
  ```bash
  docker compose exec -T backend pytest tests/test_auth_permissions.py
  ```

---

### Phase 3: Cloud-Native Non-Destructive Containment

#### Task 3.1: Kubernetes Dynamic NetworkPolicy Quarantine (`[DIR-04]`) — **[ACTIVE ROADMAP]**
* **Evidence**: [`responder/src/porygon_responder/executor.py:158-171`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/executor.py#L158-L171) executes `docker pause` and `docker stop`.
* **Implementation Blueprint**:
  1. Add `KubernetesResponseExecutor` in `responder/src/porygon_responder/k8s_executor.py`:
     - Uses official `kubernetes` Python client.
     - Operation `isolate_pod_network`: Dynamically creates a Kubernetes `NetworkPolicy` targeting the compromised pod label, dropping ingress and egress while keeping the container alive for live forensic dump.
     - Operation `rollback`: Deletes the generated quarantine `NetworkPolicy`.
  2. Implement Fleet Blast-Radius Limiter:
     - Hard limit: Maximum 1 pod isolated per Deployment in a rolling 1-hour window.
     - Hard guard: Rejects requests targeting pods in `kube-system`, `kube-public`, `porygon`, and ingress controllers.
* **Done Criteria**:
  ```bash
  docker compose exec -T responder pytest tests/test_k8s_executor.py
  ```

---

### Phase 4: High-Throughput Stream Ingestion & Collector Optimization

#### Task 4.1: Invert Collector Container Cache Checks (`[PERF-03]`) — **[COMPLETED in commit `b04aaea`]**
* **Delivered**: Inverted inspection logic in [`collector/src/porygon_collector/normalizer.py`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/normalizer.py) to check local cache first. Verified with 16 tests in [`collector/tests/test_container_cache.py`](file:///home/anuruprkris/Project/final_yeat_work/collector/tests/test_container_cache.py).

#### Task 4.2: Decouple Synchronous Identity Reconciliation (`[PERF-04]`) — **[COMPLETED in commit `b04aaea`]**
* **Delivered**: Background worker loop in [`backend/src/porygon_api/reconciliation.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/reconciliation.py) decoupling parent and container identity repairs from ingestion requests in [`backend/src/porygon_api/main.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py).

#### Task 4.3: ML Classifier Behavioral Indicators (`[ARCH-01b]`) — **[ACTIVE ROADMAP]**
* **Evidence**: [`backend/src/porygon_api/ml_classifier.py:42-81`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/ml_classifier.py#L42-L81) uses static basename sets vulnerable to path evasion (e.g. copying binaries to `/tmp`).
* **Implementation Blueprint**:
  - Incorporate behavioral signals into feature extraction: execution from writable directories (`/tmp`, `/dev/shm`), unlinked executables (`(deleted)` inode suffix), and argument entropy.
* **Done Criteria**:
  ```bash
  docker compose exec -T backend pytest tests/test_ml_classifier.py
  ```

---

### Phase 5: Production Fleet Topology & Kubernetes Packaging

#### Task 5.1: Helm Chart & Kubernetes DaemonSet Deployment (`[OPS-01]`) — **[ACTIVE ROADMAP]**
* **Implementation Blueprint**:
  1. Author production Helm chart `deploy/helm/porygon`:
     - `porygon-agent` DaemonSet: Runs `falco` with `modern_ebpf` and CRI watcher on every worker node. Uses `hostPID: true`, privileged container security context, and mounts `/run/containerd/containerd.sock`.
     - `porygon-control-plane` Deployment: Replicated FastAPI backend workers behind a Kubernetes ClusterIP Service and Ingress.
     - PostgreSQL StatefulSet with persistent volume claims.
  2. Implement `cert-manager` mutual TLS (`mTLS`) for secure communication between node agents and the control plane.
* **Done Criteria**:
  ```bash
  helm lint deploy/helm/porygon
  helm template deploy/helm/porygon
  ```

---

## 5. Strategic Traps to Avoid ("Not Worth Doing")

Per Senior Advisor principles, engineering effort must not be wasted on attractive but unproductive paths:

1. **Do NOT write a custom Linux kernel module.**
   - *Why*: Commercial agents that relied on proprietary kernel modules caused customer kernel panics across Linux distribution updates. Falco's modern CO-RE (Compile Once – Run Everywhere) eBPF probe is the industry standard adopted by major security vendors.
2. **Do NOT terminate compromised pods immediately.**
   - *Why*: Kubernetes controllers immediately spin up fresh replacement pods, destroying volatile in-memory evidence (injected shared objects, process memory) and reviving the attacker. Dynamic network quarantine (`NetworkPolicy`) is the only forensically sound containment strategy.
3. **Do NOT loosen statistical anomaly thresholds.**
   - *Why*: Lowering the Jensen-Shannon distance threshold to catch more anomalies will flood security teams with false positives. In enterprise SecOps, false-positive noise results in security tools being disabled. High-precision alerts backed by process lineage and CVE correlation provide the highest operational value.
4. **Do NOT replace the Brutalist UI with a heavy React framework.**
   - *Why*: Porygon's high-contrast, zero-border-radius brutalist UI ([`dashboard/assets/app.css`](file:///home/anuruprkris/Project/final_yeat_work/dashboard/assets/app.css)) loads in under 100ms, renders instantly, and is preferred by senior incident responders over bloated, sluggish commercial web dashboards.
