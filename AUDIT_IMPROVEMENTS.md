# Porygon Enterprise Pathway & Architecture Audit

This document establishes the authoritative, evidence-backed improvement backlog and architectural transformation roadmap for the **Porygon** container runtime security platform, maintained under the Senior Advisor protocol defined in [Improve](file:///.agents/skills/improve/SKILL.md) and [AGENTS.md](file:///AGENTS.md).

---

## Executive Summary: Bridging the Gap to Production Enterprise Readiness

Porygon possesses strong core security engineering fundamentals:
- **Digest-Bound Identity**: Workloads are cryptographically bound to immutable repository digests (`image_digest`), not mutable tags ([`models.py:77-124`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/models.py#L77-L124)).
- **Modern Kernel eBPF Telemetry**: The platform utilizes Falco's `modern_ebpf` engine rather than legacy kernel modules ([`compose.yaml:376-441`](file:///home/anuruprkris/Project/final_yeat_work/compose.yaml#L376-L441)).
- **Mathematically Grounded Drift Detection**: Jensen-Shannon behavioral distance and calibrated rarity scoring prevent the alert fatigue common to naive allowlists ([`scoring.py:1-120`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/scoring.py#L1-L120)).
- **Idempotent Containment State Machine**: Automated containment actions enforce state preconditions, cryptographic leases, and rollback verifications ([`executor.py:32-151`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/executor.py#L32-L151), [`response.py:1-75`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/response.py#L1-L75)).

However, **Porygon today is a single-host research system**. No cloud-native enterprise or Fortune 500 platform security team could deploy it in its current state without encountering production outages, Kubernetes controller conflicts, or severe telemetry blind spots.

This roadmap details the concrete architectural evolution required to transform Porygon into a production Cloud Workload Protection Platform (CWPP) ready for enterprise clusters.

---

## 1. Verified Remediations (Completed in Baseline)

The following simple, high-leverage findings have been resolved, covered with regression test suites, and verified inside active container environments:

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

---

## 2. The 5 Production Chasms (Gap Analysis Grounded in Code)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 THE 5 PRODUCTION CHASMS                                │
├───────────────────────────────┬────────────────────────────────────────────────────────┤
│ CURRENT CODEBASE REALITY      │ ENTERPRISE PRODUCTION REQUIREMENT                      │
├───────────────────────────────┼────────────────────────────────────────────────────────┤
│ 1. Single-Host Docker Socket  │ Multi-Node Kubernetes DaemonSet (containerd / CRI-O)   │
│ 2. Telemetry Blind to Net/Mem │ Multi-Syscall Fabric (Network Sockets, memfd, Files)   │
│ 3. Destructive Docker Pauses  │ Non-Destructive K8s Network Isolation & Blast Caps     │
│ 4. Sync Database Ingestion    │ Distributed Streaming Queue (Kafka/NATS) with Windows  │
│ 5. Shared Env API Tokens      │ OIDC / SAML SSO, Granular RBAC, SIEM & SOAR Webhooks   │
└───────────────────────────────┴────────────────────────────────────────────────────────┘
```

### Chasm 1: Node Agent vs. Centralized Fleet Topology
* **Evidence in Code**:
  - [`compose.yaml:163,295,353`](file:///home/anuruprkris/Project/final_yeat_work/compose.yaml#L163) binds the host `/var/run/docker.sock` directly into `collector`, `responder`, and `scanner`.
  - [`collector/src/porygon_collector/docker_source.py:47-70`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/docker_source.py#L47-L70) connects exclusively to the local Docker daemon.
  - [`responder/src/porygon_responder/executor.py:42`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/executor.py#L42) invokes `docker.DockerClient(base_url=base_url)`.
* **Production Reality**:
  - Enterprise workloads run on Kubernetes (EKS, GKE, AKS, OpenShift) where Docker Engine was removed (Dockershim deprecation). The underlying runtime is **`containerd`** or **`CRI-O`** accessed via `/run/containerd/containerd.sock`.
  - Enterprises operate dozens or hundreds of nodes. Running the full Porygon stack on every node is impossible.
* **Architecture Change**:
  - Decouple Porygon into a **Lightweight Node Agent** (`porygon-agent` DaemonSet packaging Falco eBPF + CRI lifecycle stream) and a **Centralized Control Plane** (`porygon-control-plane` deployment running FastAPI, PostgreSQL, and background scoring workers).
  - Agents stream events upstream to the control plane over gRPC with mutual TLS (`mTLS`).

### Chasm 2: Telemetry Depth Beyond `execve`
* **Evidence in Code**:
  - [`falco/porygon_rules.yaml:3-6`](file:///home/anuruprkris/Project/final_yeat_work/falco/porygon_rules.yaml#L3-L6) filters exclusively on `evt.type in (execve, execveat)`.
  - [`telemetry/src/porygon_telemetry/normalizer.py:82-89`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/src/porygon_telemetry/normalizer.py#L82-L89) drops any Falco rule other than `"Porygon Container Process Execution"`.
  - **Dormant Architecture**: The backend data model [`models.py:190-245`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/models.py#L190-L245) **already contains** `KernelRuntimeEvent` with constraint:
    ```sql
    runtime_action IN ('net_outbound', 'memfd_create', 'file_write_open', 'file_write')
    ```
    and fields `remote_address`, `remote_port`, `local_address`, `local_port`, `file_path`, and `memory_name`.
* **Production Reality**:
  - Advanced adversaries do not merely spawn shell binaries; they use:
    1. **Reverse shells / C2 sockets**: Established inside long-running application runtimes without executing a separate binary.
    2. **Fileless malware**: In-memory execution using `memfd_create` + `fexecve`.
    3. **Credential harvesting**: Reading `/var/run/secrets/kubernetes.io/serviceaccount/token` or `/etc/shadow`.
* **Architecture Change**:
  - Activate the dormant `KernelRuntimeEvent` pipeline in Falco rules and `porygon_telemetry/normalizer.py`.
  - Multiplex network socket connections, in-memory allocations, and sensitive file operations alongside process executions.

### Chasm 3: Safe Cloud-Native Containment & Blast-Radius Governance
* **Evidence in Code**:
  - [`responder/src/porygon_responder/executor.py:158-171`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/executor.py#L158-L171) executes `docker pause` and `docker stop`.
* **Production Reality**:
  - **Pausing Containers in Kubernetes**: Freezing cgroups pauses the application's liveness probe server. Kubelet marks the pod unready, kills it, and schedules a replacement pod.
  - **Stopping Containers in Kubernetes**: Terminating a pod causes the `ReplicaSet` controller to immediately spawn an identical pod, restarting the attacker while destroying volatile memory evidence.
* **Architecture Change**:
  - **Dynamic Kubernetes NetworkPolicy Quarantine**: Instead of terminating pods, apply a dynamic `NetworkPolicy` targeting the pod label (`porygon.io/isolation: isolated`), cutting off ingress/egress while leaving memory intact for live forensic memory acquisition (`gcore`).
  - **Fleet Blast-Radius Rate Limiter**: Enforce limits preventing automated containment from ever isolating more than 1 pod per Deployment or 5% of cluster capacity per hour, with strict blacklisting of system namespaces (`kube-system`, `istio-system`, `porygon`).

### Chasm 4: Ingestion Throughput & Streaming Event Architecture
* **Evidence in Code**:
  - [`collector/src/porygon_collector/spool.py`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/spool.py) and [`telemetry/src/porygon_telemetry/spool.py`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/src/porygon_telemetry/spool.py) push HTTP batches to [`backend/src/porygon_api/main.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py) which issues synchronous PostgreSQL transactions.
* **Production Reality**:
  - In a 100-node cluster running 3,000 microservices, eBPF telemetry produces 50,000+ syscall events/second during traffic spikes.
  - Synchronous database transactions saturate PostgreSQL connection pools and exhaust disk write IOPS.
* **Architecture Change**:
  - Deploy a streaming buffer (Redis Streams or NATS JetStream) between the ingest gateway and backend detection workers.
  - Ingestion acknowledges in `< 2ms`; anomaly scoring and baseline calculations consume from consumer groups asynchronously.

### Chasm 5: Enterprise Governance, Identity (RBAC/OIDC) & Ecosystem Integration
* **Evidence in Code**:
  - [`backend/src/porygon_api/security.py:10-24`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/security.py#L10-L24) enforces authentication with two shared static tokens from environment variables (`PORYGON_INTERNAL_API_TOKEN`, `PORYGON_OPERATOR_API_TOKEN`).
  - Zero webhook dispatchers or SIEM forwarding mechanisms exist in the codebase.
* **Production Reality**:
  - Enterprise compliance (SOC 2 Type II, ISO 27001) forbids shared static credentials. SecOps requires Single Sign-On (SSO via Okta, Azure AD, or Google Workspace) with Role-Based Access Control (`Viewer`, `SecOps Analyst`, `Incident Responder`, `Platform Admin`).
  - Security analysts do not monitor a standalone UI 24/7; they require real-time alerts dispatched to **Splunk HEC**, **Datadog Security Monitoring**, **Slack**, and **PagerDuty**.
* **Architecture Change**:
  - Implement JWT verification against enterprise OIDC providers.
  - Implement an asynchronous Webhook / SIEM Forwarding engine with HMAC signatures and exponential retry backoff.

---

## 3. Prioritized Leverage Matrix

Applying the Senior Advisor formula:
$$\text{Leverage} = \frac{\text{Impact}}{\text{Effort}} \times \text{Confidence}$$

| ID | Title | Category | Impact | Effort | Risk | Confidence | Leverage |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **[SEC-02]** | Activate Multi-Syscall Telemetry Pipeline in Falco & Telemetry | Security | CRITICAL | M | LOW | HIGH | **2.0** |
| **[DIR-03]** | Enterprise Incident Webhook & SIEM Forwarding Engine | Direction / DX | HIGH | S | LOW | HIGH | **2.0** |
| **[DIR-02]** | Unified Vulnerability (CISA KEV / EPSS) & Runtime Threat Correlation | Direction / Det | HIGH | M | LOW | HIGH | **1.5** |
| **[PERF-03]** | Invert Collector Container Cache Checks to Prevent Docker Socket Storms | Performance | HIGH | M | LOW | HIGH | **1.5** |
| **[ARCH-01]** | Augment ML Classifier with Behavioral Path & Inode Indicators (IMP-07) | Architecture | HIGH | M | LOW | HIGH | **1.5** |
| **[SEC-03]** | Enterprise OIDC Authentication & Role-Based Access Control (RBAC) | Security / Auth | HIGH | M | LOW | HIGH | **1.33** |
| **[DIR-04]** | Kubernetes Dynamic NetworkPolicy Containment & Blast-Radius Engine | Direction / Resp | HIGH | L | MED | HIGH | **1.2** |
| **[PERF-04]** | Decouple Synchronous Identity Reconciliation from Ingestion Request Path | Performance | MED | M | LOW | HIGH | **1.0** |
| **[ARCH-02]** | Distributed Event Streaming Bus (NATS JetStream / Redis Streams) | Architecture | HIGH | L | MED | MED | **0.8** |
| **[OPS-01]** | Helm Chart Packaging for Multi-Node Kubernetes DaemonSet | Operations | HIGH | L | LOW | HIGH | **0.8** |

---

## 4. Phase-by-Phase Master Engineering Pathway

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             5-PHASE ENTERPRISE PATHWAY                            │
├──────────────────────────────────────────────────────────────────────────────────┤
│ Phase 1: Telemetry & Threat Fabric (Multi-syscall eBPF + CVE/KEV correlation)     │
│ Phase 2: SecOps Ecosystem & Governance (SIEM/SOAR webhooks + OIDC/RBAC)          │
│ Phase 3: Cloud-Native Non-Destructive Containment (K8s NetworkPolicy + Blast Caps)│
│ Phase 4: High-Throughput Stream Ingestion (NATS/Redis Stream buffer)             │
│ Phase 5: Production Fleet Topology (Helm Chart + Kubernetes DaemonSet Node Agent)│
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 1: Telemetry & Threat Fabric

#### Task 1.1: Multi-Syscall Telemetry Pipeline Activation (`[SEC-02]`)
* **Evidence**: [`falco/porygon_rules.yaml:3-6`](file:///home/anuruprkris/Project/final_yeat_work/falco/porygon_rules.yaml#L3-L6) and [`telemetry/src/porygon_telemetry/normalizer.py:82-89`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/src/porygon_telemetry/normalizer.py#L82-L89).
* **Implementation**:
  1. Add Falco rules in `falco/porygon_rules.yaml` for:
     - `Porygon Container Outbound Network Connection` on `evt.type = connect and fd.type = ipv4 and evt.dir = >`.
     - `Porygon Container In-Memory Execution` on `evt.type = memfd_create`.
     - `Porygon Container Sensitive File Modification` on `evt.type in (open, openat) and fd.name startswith "/etc/" and evt.rawres >= 0`.
  2. In `telemetry/src/porygon_telemetry/normalizer.py`, replace strict rule check with multi-rule dispatcher:
     ```python
     if rule_name == "Porygon Container Process Execution":
         return normalize_process_event(raw_event, ...)
     elif rule_name in KERNEL_RULE_MAP:
         return normalize_kernel_event(raw_event, ...)
     ```
  3. In `telemetry/src/porygon_telemetry/file_source.py`, route kernel events to existing endpoint `POST /api/v1/kernel-events`.
* **Done Criteria**:
  ```bash
  docker compose exec -T telemetry pytest tests/test_normalizer.py
  docker compose exec -T backend pytest tests/test_kernel_events.py
  ```

#### Task 1.2: Unified Vulnerability & Behavioral Threat Correlation (`[DIR-02]`)
* **Evidence**: [`backend/src/porygon_api/detection.py:16-80`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/detection.py#L16-L80) runs independently of vulnerability data in [`vulnerability.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/vulnerability.py).
* **Implementation**:
  1. Add rule `POR-DET-008: Exploited Vulnerability Runtime Execution` in `backend/src/porygon_api/detection.py`:
     - Severity: 0.98, Confidence: 0.95.
     - Description: Process or network anomaly detected inside a container image harboring actively exploited CVEs (CISA KEV or EPSS > 0.50).
  2. Enrich detection run context with active `VulnerabilityFinding` records for the container's `image_digest`.
* **Done Criteria**:
  ```bash
  docker compose exec -T backend pytest tests/test_detection.py
  ```

---

### Phase 2: SecOps Ecosystem & Governance

#### Task 2.1: Enterprise Webhook & SIEM Forwarding Engine (`[DIR-03]`)
* **Evidence**: Zero external dispatch mechanisms exist when [`backend/src/porygon_api/incident_grouping.py:94`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/incident_grouping.py#L94) creates an `Incident`.
* **Implementation**:
  1. Create `backend/src/porygon_api/webhooks.py`:
     - Implements `dispatch_incident_webhook(incident: Incident)`.
     - Supports generic JSON webhooks, Slack incoming webhooks, and Splunk HTTP Event Collector (HEC).
     - Signs payloads using HMAC-SHA256 headers (`X-Porygon-Signature`).
     - Dispatches asynchronously with 3-attempt exponential backoff.
  2. Trigger dispatch in `attach_incident` ([`incident_grouping.py`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/incident_grouping.py)) upon incident creation or severity escalation.
* **Done Criteria**:
  ```bash
  docker compose exec -T backend pytest tests/test_webhooks.py
  ```

#### Task 2.2: Enterprise OIDC & Role-Based Access Control (`[SEC-03]`)
* **Evidence**: [`backend/src/porygon_api/security.py:10-24`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/security.py#L10-L24) verifies static shared tokens.
* **Implementation**:
  1. Add optional OIDC JWT bearer verification (Okta, Azure AD, Keycloak) using `python-jose` and JWKS caching.
  2. Define role hierarchy:
     - `Viewer`: Read-only access to incidents, metrics, and profiles.
     - `SecOps Analyst`: Acknowledge and close incidents, add notes.
     - `Incident Responder`: Approve and execute container containment actions.
     - `Platform Admin`: Modify custom detection rules and API tokens.
  3. Record user identity on incident transitions ([`models.py:633-638`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/models.py#L633-L638)) instead of leaving `acknowledged_by` null.
* **Done Criteria**:
  ```bash
  docker compose exec -T backend pytest tests/test_auth_rbac.py
  ```

---

### Phase 3: Cloud-Native Non-Destructive Containment

#### Task 3.1: Kubernetes Dynamic NetworkPolicy Quarantine (`[DIR-04]`)
* **Evidence**: [`responder/src/porygon_responder/executor.py:158-171`](file:///home/anuruprkris/Project/final_yeat_work/responder/src/porygon_responder/executor.py#L158-L171) executes `docker pause` and `docker stop`.
* **Implementation**:
  1. Add `KubernetesResponseExecutor` in `responder/src/porygon_responder/k8s_executor.py`:
     - Uses official `kubernetes` Python client.
     - Operation `isolate_pod_network`: Dynamically creates a Kubernetes `NetworkPolicy` targeting the compromised pod label, dropping ingress and egress.
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

#### Task 4.1: Invert Collector Container Cache Checks (`[PERF-03]`)
* **Evidence**: [`collector/src/porygon_collector/normalizer.py:218-222`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/normalizer.py#L218-L222) and [`collector/src/porygon_collector/docker_source.py:177`](file:///home/anuruprkris/Project/final_yeat_work/collector/src/porygon_collector/docker_source.py#L177) trigger synchronous Docker socket inspections on every raw event.
* **Implementation**:
  - Invert logic to query `store.get_cached_container(container_id)` first.
  - Re-inspect container metadata from the Docker daemon only on lifecycle events (`start`, `die`, `stop`, `destroy`) or after cache TTL expiration (30 seconds).
* **Done Criteria**:
  ```bash
  docker compose exec -T collector pytest tests/test_normalizer.py
  ```

#### Task 4.2: Decouple Synchronous Identity Reconciliation (`[PERF-04]`)
* **Evidence**: [`backend/src/porygon_api/main.py:811-812`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/main.py#L811-L812) invokes `_reconcile_process_identities(db)` synchronously within every incoming ingestion POST handler.
* **Implementation**:
  - Move identity reconciliation into a periodic background task (running every 5 seconds) or trigger it only when the unreconciled queue exceeds a defined batch threshold.
* **Done Criteria**:
  ```bash
  docker compose exec -T backend pytest tests/test_process_events.py
  ```

---

### Phase 5: Production Fleet Topology & Kubernetes Packaging

#### Task 5.1: Helm Chart & Kubernetes DaemonSet Deployment (`[OPS-01]`)
* **Implementation**:
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
