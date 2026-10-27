# Porygon

A container runtime security and behavioral anomaly detection system for Docker.

Porygon monitors container execution at the kernel level using modern eBPF (via Falco) and correlates process activity with Docker daemon lifecycle events. It builds per-image behavioral baselines, measures execution drift using Jensen-Shannon distance, enforces deterministic detection rules, and supports automated or human-approved container containment.

---

## Features

- **Kernel-Level Telemetry**: Captures process execution (`execve`/`execveat`) plus separate typed evidence for outbound connections, memory-backed files, and sensitive-path opens and writes using modern eBPF probes.
- **Digest-Bound Baselines**: Profiles expected process behavior bound to cryptographic image digests (`sha256:...`) rather than mutable image tags.
- **Behavioral Anomaly Scoring**: Calculates runtime drift using Jensen-Shannon divergence to identify unexpected processes and abnormal tool usage.
- **ML Threat Classification**: Classifies runtime telemetry into MITRE attack tactics (`shell_escape`, `reconnaissance`, `suspicious_tooling`, `privilege_escalation`, `benign`) using an explainable Random Forest ensemble with TreeSHAP feature attribution.
- **Rule Engine & AI Auditor**: Detects shell escapes, privilege escalation, unknown binaries, and suspicious executions, supplemented by automated incident summaries.
- **Automated / Approved Containment**: Quarantines compromised containers (pause or stop) with configurable human-in-the-loop approval workflows.
- **Vulnerability & SBOM Context**: Scans images with Trivy and enriches findings with EPSS exploit probabilities and CISA KEV exploitation data.
- **Interactive Web Dashboard**: Clean UI for live telemetry streaming, behavioral score visualization, incident review, and response actions.

---

## Services

| Service | Role | Port |
| :--- | :--- | :--- |
| **`backend`** | Core API, scoring engine, detection logic, and incident management | `8000` (via gateway) |
| **`collector`** | Streams Docker daemon lifecycle events (create, start, exec, die) | Internal |
| **`telemetry`** | Normalizes and durably spools separate process and kernel-runtime channels from Falco | Internal |
| **`responder`** | Executes container containment actions (pause / stop) | Internal |
| **`scanner`** | Runs Trivy vulnerability scans and retrieves EPSS/KEV metadata | Internal |
| **`falco`** | Modern eBPF sensor monitoring system calls | Internal |
| **`postgres`** | Stores events, baselines, incidents, and audit trails | `5432` (Internal) |
| **`gateway`** | Nginx reverse proxy routing external API traffic | `8000` |
| **`dashboard`** | Lightweight web server hosting the dashboard UI | `3000` |

---

## Machine Learning Threat Classification

Porygon pairs continuous kernel eBPF observation with a supervised **Random Forest ensemble** and **TreeSHAP additive feature attribution**. Rather than treating machine learning as an opaque scoring mechanism, Porygon classifies runtime process telemetry directly into standardized **MITRE ATT&CK tactics** while mathematically explaining every prediction down to individual feature contributions.

### Multi-Layer Detection Architecture

| Defense Layer | Detection Engine | Target Threat Vector | Evaluation Latency | Output Representation | Explainability Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Statistical Drift** | Jensen-Shannon Divergence | Unseen process churn & baseline deviation | < 0.2 ms | Continuous distance score (`0.00`–`1.00`) | Digest symbol distribution delta |
| **Deterministic Rules** | Falco eBPF Kernel Probes | Known exploits (`setuid`, cgroup escape, shim bypass) | Real-time (< 0.1 ms) | Boolean incident alerts | Syscall argument match & trace |
| **Supervised ML** | Calibrated Random Forest Ensemble | Stealthy multi-stage attack tactics & intent | < 1.5 ms | MITRE tactic probabilities + verdict | Exact TreeSHAP additive feature attributions ($\Delta \mathbf{P}$) |
| **Generative AI** | Local LLM Auditor (Claude/Ollama) | Complex alert correlation & blast-radius analysis | 1.5 s – 3.0 s | Plain-language remediation brief | Chain-of-thought markdown narrative |

### MITRE ATT&CK Tactic Mapping

| MITRE Attack Tactic | Target MITRE ID | Threat Severity | Primary Behavioral Indicators | Associated Binaries & Tooling | Porygon Automated Response |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`benign`** | N/A | `CLEAN` | Strict adherence to baseline digest profile; 0 unseen binaries | Container entrypoint, standard daemons (`nginx`, `node`, `python`) | Continuously monitor & refine baseline |
| **`reconnaissance`** | T1046, T1082 | `MEDIUM` | Host/network discovery, process tree enumeration, interface probing | `nmap`, `ifconfig`, `netstat`, `ping`, `ss`, `ip`, `whoami` | Alert operator & log forensic snapshot |
| **`privilege_escalation`** | T1068, T1548 | `CRITICAL` | Sudo capability abuse, root transition spikes, namespace manipulation | `sudo`, `su`, `pkexec`, `nsenter`, `capsh`, `chroot`, dirty pipe probes | Restrict cgroups & alert operator |
| **`shell_escape`** | T1611, T1059 | `CRITICAL` | Interactive shell spawned directly from runtime shim (`docker exec`) | `/bin/sh`, `/bin/bash`, `dash`, unprofiled shell invocations | Automated containment (pause/stop container) |
| **`suspicious_tooling`** | T1059, T1496 | `HIGH` | Network egress fetchers, compiler invocations, crypto-mining loops | `curl`, `wget`, `socat`, `nc`, `xmrig`, `gcc`, `make` | Revoke network egress & trigger containment lease |

### 12-Dimensional Extracted Feature Vector

The ML classifier ingests 12 normalized telemetry features derived from kernel `execve` events and container baseline digests:

| Feature Name | Value Range | Behavioral Semantic Description | Threat Implication |
| :--- | :--- | :--- | :--- |
| **`shell_ratio`** | `[0.0, 1.0]` | Proportion of executions invoking `/bin/sh`, `/bin/bash`, or `dash` | Interactive shell presence inside non-shell microservice |
| **`recon_ratio`** | `[0.0, 1.0]` | Proportion of executions invoking network or system discovery commands | Attacker reconnaissance and host discovery |
| **`tooling_ratio`** | `[0.0, 1.0]` | Frequency of file-fetch or reverse-shell binaries (`curl`, `wget`, `nc`) | Malicious payload staging and command-and-control ingress |
| **`priv_escalation_ratio`** | `[0.0, 1.0]` | Invocations of privilege elevation utilities (`sudo`, `su`, `nsenter`) | Container breakout and root privilege escalation |
| **`compiler_miner_ratio`** | `[0.0, 1.0]` | Invocations of development compilers or cryptomining software | Resource hijacking and unauthorized compilation |
| **`root_ratio`** | `[0.0, 1.0]` | Proportion of process executions running as `root` (UID 0) | Violation of least-privilege container runtime principles |
| **`parent_shim_ratio`** | `[0.0, 1.0]` | Processes spawned directly under `containerd-shim` / `docker-runc` | External operator `docker exec` injection |
| **`distinct_proc_count`** | `[0, ∞)` | Number of unique binary executables launched during the window | High process diversity indicates interactive intruder activity |
| **`event_count`** | `[0, ∞)` | Total volume of process execution events recorded | Execution churn and volume anomalies |
| **`unseen_executable_ratio`** | `[0.0, 1.0]` | Fraction of executables absent from the cryptographic baseline | Code execution outside pre-approved container images |
| **`suspicious_sequence_ratio`** | `[0.0, 1.0]` | Sequences matching rapid recon-to-exploit chaining patterns | Multi-step automated cyber kill-chain execution |
| **`jensen_shannon_drift`** | `[0.0, 1.0]` | Jensen-Shannon distance against the baseline process distribution | Global behavioral divergence from expected workload profile |

### TreeSHAP Mathematical Explainability

To satisfy strict regulatory and security audit requirements, Porygon rejects black-box classifications. Each prediction is accompanied by exact TreeSHAP local additive feature attributions:

$$\mathbf{f}(x) = \phi_0 + \sum_{i=1}^{12} \phi_i(x)$$

Where $\phi_0$ is the base expected model value and $\phi_i(x)$ represents the exact marginal contribution of feature $i$ pushing the probability toward or away from a given MITRE tactic.

### ML Classifier REST API

| Endpoint | Method | Input Payload | Output Schema | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`/api/v1/ml/classify-container/{container_id}`** | `POST` | Path parameter `container_id` | `MLThreatClassificationOut` | Extracts runtime telemetry and baseline drift for a container and classifies attack tactics. |
| **`/api/v1/ml/classify`** | `POST` | `MLClassifyEventsIn` (event list + baseline) | `MLThreatClassificationOut` | Classifies raw eBPF process events on-the-fly. |
| **`/api/v1/ml/classify-features`** | `POST` | `MLClassifyFeaturesIn` (12 feature values) | `MLThreatClassificationOut` | Evaluates a pre-computed 12-dimensional feature vector. |
| **`/api/v1/ml/model-info`** | `GET` | None | `MLModelInfoOut` | Returns ensemble metadata, classes, feature names, and version. |

---

## Prerequisites

- **OS**: Linux with eBPF support (kernel 5.8+ recommended)
- **Docker Engine**: 24.0+ with Docker Compose v2
- **Python**: 3.11+
- Appropriate permissions to access `/var/run/docker.sock` and load eBPF probes

---

## Quickstart

### 1. Initialize Configuration
Generate local secrets, database credentials, and Docker socket permissions:
```bash
make init
```

### 2. Start Services
Build and start the container stack:
```bash
make up
```

### 3. Launch the Dashboard
Start the dashboard server:
```bash
python3 scripts/serve_dashboard.py
```

Open **`http://localhost:3000`** in your browser. The backend API is available at **`http://localhost:8000`**.

---

## Useful Commands

```bash
make up          # Build and start all services in the background
make down        # Stop all running services
make logs        # Stream aggregated logs across all containers
make ps          # Check service health status
make test        # Run unit tests
make reset       # Stop services and remove volumes (clean database)
```

---

## Configuration

All configuration is controlled via `.env` (created from `.env.example` during `make init`).

Key settings:
- `PORYGON_RESPONSE_EXECUTION_MODE`: Set to `disabled` (safe default, approvals queued) or `live` (for active containment).
- `PORYGON_LOG_LEVEL`: Logging verbosity (`DEBUG`, `INFO`, `WARNING`).
- `PORYGON_OPERATOR_API_TOKEN`: Secret token used for operator actions in the dashboard and API.
- `PORYGON_COMPLETION_MAX_OPERATIONS`: Maximum retained responder operation receipts (default `50000`); only acknowledged receipts are pruned when capacity is reached.
- `PORYGON_AI_MAX_CONCURRENT_AUDITS`: Maximum simultaneous external AI calls per backend process (default `2`). Database connections are released before these calls.
- `PORYGON_RETENTION_SCHEDULER_ENABLED`: Enable periodic raw-event pruning (default `false`).
- `PORYGON_RETENTION_INTERVAL_SECONDS`: Delay between bounded retention batches (default `21600`).
- `PORYGON_RAW_EVENT_RETENTION_DAYS`: Raw-event age cutoff (default `30`).
- `PORYGON_RETENTION_MAX_DELETE_BATCH`: Maximum rows deleted per event table per tick (default `50000`).

### Local images and rare execution

Scans accept explicit `local:sha256:<64-hex-digits>` targets, including undeployed images, and bind requests, workers and exposure evidence to the Docker host. See [local image scanning](docs/local-image-scanning.md).

Scoring can explicitly select `porygon.distance.rare-execution` to retain a rare shell signal against an entirely zero shell baseline. The policy has its own score identity and preserves existing defaults; see [rare execution scoring](docs/rare-execution-scoring.md).

### Command and lineage profiles

Baseline builds can opt into `--feature-schema porygon.behaviour.command-lineage` for fixed-vocabulary command shapes and verified parent-linked sequences. Scoring uses the selected profile's contract, records command coverage, and retains existing profile defaults and historical scores. See [command and lineage scoring](docs/command-lineage-scoring.md) for selection, feature semantics and model compatibility.

### Incident episodes and response recovery

Repeated findings for the same exact container/host scope, image, profile, and detection configuration update one active incident. Every detection run remains stored and linked to the incident; each appended evidence row includes its run ID. Closing an incident ends that episode. Unknown or ambiguous container identities do not group. Recommendations bind to the latest assessed window; generate a fresh recommendation after the evidence changes.

The responder keeps an intent and completion journal in the `porygon_responder_state` named volume, using SQLite WAL with FULL durability. Pending completions are delivered before new Docker actions. Reclaimed operations replay their saved receipt; an interrupted operation with an unknown outcome requires operator review. Keep this volume across restarts and share it between workers using the same executor identity. The journal's exclusive worker lock coordinates processes sharing that filesystem; separate hosts need shared response ownership before scaling execution across them.

Collector events and their replay cursor commit atomically in batches of up to 100 events or approximately 50 ms, retaining FULL durability. Spool capacity applies backpressure without advancing the cursor past uncommitted events. External AI audit evidence is escaped and isolated from system instructions; malformed assessments and invented command citations are rejected. AI suggestions remain advisory.

### Kernel runtime evidence and background identity repair

Outbound connections, memory-backed file creation, and sensitive-path writable opens and actual writes are stored separately from exec scoring. The telemetry tab provides host and activity filters. Durable mixed-channel delivery, replay-safe storage, background identity repair, and verification commands are documented in [Kernel runtime telemetry](docs/kernel-runtime-telemetry.md). Configure the worker with `PORYGON_RECONCILIATION_ENABLED` (default `true`), `PORYGON_RECONCILIATION_INTERVAL_SECONDS` (default `5`), and `PORYGON_RECONCILIATION_BATCH_SIZE` (default `500`).

### Internal administration and verification

The public gateway rejects `/internal` and `/internal/*`. Internal services use the private Docker network. Local administrative commands use authenticated Docker-exec transport for internal routes, so the backend needs no published host port:

```bash
python3 scripts/porygon_baseline.py --help
python3 scripts/porygon_score.py --help
python3 scripts/porygon_detect.py --help
```

Public API reads and explicit remote URLs continue to use HTTP. Acceptance scripts manage their private transport automatically. To reuse images already built locally, set `PORYGON_VERIFY_BUILD=false` when running verification; the default still rebuilds images.

Retention is opt-in because it removes raw evidence older than the configured cutoff. Each scheduled batch uses a short database session and a cross-worker lock. Existing profiles and recorded score documents are retained. See [improvement progress](docs/review/improvement-progress.md) for implemented fixes, regression coverage, and remaining work.

---

## Documentation Index

Explore the complete documentation in [`docs/`](docs/):

- **Hands-On Explainer:**
  - [Interactive Walkthrough & Architecture Guide](EXPLAINER.md)
- **Architecture:**
  - [System Overview](docs/architecture/system-overview.md)
  - [eBPF Kernel Telemetry](docs/architecture/ebpf-telemetry.md)
  - [Kernel Runtime Evidence and Recovery](docs/kernel-runtime-telemetry.md)
  - [Digest-Bound Behavioral Profiling](docs/architecture/behavioral-profiling.md)
  - [Explainable ML Threat Classifier](docs/architecture/ml-threat-classifier.md)
  - [Containment Engine & Safety Leases](docs/architecture/containment-engine.md)
  - [SBOM & Vulnerability Reachability](docs/architecture/sbom-vulnerability.md)
- **Academic Research & Protocol:**
  - [Research Protocol Archive](docs/research/README.md)
  - [Frozen Research Protocol](docs/research/research-protocol.md)
  - [Threat Model](docs/research/threat-model.md)
  - [Claims Boundaries & Falsification](docs/research/claims-boundaries.md)
  - [Profile Scope Experiment](docs/research/profile-scope-experiment.md)
  - [Adversarial Scenarios Stress Tests](docs/research/adversarial-scenarios.md)
  - [Empirical Results (Pilots & Trials)](docs/research/empirical-results.md)
  - [Development Roadmap](docs/research/development-roadmap.md)
- **Defense Presentations:**
  - [Presentation Guide & Slides](docs/presentation/README.md)
  - [Presentation Spoken Script](docs/presentation/presentation-script.md)
- **Reviews:**
  - [Review Package](docs/review/review-package.md)

## Pilot dataset

[Dataset v1.0.0](datasets/porygon-pilot-v1.0.0/readme.md): 216 controlled-container trial metadata records with labels, provenance and offline validation. Raw process events are not included; licensed under CC BY 4.0. [Public Kaggle release](https://www.kaggle.com/datasets/anuruprkrishnan/porygon-controlled-container-pilot-dataset).
