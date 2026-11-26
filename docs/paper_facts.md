# Porygon Results Fact Sheet
**Project Phase II (23CSE498) — Capstone Conference Paper Reference Document**  
**Document Target**: Results and Discussion Section Evidence Base  
**Protocol Status**: `porygon.research.protocol.v1` (`1.0.0-frozen`, 2026-08-20)  
**Evidence Categories**:
- `[CONFIRMATORY]`: Pre-registered, immutable protocol run satisfying all validation gates.
- `[PILOT]`: Exploratory or pilot study evidence (specifically tagged `evidence_class: pilot`, `research_eligible: false` per `docs/research/empirical-results.md:3-14` and `Makefile:65-68`).
- `[VERIFICATION SCRIPT]`: Deterministic pass/fail integration, regression, or unit test check (`scripts/verify_*.sh`).
- `[ML-OFFLINE]`: Offline training, calibration, ablation, and held-out evaluation on the 633-window ML dataset (`windows.csv`, `metrics.json`).

---

## Source Documents & Artifact Inventory
Every number, metric, and finding in this fact sheet is derived directly from the following immutable project files:
1. `Porygon/compose.yaml` (Service definitions, container images, volumes, network topology, environment)
2. `Porygon/backend/Dockerfile`, `collector/Dockerfile`, `telemetry/Dockerfile`, `responder/Dockerfile`, `scanner/Dockerfile`
3. `Porygon/backend/src/porygon_api/models.py` (SQLAlchemy 2.0 schema, 40 table definitions)
4. `Porygon/backend/src/porygon_api/detection.py` (Deterministic rules POR-DET-001 through POR-DET-007)
5. `Porygon/backend/src/porygon_api/main.py` (API routing, 4-stage vulnerability ladder, classifier endpoints)
6. `Porygon/backend/ml_training/runs.csv` (Trial registry, 220 container trials)
7. `Porygon/backend/ml_training/windows.csv` (633 qualified 60-second tumbling windows, 12 process execution features)
8. `Porygon/backend/ml_training/results/metrics.json` (Held-out test split evaluation metrics, bootstrap CIs, ablations)
9. `Porygon/backend/ml_training/results/summary.md` (ML evaluation summary & 12 documented limitations)
10. `Porygon/backend/ml_training/notebooks/classifier_report.ipynb` (Executed report notebook with embedded plots)
11. `Porygon/backend/ml_training/models/trained_ensemble.json` (12-feature model artifact, SHA: `9327513b...`)
12. `Porygon/backend/ml_training/models/trained_ensemble_nobaseline.json` (10-feature fallback artifact, SHA: `c434fb5e...`)
13. `Porygon/scripts/collect_training_data.py` (Canary workload executors, trial harness, split assignment)
14. `Porygon/backend/ml_training/export_windows.py` (Tumbling window extraction & feature extraction logic)
15. `Porygon/backend/tests/test_trained_classifier.py` (14 integration tests, path-delta additivity tolerance)
16. `Porygon/artifacts/results.json` (Study harness results, 11 runs, 432 trials, canary counter totals)
17. `Porygon/artifacts/verification-manifest.json` (Static and live verification manifest)
18. `Porygon/artifacts/experiments/protocol-v1/tables/profile-scope-primary-216.json` (216-trial profile-scope analysis)
19. `Porygon/artifacts/experiments/protocol-v1/tables/profile-scope-primary.json` (144-trial profile-scope analysis)
20. `Porygon/artifacts/experiments/protocol-v1/exploratory/context-delta-finding-216.json` (Exploratory context-delta evaluation)
21. `Porygon/docs/research/research-protocol.md` (Frozen research protocol v1, formal hypothesis specifications)
22. `Porygon/docs/research/empirical-results.md` (Empirical pilot results summary & root-cause analysis)
23. `Porygon/docs/presentation/presentation-script.md` (Recorded presentation claims & slide transcripts)
24. `Porygon/docs/architecture/sbom-vulnerability.md` (SBOM architecture & dynamic reachability joins)
25. `Porygon/scripts/verify_containment_response.sh` (Controlled live containment acceptance test)

---

# PART A — PROJECT-WIDE FINDINGS

### A1. System Architecture, Pinned Components, and Database Schema
- **Evidence Status**: `[VERIFICATION SCRIPT]` (Code inspection & deployment configuration)
- **Services, Base Images, and Pinned Image Digests** (`compose.yaml:9-495`, `Dockerfile`s):
  1. `postgres`: `postgres:17.10-bookworm@sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f` (`compose.yaml:14`)
  2. `backend`: Custom build from `./backend` on `python:3.13.13-slim-bookworm` (`backend/Dockerfile:1`, `compose.yaml:37-38`). Application Version: `0.8.0` (`compose.yaml:58`).
  3. `gateway`: `nginxinc/nginx-unprivileged:1.29.3-alpine-slim@sha256:df9d99123d80117ea348470175f20abe85befd1ed361ea6207eaf49ab5a30ed9` (`compose.yaml:124`). Port binding: `127.0.0.1:8000:8080` (`compose.yaml:130`).
  4. `collector`: Custom build from `./collector` on `python:3.13.13-slim-bookworm` (`collector/Dockerfile:1`, `compose.yaml:164-165`). Service Version: `0.3.0` (`compose.yaml:169`).
  5. `falco-events-init`: `alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412` (`compose.yaml:220`).
  6. `telemetry`: Custom build from `./telemetry` on `python:3.13.13-slim-bookworm` (`telemetry/Dockerfile:1`, `compose.yaml:240-241`). Service Version: `0.3.0` (`compose.yaml:245`).
  7. `responder`: Custom build from `./responder` on `python:3.13.13-slim-bookworm` (`responder/Dockerfile:1`, `compose.yaml:303-304`). Service Version: `0.7.0` (`compose.yaml:309`).
  8. `scanner`: Custom build from `./scanner` on `python:3.13-slim-bookworm` (`scanner/Dockerfile:1`, `compose.yaml:358-359`). Service Version: `0.8.0` (`compose.yaml:365`).
  9. `falco`: `falcosecurity/falco:0.45.1@sha256:69e957f91b3a6beb5c82e2afae33ec3e4479dab2d4421475d288d0cd113cedf6` (`compose.yaml:420`).
- **Software Languages & Runtimes**:
  - Python: 3.13 (container base images), Python 3.14 (host verification environment).
  - Go: Aqua Security Trivy binary (`v0.72.0`) (`scanner/Dockerfile:4,28-32`).
  - C / C++ / eBPF: Linux kernel modern eBPF driver in Falco engine (`compose.yaml:430`).
  - POSIX Shell / Bash: Service entrypoints and verification test runners.
  - JavaScript / HTML / CSS: Alpine.js (`v3.x`) and Tailwind CSS newsprint dashboard (`dashboard/app.js`, `dashboard/index.html`).
- **Data Flow**:
  1. Container process invocation triggers `execve` / `execveat` kernel syscalls.
  2. Falco modern eBPF driver emits JSON records to shared volume file `/var/log/porygon/falco-events.jsonl` (`compose.yaml:447`).
  3. `telemetry` adapter tails the JSONL stream, spools records to local SQLite (`/var/lib/porygon/process-outbox.db`), and batches delivery via HTTP POST to `backend:8000/internal/v1/process-events/batch` (`telemetry/src/porygon_telemetry/main.py:144`, `backend/src/porygon_api/main.py:926`).
  4. `backend` writes events to PostgreSQL `process_exec_events` table and correlates container identity from Docker engine events received via `collector` (`outbox.db` -> `/internal/v1/runtime-events/batch`).
  5. The deterministic detection engine runs rules POR-DET-001..007; **deterministic rules do NOT trigger ML classification**. In the assessment service (`assessment_service.py:511`), anomaly scoring invokes `default_classifier.predict_document` using the hand-authored heuristic specialist, while the trained ML threat classifier (`PorygonThreatClassifier`) executes strictly on request via the ML endpoints (`POST /api/v1/ml/classify`, `POST /api/v1/ml/classify-container/{container_id}`, `POST /api/v1/ml/classify-features`, `GET /api/v1/ml/model-info`).
  6. Incidents and containment recommendations are generated in PostgreSQL; authorized human operators inspect tree-path deltas and approve actions via `gateway` (`backend:8000/operator/v1/`).
  7. `responder` polls approved actions, executes container containment via Docker API, and records state verification audits.
- **Vulnerability Scanner & Intelligence Feeds**:
  - Aqua Security Trivy: Version `0.72.0` (`compose.yaml:361`, `scanner/Dockerfile:4`).
  - FIRST EPSS API: `https://api.first.org/data/v1/epss` (`compose.yaml:367`). Retrieved timestamp in protocol: `2026-10-27` (`experiments/protocols/runtime-evidence-study.json:34-40`).
  - CISA Known Exploited Vulnerabilities (KEV) Catalog: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (`compose.yaml:368`). Retrieved timestamp in protocol: `2026-10-27` (`experiments/protocols/runtime-evidence-study.json:34-40`).
- **Database Schema (40 Tables Defined in `backend/src/porygon_api/models.py`)**:
  - `service_heartbeats` (L27), `runtime_events` (L44), `image_identities` (L79), `container_identities` (L101), `process_exec_events` (L127), `kernel_runtime_events` (L207), `behavior_profiles` (L272), `calibrated_rarity_models` (L326), `calibrated_model_runs` (L368), `calibrated_calibration_blocks` (L393), `calibrated_rarity_scores` (L416), `anomaly_scores` (L463), `detection_allowlists` (L515), `custom_detection_rules` (L548), `custom_detection_rule_revisions` (L615), `custom_detection_rule_receipts` (L630), `custom_detection_rule_audit` (L653), `detection_runs` (L670), `incidents` (L716), `detection_incident_links` (L797), `incident_evidence` (L812), `response_recommendations` (L842), `response_executions` (L891), `response_audit_events` (L953), `image_scans` (L984), `sbom_artifacts` (L1022), `vulnerability_report_artifacts` (L1045), `vulnerability_intel` (L1068), `vulnerability_findings` (L1099), `api_credentials` (L1156), `assessment_targets` (L1181), `managed_profiles` (L1200), `assessment_jobs` (L1215), `assessment_audits` (L1242), `runtime_evidence_bundles` (L1253), `advisory_models` (L1265), `notification_deliveries` (L1275), `sensor_health_samples` (L1296), `model_quality_locks` (L1310), `model_promotion_reviews` (L1319).
  - *Live database row counts*: **NOT AVAILABLE** in committed repository files (querying active database blocked by local sandbox boundary). Read-only SQL query to obtain exact counts across all 40 tables:
    ```sql
    SELECT table_name, 
           (xpath('/row/cnt/text()', xml_count))[1]::text::bigint AS row_count
    FROM (
      SELECT table_name, 
             query_to_xml(format('SELECT count(*) AS cnt FROM %I', table_name), false, true, '') as xml_count
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    ) t
    ORDER BY table_name;
    ```

---

### A2. Telemetry and Ingestion Pipeline
- **Evidence Status**: `[PILOT]` & `[ML-OFFLINE]`
- **Recorded Event Totals from Study Harness Runs** (`artifacts/results.json:2-3`):
  - Total canary actions planned: 2,592.
  - Total canary events captured at Falco: 2,585.
  - Total canary events committed to PostgreSQL database: 2,585.
  - Telemetry loss: Exactly 7 canary events were lost **before Falco capture** (2,585 reached Falco and were committed to PostgreSQL; loss rate: $7 / 2592 = \mathbf{0.2701\%}$).
- **ML Training Telemetry Volumes** (`backend/ml_training/runs.csv:1-221`, `windows.csv:1-634`):
  - Total live container trials executed: 220 trials (`runs.csv`).
  - Distinct container image used: 1 (`porygon-training-workload:latest`).
  - Total tumbling 60s windows extracted: 633 windows (`windows.csv`).
  - Events per 60-second window distribution (recomputed directly from `windows.csv` column `event_count`):
    - Minimum: **3.0** events per window (sparse window cut-off rule in `export_windows.py:134,245`).
    - Median: **44.0** events per window.
    - Mean: **46.2322** events per window.
    - Maximum: **92.0** events per window.
  - Telemetry time span in `runs.csv` (computed as $\min(\text{start\_time})$ to $\max(\text{end\_time})$):
    - Minimum start time: `2026-11-19T18:13:10.472096+00:00` (run 0).
    - Maximum end time: `2026-11-20T20:35:47.072503+00:00` (run 219).
    - Exact time span: **1 day, 2 hours, 22 minutes, 36.6004 seconds** (94,956.6004 seconds / ~26.3768 hours; runs in `runs.csv` are not strictly sorted in chronological order by row index).
- **Ingestion Latency (Event Timestamp to DB Commit)**: **NOT AVAILABLE** (No end-to-end event timestamp delta log is preserved in committed JSON/CSV files).
- **Correlation Status Counts (Resolved / Unresolved / Ambiguous)**: **NOT AVAILABLE** in committed manifests. Read-only SQL query to extract correlation distributions:
  ```sql
  SELECT correlation_status, count(*) AS event_count
  FROM process_exec_events
  GROUP BY correlation_status
  ORDER BY event_count DESC;

  -- Events per container distribution
  WITH container_counts AS (
      SELECT COALESCE(container_id, reported_container_id, container_name) AS cid, count(*) AS cnt
      FROM process_exec_events
      GROUP BY COALESCE(container_id, reported_container_id, container_name)
  )
  SELECT min(cnt) AS min_events,
         percentile_cont(0.5) WITHIN GROUP (ORDER BY cnt) AS median_events,
         round(avg(cnt), 4) AS mean_events,
         max(cnt) AS max_events
  FROM container_counts;
  ```
- **Falco File Permission Deadlock Incident & Recovery**:
  - *Incident Description*: An initial Docker volume permissions mismatch on `/var/log/porygon/falco-events.jsonl` (owned by `root:root` with mode `644`) locked out the Falco process (running under container user with group `10003`), preventing event writes following container recreation. Exactly 100 trials executed with zero events ingested before detection (`summary.md:58`, `classifier_report.ipynb:cell 17`).
  - *Verification Boundary*: Who originally created `falco-events.jsonl` with mode 644 and whether the 100 zero-event trials were strictly consecutive: **NOT VERIFIED** (The specific process/command that originally created `falco-events.jsonl` before `falco-events-init` was introduced is unrecorded in git history; `summary.md:58` records that 100 trials recorded zero events, but per-trial execution logs for the discarded trials were purged).
  - *Remediation Applied*: Updated `compose.yaml:224` (`falco-events-init` service) to execute:
    `chown 0:10003 /var/log/porygon && chmod 775 /var/log/porygon && touch /var/log/porygon/falco-events.jsonl && chown 0:10003 /var/log/porygon/falco-events.jsonl && chmod 664 /var/log/porygon/falco-events.jsonl`
    while preserving `group_add: ["10003"]` in `falco` service (`compose.yaml:490`).
  - *Data Integrity Recovery*: All 100 zero-event trials were systematically purged and re-run with identical ground-truth labels and split assignments, preventing class attrition, survivor bias, or data leakage (`summary.md:58`).

---

### A3. Behavioral Profiling & Jensen-Shannon Drift
- **Evidence Status**: `[PILOT]` & `[ML-OFFLINE]`
- **Baseline Construction Methodology**:
  - In `export_windows.py:101-126`, baseline profiles are constructed by aggregating process execution events strictly from the 15 dedicated `baseline` split trials (`runs.csv:split == "baseline"`).
  - Extracts empirical categorical probability distributions for process names ($P(proc)$) and executable file paths ($P(exe)$).
  - Jensen-Shannon Distance is computed per window as:
    $$JSD(P \parallel Q) = \sqrt{\frac{D_{KL}(P \parallel M) + D_{KL}(Q \parallel M)}{2}}, \quad M = \frac{P + Q}{2}$$
- **Jensen-Shannon Drift Statistics by Tactic Class** (recomputed directly from `windows.csv` column `jensen_shannon_drift`):
  - **benign** (n=135): Min = **0.3003**, Median = **0.5318**, Mean = **0.5014**, Max = **0.6365**.
  - **reconnaissance** (n=118): Min = **0.5069**, Median = **0.5487**, Mean = **0.5510**, Max = **0.6595**.
  - **privilege_escalation** (n=119): Min = **0.5840**, Median = **0.6338**, Mean = **0.6343**, Max = **0.7124**.
  - **shell_escape** (n=143): Min = **0.5982**, Median = **0.6598**, Mean = **0.6713**, Max = **0.7873**.
  - **suspicious_tooling** (n=118): Min = **0.4843**, Median = **0.5504**, Mean = **0.5522**, Max = **0.6204**.
- **Empirical Baseline Scope Pilot Findings** (`artifacts/experiments/protocol-v1/tables/profile-scope-primary-216.json`):
  - In the 216-trial profile-scope study (`study-confirmatory-200-20260906t071234Z`), process-name JSD achieved 100% false positive reduction comparing `ARM-CONTEXT` vs `ARM-GLOBAL` (0/53 vs 53/53 false positives, $p = 2.22 \times 10^{-16}$).
  - Comparing `ARM-CONTEXT` vs `ARM-DIGEST` yielded an exact null result ($p = 1.0$, 0 discordant pairs across 53 trials) because the dropped Linux capability (`NET_RAW`) altered container permissions without altering process binary names.
  - Follow-on exploratory direct context-delta scoring (`artifacts/experiments/protocol-v1/exploratory/context-delta-finding-216.json`) achieved 0/26 false positives on baseline trials and 27/27 correct detections on dropped capability trials.
- **Live Database Baseline Rows**: **NOT AVAILABLE** in committed files. Read-only SQL query:
  ```sql
  SELECT count(*) AS total_behavior_profiles,
         count(DISTINCT image_digest) AS distinct_images_profiled,
         status,
         feature_schema_version
  FROM behavior_profiles
  GROUP BY status, feature_schema_version;
  ```

---

### A4. Detection Engine Rules (POR-DET-001 through POR-DET-007)
- **Evidence Status**: `[VERIFICATION SCRIPT]` (`backend/src/porygon_api/detection.py:18-82`)
- **Deterministic Rules Specification**:

| Rule ID | Rule Name | Category | Severity Weight | Confidence Weight | Incident Eligible | Description / Trigger Condition |
|---|---|---|:---:|:---:|:---:|---|
| **POR-DET-001** | High Behavioral Distance | anomaly | 0.65 | 0.70 | False | Window Jensen-Shannon drift score $\ge 0.50$ relative to container trained baseline profile. |
| **POR-DET-002** | Previously Unseen Shell Execution | execution | 0.72 | 0.90 | True | A shell executable (`sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `fish`) not present in digest baseline executed. |
| **POR-DET-003** | Novel Root Process | privilege | 0.78 | 0.90 | True | A UID 0 process executed although UID 0 was absent from baseline profile. |
| **POR-DET-004** | Previously Unseen Non-Shell Executable | execution | 0.64 | 0.80 | True | A non-shell executable absent from digest baseline executed, regardless of process name. |
| **POR-DET-005** | Shell-to-Tool Sequence | correlation | 0.90 | 0.95 | True | Unseen shell followed by unseen non-shell executable in same container within correlation window. |
| **POR-DET-006** | Docker Exec Activity | container-control | 0.35 | 0.95 | False | Docker exec activity occurred during observation window. |
| **POR-DET-007** | Privileged Container Configuration | container-configuration | 0.92 | 0.95 | True | Container lifecycle event reported privileged mode during observation window. |

- **Empirical Triggers & False Positive Rates**:
  - In `scripts/verify_detection_engine.sh:141` and `scripts/verify_containment_response.sh:195`, controlled execution of novel shell and encoding binaries verified deterministic firing of POR-DET-002, POR-DET-004, and POR-DET-005.
  - Number of events triggering each rule across live fleet: **NOT AVAILABLE** as a static summary file. Read-only SQL query:
    ```sql
    SELECT rule_id, count(*) AS trigger_count
    FROM custom_detection_rule_receipts
    GROUP BY rule_id
    ORDER BY trigger_count DESC;

    SELECT evidence_type, count(*) AS hit_count
    FROM incident_evidence
    GROUP BY evidence_type
    ORDER BY hit_count DESC;
    ```
  - Detection Latency: **NOT AVAILABLE** (No latency timer file recorded).

---

### A5. Vulnerability Reachability Funnel
- **Evidence Status**: `[VERIFICATION SCRIPT]` & `[PILOT]`
- **The 4-Stage Evidence Ladder** (`backend/src/porygon_api/main.py:4040-4050`):
  1. `package_present`: Package exists in container filesystem / SBOM artifact.
  2. `deployed`: Container instantiated and running from the image.
  3. `runtime_observed`: Binary / library execution confirmed via Falco eBPF telemetry join on `executable` file path.
  4. `runtime_observed_and_port_published`: Binary executed in a container with exposed host network ports.
  - *Claim Boundary* (`main.py:4047-4049`): *"No stage proves exploitation. EPSS, CISA KEV, process observation, and published ports are independent prioritization or exposure signals."*
- **Discrepancy Explanation (453 vs 136 Findings)**:
  - **453 Total Findings** (Slide 21 / `presentation-script.md:451`): Full static vulnerability scan of the `postgres:17.10-bookworm` container image (150 components, 182 distinct CVEs, 421 with live EPSS, 0 KEV-listed).
  - **136 Findings at Stage 1** (Slide 22 / `presentation-script.md:462`): Evaluated subset from a specific deployed workload container instance.
  - Primary static scan JSON artifacts for these scans: **NOT AVAILABLE** (No standalone raw Trivy JSON report files are committed in `artifacts/`; counts are cited directly from the documented presentation script).
- **Stage Counts across the Ladder**:
  - Stage 1 (`package_present`): **136 findings** (deployed workload instance) / **453 findings** (full Postgres image).
  - Stage 2 (`deployed`): **NOT AVAILABLE** in committed logs.
  - Stage 3 (`runtime_observed`): **4 findings** reached heuristic runtime observation.
  - Stage 4 (`runtime_observed_and_port_published`): **NOT AVAILABLE** in committed logs.
  - Funnel Reduction from Stage 1 to Stage 3: $(136 - 4) / 136 = \mathbf{97.0588\%}$ **alert noise reduction**.
  - Aggregate Fleet-Wide Reduction Rate: **NOT AVAILABLE** (Stated verbatim in `presentation-script.md:464-465`: *"No aggregate noise-reduction rate has been measured"*).
  - Scanner runtime: **NOT AVAILABLE** in committed logs.
- **Join Logic Specification (`backend/src/porygon_api/vulnerability.py:188-250`)**:
  - `runtime_observed` joins on **BOTH executable path and process name**.
  - In `_observed_executables` (`vulnerability.py:188-197`), values are collected from both `executable` (full path and basename) and `process_name`.
  - In `assess_exposure` (`vulnerability.py:213-245`), `package_tokens` (package name, name without `lib`, and basename of `package_path`) are intersected with `_observed_executables(relevant)`:
    $$\text{matched} = \text{bool}(\_observed\_executables(\text{relevant}) \cap \text{package\_tokens})$$
  - In `presentation-script.md:463`, this heuristic match is explicitly described as *"a process-name match against kernel telemetry — not proof of reachability or exploitation."*

---

### A6. Containment and Automated Response Engine
- **Evidence Status**: `[VERIFICATION SCRIPT]` (`scripts/verify_containment_response.sh`, `compose.yaml`)
- **Runtime Execution Policy**:
  - `PORYGON_RESPONSE_EXECUTION_MODE`: Default is **`disabled`** (`compose.yaml:78`).
  - **Explicit Confirmation**: Live automated containment execution was **never enabled during research data collection** (`research-protocol.md:38-39` explicitly states: *"automated disruptive response are prohibited"*).
- **Verified Response Controls** (`scripts/verify_containment_response.sh:61-350`):
  - Supported Action Set: `observe_only`, `pause_container`, `stop_container` (`L71`).
  - Credential Separation: Automated internal token (`X-Porygon-Internal-Token`) rejected by operator containment endpoints with HTTP 401 (`L75-81`). Operator endpoints strictly require `X-Porygon-Operator-Token`.
  - Operator Approval Gate: Containment recommendations remain in `status: proposed` until explicitly approved via POST `/operator/v1/response-recommendations/{id}/approve` with `acknowledge_disruption: true` (`L212,231`).
  - Pre- and Post-State Verification:
    - Pre-state: `paused: false` (`L271`).
    - Post-state: `paused: true`, verified via immediate Docker inspect (`L272-275`).
  - Idempotency: Repeated identical approval requests return the existing execution ID without creating duplicate containment actions (`L278-290`).
  - Safe Rollback: Rollback action POST `/operator/v1/response-executions/{id}/rollback` unpauses container and verifies `paused: false`, `running: true` (`L292-326`).
  - Chronological Audit Trail: Complete sequence verified: `recommendation_created` $\rightarrow$ `recommendation_approved` $\rightarrow$ `execute_claimed` $\rightarrow$ `execute_succeeded` $\rightarrow$ `rollback_requested` $\rightarrow$ `rollback_claimed` $\rightarrow$ `rollback_succeeded` (`L334-350`).
- **Timing Benchmarks**: Specific sub-second execution latency numbers are **NOT AVAILABLE** in static test outputs.

---

### A7. Experiment Harness Runs & Protocol Evaluation
- **Evidence Status**: `[PILOT]`
- **Study Manifest Inventory** (`artifacts/results.json:4-100`):
  - Total runs: 11 runs (432 trials).
  - Protocol file: `experiments/protocols/runtime-evidence-study.json` (`status: "design-pending"`).
  - Run breakdown:
    1. `pilot-20260905t130823Z`: 1 trial, `research_eligible: false`.
    2. `pilot-20260905t130905Z`: 8 trials, `research_eligible: false`.
    3. `pilot-20260905t131705Z`: 6 trials, `research_eligible: false`.
    4. `pilot-20260905t131834Z`: 4 trials, `research_eligible: false`.
    5. `pilot-20260905t181541Z`: 1 trial, `research_eligible: false`.
    6. `study-20260905t174138Z`: 18 trials, `research_eligible: false`.
    7. `study-20260905t175035Z`: 18 trials, `research_eligible: false`.
    8. `study-20260905t181654Z`: 144 trials, `research_eligible: false` (Round 1 Study).
    9. `study-confirmatory-200-20260906t071234Z`: 216 trials, `research_eligible: false` (Round 2 Study; retains original `confirmatory` name for provenance, but carries `evidence_class: pilot`).
    10. `tagdrift-20260905t192840Z`: 4 trials.
    11. `tagdrift-20260905t193051Z`: 12 trials.
- **Formal Protocol Hypotheses & Evaluated Outcomes** (`docs/research/research-protocol.md:452-589`, `empirical-results.md:26-63`):

| Hypothesis ID | Question ID | Protocol Formal Definition / Acceptance Criteria | Evaluated Outcome in Study Data | Empirical Status |
|---|---|---|---|---|
| **$H_1\_001$** | RQ-001 | `ARM-CONTEXT` achieves $\ge 25\%$ relative FPR reduction vs baselines, Holm-adjusted $p < 0.05$, and non-inferior recall (margin -5%). | Supported vs `ARM-GLOBAL` ($p = 2.22 \times 10^{-16}$, 100% relative FPR reduction). **NULL result vs `ARM-DIGEST`** ($p = 1.0$, 0 discordant pairs across 53 trials). | **Partially Supported (Null on Headline Thesis)** |
| **$H_1\_002$** | RQ-002 | Run-level calibration retains nominal 92%–98% coverage and exposes version/context drift without silent degradation. | Mutable tag drift experiment (`nginx:1.26.3` vs `1.28.0`) produced process-name JSD = 0.0 (same binary behavior). | **Null on Process-Name Signal** |
| **$H_1\_003$** | RQ-003 | Sensor overhead $\le 1.0$ CPU-s/min, peak RSS $\le 1.5$ GiB, disk $\le 100$ MiB/hr, application p95 latency delta $\le 5\%$. | Formal confirmatory overhead measurement not executed. | **NOT AVAILABLE** |

---

### A8. System Overhead and Resource Consumption
- **Evidence Status**: `[VERIFICATION SCRIPT]` (Protocol specifications vs observed metrics)
- **Protocol Budgets** (`docs/research/research-protocol.md:237-241`):
  - CPU: $\le 1.0$ CPU-second per workload-minute at steady load.
  - Memory: Aggregate peak RSS $\le 1.5$ GiB across Porygon services.
  - Disk Writes: $\le 100$ MiB per workload-hour (excluding raw debug dumps).
  - Application Latency Impact: Median p95 latency delta $\le 5\%$, upper confidence bound $\le 10\%$.
- **Empirical Measured Numbers**:
  - Telemetry Event Drop Rate: **0.2701%** (7 / 2,592 events dropped between container execution and PostgreSQL commit in `artifacts/results.json:3`).
  - CPU, RAM RSS, and Disk Write measurements under load: **NOT AVAILABLE** (No dedicated resource profiling benchmarks were recorded into static repository tables).

---

### A9. Verification and Test Suite Coverage
- **Evidence Status**: `[VERIFICATION SCRIPT]`
- **Recorded Static Verification Run** (`artifacts/verification-manifest.json:75-103`):
  - Timestamp: `2026-10-27T13:48:14Z`
  - Git Commit: `b04aaea` (git_dirty: true)
  - Result: **PASSED** (Gate: `make verify-static`, Duration: 88 seconds)
  - Tool versions: Docker `29.9.2`, Compose `5.6.1`, Python `3.14.8`, Ruff `0.17.2`.
  - **Temporal & Architectural Scope Note**: This static verification manifest strictly dates from **2026-10-27**, prior to the design, training, calibration, and integration of the ML Threat Classifier (`backend/ml_training/`, completed in November 2026). It verifies the platform before the ML pipeline was added.
- **Active Unit & Integration Test Counts Across All Modules**:
  - Total Test Files: **103 files**
  - Total Automated Test Cases: **697 test cases**
  - Breakdown by Module:
    1. `backend/tests/`: 59 files, **362 tests** (Includes `test_trained_classifier.py` [14 tests] and `test_ml_classifier.py` [14 tests]).
    2. `experiments/tests/`: 23 files, **247 tests** (Conformance, sample size, study design, analysis replay).
    3. `telemetry/tests/`: 7 files, **29 tests** (Falco line parser, dead letter queue, spooling).
    4. `collector/tests/`: 5 files, **18 tests** (Docker socket reconciler, container inventory cache).
    5. `responder/tests/`: 3 files, **15 tests** (Containment state machine, approval tokens).
    6. `scripts/tests/`: 4 files, **14 tests** (Verification API, credential rotation).
    7. `scanner/tests/`: 2 files, **12 tests** (Trivy JSON parser, EPSS/KEV joins).
- **Core Verification Scripts (`scripts/verify_*.sh`)**:
  - `verify_infrastructure.sh`: Health endpoints of postgres, backend, collector, telemetry, gateway.
  - `verify_ebpf_telemetry.sh`: Falco eBPF syscall capture into `/var/log/porygon/falco-events.jsonl`.
  - `verify_event_ingestion.sh`: Telemetry adapter outbox delivery into PostgreSQL `process_exec_events`.
  - `verify_behavior_profiling.sh`: Profile construction and categorical probability computation.
  - `verify_anomaly_scoring.sh`: Jensen-Shannon distance calculation against baseline.
  - `verify_detection_engine.sh`: Deterministic rule matching (POR-DET-001..007) and incident generation.
  - `verify_containment_response.sh`: Controlled live container pause, idempotency, and rollback.
  - `verify_vulnerability_scanner.sh`: Trivy SBOM generation and dynamic reachability join.
  - `verify_real_container.sh`: End-to-end telemetry reconciliation for disposable test container.
  - `verify_all.sh`: Aggregation runner across all non-disruptive verification gates.

---

### A10. Host and Container Runtime Environments & Machine Provenance
- **Evidence Status**: `[VERIFICATION SCRIPT]`
- **Machine Provenance & Hardware Architecture**:
  1. **Primary Study Harness & Verification Testbed**:
     - Data Produced: Study harness runs (`artifacts/results.json`, 11 runs, 432 trials), profile scope analysis (`profile-scope-primary-216.json`), and static verification manifest (`verification-manifest.json`).
     - Host OS Platform: `Linux-7.1.8-1-cachyos-x86_64-with-glibc2.44` (`results.json:9`, `verification-manifest.json:98`).
     - Docker Engine: `29.7.2` (study runs) / `29.9.2` (verification manifest).
     - Docker Compose: `5.6.1`.
     - Python: `3.14.8`.
     - Underlying Physical Hardware: **NOT AVAILABLE** in recorded experiment logs.
  2. **Local Workstation / ML Training & Inference Environment**:
     - Data Produced: Live container canary execution (`runs.csv`, 220 trials), tumbling window dataset (`windows.csv`, 633 windows), model training, temperature calibration, TreeSHAP parity testing (`metrics.json`), report notebook (`classifier_report.ipynb`), and live Docker stack execution.
     - Host OS Platform: Windows 11 (`Windows-11-10.0.26300-SP0`) running WSL2 and Docker Desktop.
     - Processor / CPU: Intel64 Family 6 Model 186 Stepping 2, GenuineIntel, **16 logical processors** (`multiprocessing.cpu_count() = 16`).
     - Physical Memory / RAM: **15.64 GB** total physical RAM (`GlobalMemoryStatusEx.ullTotalPhys = 16,793,767,936 bytes`).
     - Host Python: `3.14.4`.
- **Container Operating System & Base Images**:
  - Debian 12 (Bookworm): Python `3.13.13-slim-bookworm` (backend, collector, telemetry, responder) and `postgres:17.10-bookworm`.
  - Alpine Linux: `alpine:3.22.2` (falco-events-init, workload base) and `nginx:1.29.3-alpine-slim` (gateway).
  - Falco Runtime: Alpine-based `falcosecurity/falco:0.45.1` with modern eBPF driver.

---

# PART B — ML THREAT CLASSIFIER (Madhav's Section)

### B1. Telemetry Dataset & Tumbling Window Partitioning
- **Evidence Status**: `[ML-OFFLINE]`
- **Container Trials Breakdown** (`backend/ml_training/runs.csv:1-221`):
  - Total container trials executed: **220 trials**.
  - Total container image: **1** (`porygon-training-workload:latest` based on `alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf`).
  - Total baseline construction trials: **15 trials** (`split == "baseline"`, all benign).
  - Total non-baseline evaluated trials: **205 trials**.
  - Trials by ground-truth label:
    - `benign`: 60 trials (15 baseline, 18 fit, 14 calibration, 13 test).
    - `reconnaissance`: 40 trials (16 fit, 12 calibration, 12 test).
    - `privilege_escalation`: 40 trials (16 fit, 12 calibration, 12 test).
    - `shell_escape`: 40 trials (16 fit, 12 calibration, 12 test).
    - `suspicious_tooling`: 40 trials (16 fit, 12 calibration, 12 test).
  - Trials by split: `fit` = **82**, `calibration` = **62**, `test` = **61**, `baseline` = **15**.
- **Window Slicing & Extraction Rules** (`export_windows.py:133-134,228-245`):
  - Window Duration: **60-second tumbling windows**.
  - Warmup Window Drop: The first 60-second window of every trial is dropped (startup/warmup noise). Exactly **205 warmup windows dropped** across the 205 evaluated trials.
  - Minimum Events Rule: Windows with fewer than 3 process execution events are discarded as sparse.
  - Windows per trial: Minimum = **2**, Mean = **3.0878**, Max = **4** windows.
- **Qualified Windows Breakdown** (`backend/ml_training/windows.csv:1-634`):
  - Total qualified windows: **633 windows**.
  - Windows by split: `fit` = **255**, `calibration` = **192**, `test` = **186**.
  - Windows by class:
    - `benign`: 135 windows (54 fit, 42 calibration, 39 test).
    - `reconnaissance`: 118 windows (47 fit, 36 calibration, 35 test).
    - `privilege_escalation`: 119 windows (48 fit, 35 calibration, 36 test).
    - `shell_escape`: 143 windows (59 fit, 43 calibration, 41 test).
    - `suspicious_tooling`: 118 windows (47 fit, 36 calibration, 35 test).
- **Independent Trials in Test Split**: Exactly **61 independent container trials** (13 benign, 12 reconnaissance, 12 privilege escalation, 12 shell escape, 12 suspicious tooling).
- **Per-Class Means for All 12 Process Execution Features** (`windows.csv`, `classifier_report.ipynb:cell 6`):

| Feature Name | benign (n=135) | reconnaissance (n=118) | privilege_escalation (n=119) | shell_escape (n=143) | suspicious_tooling (n=118) |
|---|:---:|:---:|:---:|:---:|:---:|
| `shell_ratio` | 0.0000 | 0.0000 | 0.0447 | 0.3017 | 0.0000 |
| `root_ratio` | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| `recon_ratio` | 0.2750 | 0.4704 | 0.1985 | 0.3849 | 0.0649 |
| `tooling_ratio` | 0.0992 | 0.0000 | 0.0000 | 0.0000 | 0.3311 |
| `priv_escalation_ratio` | 0.0000 | 0.0000 | 0.2691 | 0.0000 | 0.0000 |
| `compiler_miner_ratio` | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0701 |
| `distinct_proc_count` | 4.4667 | 4.5000 | 5.7731 | 5.4266 | 6.5847 |
| `event_count` | 39.5259 | 41.2119 | 46.4958 | 60.1399 | 41.8051 |
| `unseen_executable_ratio` | 0.0000 | 0.1050 | 0.4923 | 0.1925 | 0.2724 |
| `parent_shim_ratio` | 1.0000 | 1.0000 | 1.0000 | 0.7917 | 1.0000 |
| `suspicious_sequence_ratio` | 0.0000 | 0.0000 | 0.0000 | 0.1111 | 0.0000 |
| `jensen_shannon_drift` | 0.5014 | 0.5510 | 0.6343 | 0.6713 | 0.5522 |

- **Deterministic Split Assignment**: Computed in `collect_training_data.py:36-39` using `hashlib.sha256(run_id.encode("utf-8")) % len(splits)`.
- **Exact Command Invocations per Workload Scenario** (`scripts/collect_training_data.py:140-323`):
  - *Benign Web API*: `curl -s http://127.0.0.1:8000/healthz`, `/api/v1/status`, `/metrics`, `wget -q -O- http://127.0.0.1:8000/ready`, `curl -s -I`, `uptime`, `date`, `df -h`.
  - *Benign Sysadmin*: `uname -a`, `id`, `whoami`, `hostname`, `uptime`, `df -h`, `free -m`, `ps aux`, `cat /etc/os-release`, `cat /proc/version`, `cat /etc/hosts`, `cat /etc/resolv.conf`, `head -n 10 /etc/passwd`, `cat /proc/meminfo`, `cat /proc/loadavg`.
  - *Benign Batch Worker*: `du -sh /tmp`, `find /var -maxdepth 2`, `sha256sum /etc/os-release`, `sha256sum /etc/hosts`, `md5sum /etc/resolv.conf`, `head -n 20 /etc/services`, `tar -cf /tmp/backup.tar /etc/resolv.conf`, `gzip -f /tmp/backup.tar`, `rm -f /tmp/backup.tar.gz`, `date "+%Y-%m-%d %H:%M:%S"`, `uptime`.
  - *Reconnaissance*: `whoami`, `uname -a`, `id`, `hostname`, `ps aux`, `netstat -tlpn`, `ip addr`, `cat /proc/cpuinfo`, `cat /etc/passwd`, `find /etc -maxdepth 2`.
  - *Privilege Escalation*: `sudo -l`, `sudo -V`, `su -c id`, `nsenter --help`, `capsh --print`, `chmod +s /tmp`, `cat /etc/shadow`, `find /usr/bin -perm -4000`.
  - *Suspicious Tooling*: `curl -s http://127.0.0.1:9999/stage2`, `wget -q -O- http://127.0.0.1:9999/miner`, `nc -zv 127.0.0.1 4444`, `gcc --version`, `wget --help`, `curl --version`.
  - *Shell Escape*: `/bin/sh -c "echo 'interactive shell session'; id; whoami"`, `/bin/bash -c "sh -c 'uname -a; cat /proc/1/cgroup'"`, `/bin/sh -c "cat /proc/self/status | head -n 10"`, `/bin/bash -c "echo 'subshell probe'; ps aux"`, `/bin/sh -c "cd /tmp && pwd"`.

---

### B2. Model Architectures & Calibration Specifications
- **Evidence Status**: `[ML-OFFLINE]`
1. **Hand-Authored Specialist Ensemble (Default Baseline)**:
   - Implementation: `porygon_api.ml_classifier.default_classifier` (`PorygonThreatClassifier()`).
   - Kind: `heuristic`, Status: `hand_authored`, Calibration: `unvalidated`, Temperature: $T = 0.35$.
   - Contract: 5 heuristic tree estimators matching individual threat signatures.
2. **Trained 12-Feature Tree Ensemble (Primary Baseline Model)**:
   - Hyperparameters: `n_estimators = 5`, `max_depth = 4`, `random_state = 42`, criterion = `gini`.
   - Trained on: 255 `fit` windows.
   - Temperature Calibration: Post-hoc scalar temperature $T^* = \mathbf{0.4412}$ fitted via negative log-likelihood minimization on 192 `calibration` windows.
   - Canonical Artifact SHA-256 Digest: `9327513b1c3bfb6be3ed0e9916eb37aa69888961720e49373352fdea7ba7e548`.
   - File Path: `backend/ml_training/models/trained_ensemble.json`.
3. **Trained 10-Feature Tree Ensemble (No-Baseline Fallback Model)**:
   - Features Used (10): Excludes `unseen_executable_ratio` and `jensen_shannon_drift`.
   - Hyperparameters: `n_estimators = 5`, `max_depth = 4`, `random_state = 42`.
   - Temperature Calibration: Fitted temperature $T^* = \mathbf{0.4996}$ on 192 calibration windows.
   - Canonical Artifact SHA-256 Digest: `c434fb5ef16bbc04a58d0e805f6398a46fb7d17fd667071df51a86ab853689de`.
   - File Path: `backend/ml_training/models/trained_ensemble_nobaseline.json`.
4. **Reference Baselines (Tuned on `fit` Split via 5-Fold `GroupKFold` by `run_id`)**:
   - **LightGBM**: Tuned learning rate = 0.1 (`fit_cv_macro_f1 = 1.0000`), `max_depth = 3`, `n_estimators = 50`.
   - **Logistic Regression**: Tuned regularization $C = 1.0$ (`fit_cv_macro_f1 = 0.9943`), `max_iter = 1000`, `solver = 'lbfgs'`.

---

### B3. Held-Out Test Split Performance
- **Evidence Status**: `[ML-OFFLINE]` (`backend/ml_training/results/metrics.json:165-512`)
- **Single Evaluation Protocol**: The test split (186 windows across 61 trials) was evaluated **once and only once** after all model structures, depths, and calibration temperatures were finalized (`metrics.json:2-6`).
- **Comparative Performance on Test Split (186 Windows, 61 Trials)**:

| Model | Macro-F1 | Benign FPR | Benign F1 (P / R) | Recon F1 (P / R) | PrivEsc F1 (P / R) | ShellEscape F1 (P / R) | Tooling F1 (P / R) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Trained Tree Ensemble (Calibrated $T^*$)** | **0.9664** | **0.00%** (0/39) | 0.9630 (0.9286 / 1.0000) | 0.9296 (0.9167 / 0.9429) | 1.0000 (1.0000 / 1.0000) | 1.0000 (1.0000 / 1.0000) | 0.9394 (1.0000 / 0.8857) |
| **Hand-Authored Specialist (Default)** | 0.4159 | 76.92% (30/39) | 0.3750 (1.0000 / 0.2308) | 0.4192 (0.2652 / 1.0000) | 0.3636 (1.0000 / 0.2222) | 0.0930 (1.0000 / 0.0488) | 0.8286 (0.8286 / 0.8286) |
| **LightGBM (Reference, lr=0.1)** | 0.9838 | 0.00% (0/39) | 0.9630 (0.9286 / 1.0000) | 0.9706 (1.0000 / 0.9429) | 1.0000 (1.0000 / 1.0000) | 1.0000 (1.0000 / 1.0000) | 0.9855 (1.0000 / 0.9714) |
| **Logistic Regression (Reference, C=1.0)** | 0.9729 | 0.00% (0/39) | 0.9398 (0.8864 / 1.0000) | 0.9394 (1.0000 / 0.8857) | 1.0000 (1.0000 / 1.0000) | 1.0000 (1.0000 / 1.0000) | 0.9855 (1.0000 / 0.9714) |

- **No-Baseline Fallback Model Performance (10 Features on Test Split)** (`summary.md:44`, `train_nobaseline.py` output):
  - Test Macro-F1 = **0.8619** (95% Bootstrap CI: [0.7697, 0.9296]).
  - `benign`: Precision = 0.9412, **Recall = 0.4103**, F1 = 0.5714 (High false alarms on benign when baselines absent).
  - `reconnaissance`: **Precision = 0.6034**, Recall = 1.0000, F1 = 0.7527.
  - `privilege_escalation`: Precision = 1.0000, Recall = 1.0000, F1 = 1.0000.
  - `shell_escape`: Precision = 1.0000, Recall = 1.0000, F1 = 1.0000.
  - `suspicious_tooling`: Precision = 1.0000, Recall = 0.9714, F1 = 0.9855.
- **Trained Model 95% Confidence Intervals (1,000 Trial-Clustered Bootstrap Iterations, Resampled by `run_id`, n=61)**:
  - Test Macro-F1: **[0.9305, 0.9916]** (Mean: 0.9647 ± 0.0156).
  - Benign False Positive Rate: **[0.00%, 0.00%]** (0 false alarms out of 39 benign test windows across 13 benign trials).
- **Confusion Matrices (Classes in order: Benign, Recon, PrivEsc, ShellEsc, Tooling)**:
  - *Trained Tree Ensemble*:
    $$\begin{pmatrix} 39 & 0 & 0 & 0 & 0 \\ 2 & 33 & 0 & 0 & 0 \\ 0 & 0 & 36 & 0 & 0 \\ 0 & 0 & 0 & 41 & 0 \\ 1 & 3 & 0 & 0 & 31 \end{pmatrix}$$
  - *Hand-Authored Specialist Ensemble*:
    $$\begin{pmatrix} 9 & 24 & 0 & 0 & 6 \\ 0 & 35 & 0 & 0 & 0 \\ 0 & 28 & 8 & 0 & 0 \\ 0 & 39 & 0 & 2 & 0 \\ 0 & 6 & 0 & 0 & 29 \end{pmatrix}$$

---

### B4. Feature Ablation Study
- **Evidence Status**: `[ML-OFFLINE]` (`backend/ml_training/results/metrics.json:513-551`)
- Models re-trained on `fit` split with identical parameters ($n=5, d=4, seed=42$) and evaluated on held-out test split:

| Condition Name | Features Retained | Dropped Feature List | Test Macro-F1 | $\Delta$ vs Full |
|---|:---:|---|:---:|:---:|
| **Full Feature Set (12 Features)** | 12 | *None* | **0.9664** | 0.0000 |
| **Without Baseline Drift** | 10 | `unseen_executable_ratio`, `jensen_shannon_drift` | **0.8619** | **-0.1045** |
| **Without Container Shim Shortcut** | 11 | `parent_shim_ratio` | **0.9838** | **+0.0174** |
| **Without All Three Shortcut Features** | 9 | `unseen_executable_ratio`, `jensen_shannon_drift`, `parent_shim_ratio` | **0.9736** | **+0.0072** |

- *Ablation Finding*: Removing baseline drift metrics drops test Macro-F1 by ~0.1045, demonstrating empirical dependence on baseline drift features for distinguishing benign commands from reconnaissance. Conversely, omitting `parent_shim_ratio` does not degrade performance on this dataset.

---

### B5. Probability Calibration & Reliability
- **Evidence Status**: `[ML-OFFLINE]` (`backend/ml_training/results/metrics.json:7-164`)
- Calibration Dataset: 192 qualified windows from 62 independent trials (`calibration` split).
- Binning Configuration: 10 uniform bins on $[0, 1]$.
- **Evaluations across Temperature Configurations**:
  - **Uncalibrated Softmax ($T=1.00$)**: Negative Log-Likelihood (NLL) = **0.1115**, Expected Calibration Error (ECE) = **0.0709**.
  - **Heuristic Temperature ($T=0.35$)**: NLL = **0.0591**, ECE = **0.0193**.
  - **Fitted Temperature ($T^*=0.4412$)**: NLL = **0.0560**, ECE = **0.0107** (an $84.9\%$ relative reduction in calibration error compared to uncalibrated softmax).
- **Fitted Temperatures**:
  - 12-feature model: $T^* = \mathbf{0.4412}$ (`models/trained_ensemble.json`).
  - 10-feature no-baseline fallback model: $T^* = \mathbf{0.4996}$ (`models/trained_ensemble_nobaseline.json`).

---

### B6. Explainability Verification: Path-Delta vs. TreeSHAP
- **Evidence Status**: `[ML-OFFLINE]` & `[VERIFICATION SCRIPT]`
- **Attribution Method Name**: `path-based attribution` / `tree_path_delta` (`backend/src/porygon_api/ml_classifier.py:726-800`).
- **Mathematical Additivity Assertion**:
  Decomposes active branch decisions into telescoping probability deltas:
  $$\Delta p = p(\text{child}) - p(\text{parent})$$
  Additivity identity: $p(\text{leaf}) = p(\text{root}) + \sum_{i} \Delta p_i$.
  - Unit Test Assertion: `abs(raw_val - (base_val + delta_sum)) < 1e-5` across operational test vectors.
  - Test Result: **PASSED** in `backend/tests/test_trained_classifier.py:106-147`.
- **Empirical Comparison with `shap.TreeExplainer` on Scikit-Learn Forest** (`metrics.json:552-560`):
  - Evaluation Sample: 50 randomly selected held-out test windows.
  - Total Value Pairs Compared: 3,000 attribution pairs (50 windows $\times$ 5 classes $\times$ 12 features).
  - **Pearson Correlation ($r$)**: **0.9467** ($p < 10^{-15}$).
  - **Spearman Rank Correlation ($\rho$)**: **0.8320** ($p < 10^{-15}$).
  - Difference Flag: `differs_from_treeshap = true` (Tree-path deltas compute localized directional probability transitions along the traversed branch in $O(\text{depth})$ time, whereas TreeSHAP computes cooperative game-theoretic Shapley values across all counterfactual subtrees).

---

### B7. Runtime System Integration & Live Inference
- **Evidence Status**: `[VERIFICATION SCRIPT]` (`backend/src/porygon_api/main.py:2680-2935`, `dashboard/app.js:1450-1750`)
- **API Endpoints**:
  1. `GET /api/v1/ml/model-info`: Returns model name, version, architecture, classes, and SHA-256 digest.
  2. `POST /api/v1/ml/classify`: Classifies an explicit JSON array of process events.
  3. `POST /api/v1/ml/classify-container/{container_id}`: Queries PostgreSQL for the latest process execution events of the designated container and classifies live behavior.
  4. `POST /api/v1/ml/classify-features`: Evaluates precomputed feature dictionaries.
- **Operational Slicing & Minimum Event Gate**:
  - Telemetry Slice Size: `event_limit = 50` events (query parameter, default 50, range 1–200) (`main.py:2785`).
  - Minimum Event Cutoff: Telemetry slices with **fewer than 3 events** return `predicted_class: "insufficient_data"`, confidence 0.0, risk level `clean`, summary statement: *"fewer than 3 process execution events in telemetry slice"* (`main.py:2721-2735`).
- **Dynamic Model Selection Rule** (`main.py:2840-2856`):
  - If `baseline_features` is present **AND** `drift_score` is not `None` $\rightarrow$ Evaluates **12-feature model** (`PORYGON_ML_MODEL_PATH`, `model_variant = "baseline"`).
  - Otherwise $\rightarrow$ Falls back to **10-feature model** (`PORYGON_ML_MODEL_NOBASELINE_PATH`, `model_variant = "no_baseline"`).
  - Fail-Safe Boundary: If an environment variable is set to a nonexistent or tampered file, the API immediately raises **HTTP 500** (`main.py:2657-2675`). Silent fallback to uncalibrated heuristic mode is strictly prohibited. When both environment variables are unset, the hand-authored heuristic ensemble serves as the default fallback.
- **Frontend Dashboard Behavior** (`dashboard/app.js`, `dashboard/index.html`):
  - Monitored Containers: Filtered by default to running containers where `current_snapshot.state.running === true` AND `last_seen_at` $\le 120$ seconds.
  - Auto-Refresh Engine: Periodic re-classification executes every 30 seconds in concurrent chunks of 8 containers. Pauses when browser tab is hidden (`document.hidden`).
- **Inference Latency & Memory Footprint**: **NOT AVAILABLE** in committed logs (No microbenchmark measurement file recorded).

---

### B8. Supplementary Evaluations & Cross-Image Generalization
- **Evidence Status**: **NOT AVAILABLE**
- Cross-image evaluation (e.g. testing the model trained on Alpine against Debian/Ubuntu live containers) was not executed. No secondary cross-image test records exist in `backend/ml_training/`.

---

# PART C — CROSS-CUTTING RIGOR & VERIFIABILITY

### C1. Documented Limitations and Threats to Validity

#### Group 1: Verbatim Limitations from `summary.md:53-66`:
1. **Single Workload Container Image**: All training and test trials were generated using the `porygon-training-workload:latest` image (an Alpine-based environment containing developer tools such as `sudo`, `nsenter`, `capsh`, `gcc`, `nc`). In heterogeneous production environments with varied base images (Debian, Ubuntu, Distroless, scratch), executable distributions and baseline behaviors will vary.
2. **Benign and Reconnaissance Command Overlap**: Commands such as `whoami`, `id`, `ps`, `netstat`, and `uname -a` are frequently executed during both administrative benign operations and attacker reconnaissance. Because the benign baseline was compiled from the scripted benign trials, reconnaissance attacks only triggered elevated `unseen_executable_ratio` and `jensen_shannon_drift` when the attacker executed tools absent from the baseline profile.
3. **Correlated Windows per Trial**: Multiple 60-second tumbling windows extracted from the same 4-5 minute container trial share execution context, container ID, and temporal state. We addressed this autocorrelation through `GroupKFold` grouped by `run_id` on the `fit` split for all tuning, and trial-clustered bootstrap resampling on the test split.
4. **Falco Output File Permission Remediation and Reruns**: An earlier Docker volume permissions deadlock on `/var/log/porygon/falco-events.jsonl` caused 100 trials to record zero events before permanent remediation in `compose.yaml`. All 100 zero-event trials were systematically rerun with identical ground-truth tactic labels and split assignments, preventing class attrition or survivor bias.
5. **Execution Modality via `docker exec`**: All canary attack scripts were injected into live containers using `docker exec`, causing process ancestries to originate under container runtime shims (`containerd-shim` / `docker-runc`). This makes `parent_shim_ratio` an effective operational discriminator for external injection. The ablation study above explicitly documents classifier performance when this feature is withheld.
6. **Constant Feature Distribution**: `root_ratio` was constant (1.0) across all trials because the container runtime executed without user namespaces (`root` user).
7. **Shell Execution Diversity**: Only `shell_escape` canary attacks invoked interactive `sh`/`bash` shells; other attack tactics were executed via direct non-shell invocations.
8. **Minimum Event Requirement**: The production live endpoint requires 3 or more process execution events in the telemetry slice; slices with fewer than 3 events return `insufficient_data` without producing a verdict.
9. **Test Set Sample Size**: The held-out test split comprises about 12 independent trials per class (61 total: 13 benign, 12 reconnaissance, 12 privilege escalation, 12 shell escape, 12 suspicious tooling).
10. **Absence of Production Image Baselines**: In live production environments, cryptographic baseline profiles do not exist for unprofiled container images, requiring fallback to the 10-feature no-baseline model (`trained_ensemble_nobaseline.json`) with lower benign recall (~0.41).
11. **Hand-Set Threshold Transferability**: Hand-authored heuristic thresholds calibrated on synthetic rules did not transfer effectively to real multi-class process telemetry, producing high benign false alarms (76.92%).
12. **Strict Held-Out Test Evaluation**: The test split was evaluated once and only once. No model hyperparameter, depth, threshold, or calibration parameter was tuned or modified based on test set performance.

#### Group 2: Additional Verifiable Limitations from Protocol and Code:
13. **Recall Non-Inferiority Lack of Stress-Testing** (`empirical-results.md:42-44,58`): In the 216-trial profile-scope study, recall was 100% across all arms (96/96) with zero variance, meaning the statistical machinery for detecting a recall trade-off was never exercised against a real trade-off.
14. **Process-Name Scope Insensitivity** (`empirical-results.md:37-40`): Jensen-Shannon distance computed on process binary names cannot detect Linux capability changes (`NET_RAW`), resulting in an identical null result ($p=1.0$) between `ARM-CONTEXT` and `ARM-DIGEST`.
15. **Synthetic / Scripted Canary Scenarios**: All attack workloads were scripted sequences executed via `collect_training_data.py`; no live compiled malware binaries or polymorphic evasion techniques were evaluated.
16. **Single-Host Topology**: The entire platform runs on a single Docker host; network partition, distributed consensus, or multi-node Kubernetes telemetry loss scenarios were not evaluated.

---

### C2. Inconsistencies and Data Gaps

1. **Protocol Evidence-Class Mislabling in Initial Study Artifacts**:
   - *Discrepancy*: An earlier study manifest mislabeled run `study-confirmatory-200-20260906t071234Z` as `evidence_class: confirmatory` / `research_eligible: true`.
   - *Resolution*: Documented in `empirical-results.md:3-14` as a study-summary reporting defect. The run is strictly `evidence_class: pilot` and `research_eligible: false`. No confirmatory-grade run has ever been collected.
2. **Planned vs. Executed Test Trial Counts**:
   - *Discrepancy*: Early design documentation referenced approximately 56 test trials based on a nominal 25% expectation ($220 \times 0.25 = 55$).
   - *Actual Number*: Deterministic SHA-256 pseudo-random hashing across the 220 completed runs yielded exactly **61 test trials** (13 benign, 12 reconnaissance, 12 privilege escalation, 12 shell escape, 12 suspicious tooling) in both `runs.csv` and `windows.csv`.
3. **Macro-F1 Rounding in Early Text**:
   - *Discrepancy*: Early scratch text referenced "0.963 Macro-F1".
   - *Actual Number*: In `metrics.json:168` and `summary.md:14`, the exact calculated test Macro-F1 for the calibrated 12-feature ensemble is **0.9664**.
4. **Items Confirmed as NOT AVAILABLE**:
   - Ingestion latency from Falco capture to PostgreSQL commit ($t_{\text{db}} - t_{\text{event}}$).
   - CPU, RAM RSS, and disk write throughput benchmarks under sustained load.
   - Live PostgreSQL table row counts (static dump not committed; live DB query prohibited).
   - Aggregate vulnerability reachability noise reduction across the entire enterprise cluster.
   - Cross-image ML evaluation results.

---

### C3. Existing Figures and Tables Inventory

| Item ID | Title / Description | Source File Path | Rendered Format | 300 DPI Exportability without Re-running |
|---|---|---|:---:|:---:|
| **FIG-01** | Test Split Confusion Matrices ($5 \times 5$ Heatmaps across 4 Models) | `backend/ml_training/notebooks/classifier_report.ipynb:cell 10` | Embedded PNG (Base64) | **Available** (Base64 raster can be extracted at 130 DPI; rendering at native 300 DPI requires re-saving the existing figure object in Python) |
| **FIG-02** | Softmax Reliability Diagrams ($T=0.35, 1.00, 0.4412$) | `backend/ml_training/notebooks/classifier_report.ipynb:cell 12` | Embedded PNG (Base64) | **Available** (130 DPI in notebook JSON) |
| **FIG-03** | Feature Ablation Macro-F1 Bar Chart | `backend/ml_training/notebooks/classifier_report.ipynb:cell 14` | Embedded PNG (Base64) | **Available** (130 DPI in notebook JSON) |
| **FIG-04** | Tree-Path Attribution Waterfall (Shell Escape Window) | `backend/ml_training/notebooks/classifier_report.ipynb:cell 16` | Embedded PNG (Base64) | **Available** (130 DPI in notebook JSON) |
| **FIG-05** | Interactive Results Dashboard Visualizations | `artifacts/results.html` | HTML / SVG / Canvas | **Available** (Browser exportable) |
| **TBL-01** | Primary Comparative Model Performance Table | `backend/ml_training/results/summary.md:12-17` | Markdown / JSON | **Available** (Exact table data in `metrics.json`) |
| **TBL-02** | Feature Ablation Summary Table | `backend/ml_training/results/summary.md:37-42` | Markdown / JSON | **Available** (Exact table data in `metrics.json`) |
| **TBL-03** | 216-Trial Profile-Scope Primary Analysis Table | `artifacts/experiments/protocol-v1/tables/profile-scope-primary-216.json` | JSON Table | **Available** |
| **TBL-04** | Exploratory Context-Delta Finding Table | `artifacts/experiments/protocol-v1/exploratory/context-delta-finding-216.json` | JSON Table | **Available** |

---

### C4. Authorship & Project Attribution
Extracted verbatim from Git commit log history (`git log --format="%an: %s"`):

#### 1. Madhav Sreejith:
- `Initial commit`
- `feat: add explainable ML threat classifier`
  - Authored: `backend/src/porygon_api/ml_classifier.py`
  - Authored: `backend/ml_training/` (dataset collection harness, window extraction, training, temperature calibration, evaluation pipeline, TreeSHAP parity testing, and model registry verification).
  - Authored: `dashboard/app.js` and `dashboard/index.html` (ML Classifier frontend page, running container auto-refresh, verdict cards, and path-delta modal inspection).
- `Removed some banner and cleaned it up`

#### 2. Anurup R Krishnan:
- Core Platform Infrastructure: `compose.yaml`, `gateway/`, `postgres`, `backend/entrypoint.sh`.
- Event Telemetry & Ingestion: `collector/` (Docker engine event listener), `telemetry/` (Falco line parser and spooling outbox), `falco/porygon_rules.yaml`.
- Vulnerability Scanning: `scanner/` (Trivy integration, SBOM extraction, FIRST EPSS and CISA KEV real-time joins).
- Continuous Behavioral Profiling & Anomaly Scoring: `porygon_api/scoring.py`, `porygon_api/models.py`, `porygon_api/detection.py` (POR-DET-001..007).
- Containment Response Engine: `responder/`, `scripts/verify_containment_response.sh`.
- Research Protocol & Experiment Harness: `experiments/` (protocol v1 runner, sample size calculations, conformance tests, study manifests, profile scope analysis, `artifacts/results.json`).
- Verification Framework & Documentation: `scripts/verify_*.sh`, LaTeX Beamer presentation decks (`docs/presentation/`), and architectural specification guides.
