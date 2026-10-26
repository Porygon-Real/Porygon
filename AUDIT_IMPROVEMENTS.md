# Porygon Improvements Backlog

Actionable complex engineering and security tasks remaining to be implemented. All simple, resolved items (including command shape unquoting, incident grouping short container ID support, Gemini header authentication, Trivy concurrency locking, and auto-remove rollback protection) have been implemented, verified, and removed.

---

## Open Tasks Matrix

| ID | Component | Severity | Issue | Target Remediation |
|:---|:---|:---:|:---|:---|
| **IMP-02** | Kernel Telemetry & Ingestion | **CRITICAL** | Only hooks `execve`; telemetry adapter drops non-execve events | Multi-syscall eBPF rules + telemetry normalizer & spool schema upgrade |
| **IMP-07** | ML Classifier Engine | **HIGH** | Static frozen sets on basenames bypassed by renaming (`/tmp/worker`) | Behavioral heuristics (writable dirs, unlinked inodes, argument tokens) |

---

## 1. Kernel Telemetry & Ingestion

### IMP-02: Multi-Syscall Telemetry & Adapter Spool Expansion
* **Code Reference:** [`falco/porygon_rules.yaml:3-6`](file:///home/anuruprkris/Project/final_yeat_work/falco/porygon_rules.yaml#L3-L6) & [`telemetry/src/porygon_telemetry/normalizer.py:82-89`](file:///home/anuruprkris/Project/final_yeat_work/telemetry/src/porygon_telemetry/normalizer.py#L82-L89)
* **Issue:** Falco only hooks `execve`/`execveat`. Telemetry normalizer strictly filters for `expected_rule == "Porygon Container Process Execution"` and outbox only dispatches to `/internal/v1/process-events/batch`, silently dropping any socket or memory syscall events.
* **Action:**
  1. Add Falco rules for non-loopback outbound socket connections (`connect`), executable memory (`memfd_create`), and file tampering (`openat`).
  2. Update `porygon_telemetry` normalizer and outbox schema to multiplex `runtime_events` alongside `process_events`.
  3. Wire delivery loop to post runtime events to `/internal/v1/runtime-events/batch`.

---

## 2. Behavioral Modeling & Detection

### IMP-07: Behavioral Heuristics Over Static Binary Matching
* **Code Reference:** [`backend/src/porygon_api/ml_classifier.py:42-81, 186-205`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/ml_classifier.py#L42-L81)
* **Issue:** Taxonomy sets (`SHELL_BINARIES`, `RECON_BINARIES`) rely on exact basename matching; copying binaries to `/tmp/worker` or `/dev/shm/.x` bypasses all category counters.
* **Action:**
  1. Add runtime behavioral indicators: execution from writable dirs (`/tmp`, `/dev/shm`), unlinked executables (`(deleted)`), and command argument tokens.
  2. Feed indicators directly into Random Forest feature extraction vector and retrain tree decision thresholds.
