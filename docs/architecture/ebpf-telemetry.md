# eBPF Kernel Telemetry & Ingestion Architecture

> **Components:** Falco modern-eBPF driver, `porygon-telemetry`, backend identity resolution<br>
> **Schema:** `porygon.behaviour.v1`  
> **Behavioral input:** `execve`, `execveat`<br>
> **Separate runtime evidence:** `connect`, `memfd_create`, sensitive-path open/write syscalls; see [kernel runtime telemetry](../kernel-runtime-telemetry.md).

---

## 1. Observability Principles

Porygon leverages Linux eBPF (extended Berkeley Packet Filter) to achieve kernel-level observability with three non-negotiable architectural constraints:

1. **Zero Workload Mutation:** No sidecar injection, no `LD_PRELOAD` tricks, no kernel module compilation, and no modifications to containerized application binaries.
2. **Minimal Kernel Footprint:** Relies on the modern eBPF probe driver utilizing BPF ring buffers rather than legacy perf-event buffers, minimizing context switches and memory overhead.
3. **Provable Ingestion Loss Accounting:** In systems security research, silent telemetry loss leads to false negatives. Porygon treats event loss as a first-class metric, accounting for ring-buffer overruns and pipeline backpressure.

---

## 2. Event Interception & Kernel Tracepoints

Porygon hooks raw kernel tracepoints rather than kprobes to ensure portability and stability across Linux kernel versions:

```
[User Space Process]
        |
        | execve("/bin/sh", ["sh", "-c", "whoami"], ...)
        v
[Kernel System Call Handler]
        |
        +---> tracepoint:syscalls:sys_enter_execve
        |           |
        |           +---> BPF Program: Extracts PPID, UID, GID, Comm, CGroup ID
        |
        | (Process Image Replacement & Execution)
        |
        +---> tracepoint:syscalls:sys_exit_execve
                    |
                    +---> BPF Program: Extracts return code, registers executable path
                          |
                          v
                    [BPF Ring Buffer (Host Memory)]
```

### Separate observation from behavioral scoring

The frozen [research threat model](../research/threat-model.md) defines the exec-based behavior-profile contract. `execve` and `execveat` continue to feed that contract. Existing profile hashes, features, and detection semantics do not incorporate the additional syscalls.

A separate typed evidence channel observes non-loopback outbound connections, memory-backed file creation, writable opens, and actual writes to sensitive paths. A successful open records write access; a positive write result records bytes written. Neither a connection nor a memory-backed file alone establishes exploitation. Falco enables the write-family syscalls required by the rules, with emitted events restricted by path and protected-container filters. Capture overhead and event drops depend on workload and must be measured for the deployment.

---

## 3. Container Context & Identity Resolution

Falco supplies container and process context. `porygon-telemetry` normalizes and durably spools this evidence. Independently, `porygon-collector` records Docker lifecycle snapshots and immutable image metadata. The backend resolves the reported container prefix within its exact Docker host, and a bounded background worker repairs out-of-order identities after commit:

```
+------------------------------------+
|  eBPF Event (Kernel CGroup v2 ID)  |
+-----------------+------------------+
                  |
                  v
+--------------------------------------------------------------+
|                   porygon-collector                          |
|                                                              |
| 1. Query Docker Engine /proc/self/cgroup or Docker socket    |
| 2. Map cgroup -> Container ID (e.g. 7f93a18b...)             |
| 3. Retrieve immutable image repository digest:               |
|    docker.io/library/nginx@sha256:4b83445e998a...            |
| 4. Extract runtime security permissions:                     |
|    - Privileged mode: bool                                   |
|    - Exposed host ports: [80/tcp, 443/tcp]                   |
|    - Mounted volumes: [/var/log -> /var/log:ro]              |
+------------------------------+-------------------------------+
                               |
                               v
                Normalized Porygon Telemetry Event
```

---

## 4. Process evidence and behavioral features

The following diagram organizes process, parent, and deployment context conceptually. The wire schemas are `ProcessExecEventIn` and `KernelRuntimeEventIn` in `backend/src/porygon_api/schemas.py`; `porygon.behaviour.v1` names the aggregated feature contract rather than this context diagram.

```json
{
  "event_id": "018f6c48-26ab-7b70-87a4-0c33a9b1c701",
  "timestamp": "2026-10-24T15:30:12.451928Z",
  "container_id": "7f93a18b2c45e1a90d817456bc3a918e0018a9",
  "container_name": "web_frontend",
  "image_repo": "nginx",
  "image_tag": "1.25.4-alpine",
  "image_digest": "sha256:4b83445e998a1a3b593798ef3d21c430e719548bb2081a98075f14e7a0487d55",
  "process": {
    "pid": 4821,
    "ppid": 1402,
    "comm": "curl",
    "exe": "/usr/bin/curl",
    "cmdline": "curl -s http://169.254.169.254/latest/meta-data/",
    "uid": 0,
    "gid": 0
  },
  "parent": {
    "pid": 1402,
    "comm": "sh",
    "exe": "/bin/sh",
    "cmdline": "sh -c curl -s http://169.254.169.254/latest/meta-data/"
  },
  "runtime_context": {
    "privileged": false,
    "network_mode": "bridge",
    "read_only_rootfs": false
  }
}
```

---

## 5. Recovery and verification

`scripts/verify_ebpf_telemetry.sh` exercises real execs, parent linkage, identity resolution, adapter/backend outages, malformed input handling, and replay idempotency. Its evidence records the observed Falco file IDs, queued rows, and recovered database rows for each run. `scripts/verify_event_ingestion.sh` additionally saturates the lifecycle spool and reconciles Docker canary events against PostgreSQL.

`python3 scripts/verify_kernel_runtime.py` exercises the separate non-exec channel with real connections, memory-backed files, and sensitive-path writes, repeats them through both outages, and replays the normalized records. It also verifies loopback exclusion and exec-stream isolation. Kernel drop accounting, source-file retention, queue saturation, and database recovery must be considered together under the deployment workload.
