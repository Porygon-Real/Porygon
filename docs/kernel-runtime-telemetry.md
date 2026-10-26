# Kernel runtime telemetry

Porygon stores non-exec syscall evidence in `kernel_runtime_events`, separately from process execution and Docker lifecycle events. Existing behavior profiles, feature vectors, frozen research artifacts, and detection rules continue to use their original input streams.

| Activity | Syscalls | Meaning |
| --- | --- | --- |
| Outbound connection | `connect` | A non-loopback IP connection succeeded or returned `EINPROGRESS`; the latter records an attempt still in progress. |
| Memory-backed file | `memfd_create` | An anonymous file was created. This does not establish that its contents were executed. |
| Writable file open | `open`, `openat`, `openat2` | A sensitive path was successfully opened with write access. |
| File write | `write`, `writev`, `pwrite`, `pwritev` | Positive bytes were written to a sensitive path. Only the byte count and context are captured, never the write buffer. |

The Falco command enables `base_syscalls.all=true` so write-family syscalls used by these rules are actually active. Path filters bound emitted file evidence, but tracing these syscalls adds capture work; validate event drops and resource use under the intended workload. See [Falco syscall tuning](https://falco.org/docs/concepts/event-sources/kernel/tuning/).

Sensitive paths cover `/etc/`, `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`, and `/root/.ssh/`. Protected platform containers remain excluded by their existing label. This capture scope is intentionally narrower than all filesystem activity. An inbound accept or a memory-backed file creation is not labeled outbound communication or code execution.

## Delivery and storage

Falco outputs typed records into its existing JSON file. The telemetry adapter recognizes four additional rules and validates the syscall, result, peer address, and container ID. A durable SQLite outbox assigns each record to either the process or kernel channel. Upgrading an existing spool preserves queued exec payloads and the file checkpoint. Queue writes and checkpoint advancement remain atomic.

Each delivery pass shares capacity between due channels. A failed kernel request retains its own rows for backoff and retry; an acknowledged process request can still drain. Internal channel markers are stripped from API payloads. Stable evidence IDs and conflict-safe inserts prevent duplicate database growth after replay or a lost acknowledgement. Queue capacity remains shared and bounded; sustained overload still requires operational attention.

`POST /internal/v1/kernel-events/batch` requires the internal service token and accepts at most 250 events atomically. A database failure rolls back the batch. The gateway does not expose this route. The new Alembic migration adds storage and indexes without rewriting historical evidence. Downgrade refuses to remove a nonempty kernel evidence table.

## Identity repair

Initial ingest attempts host-scoped container resolution. A missing or ambiguous identity remains explicitly unresolved. A background worker repairs committed process and kernel rows in bounded transactions, rather than rescanning evidence inside ingestion requests. Wake hints coalesce; periodic scans recover outstanding work after restart. PostgreSQL transaction advisory locking coordinates backend replicas, with local lock and statement timeouts.

| Configuration | Default | Purpose |
| --- | --- | --- |
| `PORYGON_RECONCILIATION_ENABLED` | `true` | Enable the background worker. |
| `PORYGON_RECONCILIATION_INTERVAL_SECONDS` | `5` | Periodic recovery interval. |
| `PORYGON_RECONCILIATION_BATCH_SIZE` | `500` | Maximum candidates per repair stream and pass. |

Local images can resolve to a host/container/image ID before a registry digest exists. Kernel evidence does not require a fabricated digest. A later known registry digest can enrich the same event. Existing research profile requirements remain unchanged.

## Inspection

The dashboard telemetry tab includes a separate kernel activity table with exact host, container selection, and activity filtering. An unavailable response clears stale results and displays an explicit retry state. Evidence strings render as text.

- `GET /api/v1/kernel-events`: newest events, optional `runtime_action`, `container_id`, `docker_host_id`, and `image_digest`; maximum 1,000 rows.
- `GET /api/v1/kernel-events/summary`: counts by action and resolved identity.
- `GET /api/v1/kernel-events/{event_id}`: one stored record.
- `GET /api/v1/reconciliation/status`: worker state, last success/error class, cumulative repaired counts.
- `POST /operator/v1/kernel-events/reconcile`: explicit bounded repair, authenticated with the operator token.

Kernel events participate in existing bounded raw-evidence retention, including dry runs. Scheduled deletion remains disabled by default. No new single-syscall automatic containment policy is introduced.

## Verification

Run `python3 scripts/verify_kernel_runtime.py` against the local stack. It creates one disposable container with no host mounts and all capabilities dropped. It generates a non-loopback connection, a loopback negative control, a memory-backed file, and a controlled write inside the container layer. It repeats the probes during telemetry and backend outages, verifies recovered records, replays normalized evidence, and checks isolation from exec events. Both services and the disposable target are restored or removed on exit. Results are saved under `artifacts/local/kernel-runtime-validation/`.

The backend tests cover a 50,000-row retention batch with a 999-parameter database limit, transaction rollback, replay isolation, host ambiguity, local image repair, worker restart recovery, and replica lock ownership. `PORYGON_TEST_POSTGRES=1 pytest tests/test_kernel_migration.py` exercises the full Alembic chain in a unique disposable schema, including evidence-preserving downgrade refusal. Use `alembic upgrade head --sql` for an offline SQL migration check; the installed Alembic CLI has no `--dry-run` option.
