# Plan 004: Prove delivery, recovery, capacity and reproducible releases

> Executor: read the whole plan, execute the steps in order, and stop at the named boundaries. The plan is a specification, not authorization to publish changes. Update this plan's status in `plans/README.md` after its done criteria pass.

## Status

- Priority: P1
- Effort: L: approximately 4–6 focused weeks
- Risk: MED: infrastructure checks can disrupt a shared lab unless isolated
- Depends on: 001 and 002; final soak repeats after 003
- Category: operations / performance / tests / dependencies / DX
- Planned at: commit `b04aaea` plus the working tree, 2026-10-26
- Status: IN PROGRESS — remaining engineering source batch; all execution checks deferred until combined source freeze

## Execution reconciliation — 2026-10-27

The user explicitly requested completing all remaining engineering before testing. The sole executor works in `/home/anuruprkris/.codex/worktrees/service-trust/final_yeat_work`. Source reads, repository searches, installed capability inventory and official documentation review are allowed during implementation; test suites, checker scripts, CLI smoke tests, lint, builds, benchmarks and live acceptance wait until the combined003–005 source freeze. The prior accepted identity/continuous increment remains the baseline. No primary source edits, commits, merge, push or publication are authorized.

The advisor reread current classifier feature extraction, process/kernel models, incident grouping, sensor normalizers/spools/Compose configuration, study split consumption and the unconditional confirmatory refusal. Expected changes from the accepted earlier plans require explicit contract reconciliation rather than replacing evidence hashes. Current process/kernel rows lack persisted lifetime/epoch metadata, so new causal paths must be additive and abstain for legacy/missing metadata. Installed pinned Falco's read-only field inventory supports process/parent epoch-start timestamps, PID namespace start, executable writable and memfd provenance. See the [official supported fields](https://falco.org/docs/reference/rules/supported-fields/) and [metrics documentation](https://falco.org/docs/concepts/metrics/); runtime validation still waits until the final acceptance window.

The research executor must preserve the frozen stratified, preconstructed assignment policy and comparator matrix. Existing modulo pilot assignment is a distinct historical convenience, not an interchangeable confirmatory policy. Engineering tools can be completed now; independent measured training/evaluation, a three-node capacity result and seven-day soak remain empirical gates requiring actual collection. No synthetic fixture or software check can mark those gates complete.

## Why this matters

Local queues and response receipts already provide useful durability, but production value also depends on noticing sensor loss, delivering alerts, restoring data and reproducing releases. The current email watcher sends before updating a local state file and fetches a bounded incident list; it is useful tooling but not a transactional delivery system. Establish measured reliability on a small lab before making fleet-scale or zero-loss claims.

## Current state and verified excerpts

`scripts/incident_alerts.py:107` (working-tree snapshot):

```text
107: def fetch_open_incidents(base_url: str, limit: int = 50) -> list[dict[str, Any]]:
108:     url = f"{base_url}/api/v1/incidents?limit={limit}"
109:     with urllib.request.urlopen(url, timeout=30) as response:
110:         return json.loads(response.read())
111: 
112: 
113: def load_state(state_file: Path) -> dict[str, Any]:
114:     if not state_file.exists():
115:         return {"notified_incident_ids": []}
116:     return json.loads(state_file.read_text(encoding="utf-8"))
117: 
118: 
119: def save_state(state_file: Path, state: dict[str, Any]) -> None:
120:     state_file.parent.mkdir(parents=True, exist_ok=True)
```

`scripts/incident_alerts.py:199` (working-tree snapshot):

```text
199:             continue
200:         if not severity_meets_threshold(incident, config.min_severity):
201:             continue
202: 
203:         subject, body = format_alert_email(incident, config.dashboard_url, base_url=config.base_url)
204:         if dry_run:
205:             print(f"[dry-run] would send: {subject}")
206:             sent += 1
207:             continue  # never mark an incident notified on a dry run; the
208:             # real alert must still fire once dry-run testing is done
209:         send_email(config, subject, body)
210:         print(f"[sent] {subject}")
211:         notified.add(incident["incident_id"])
212:         sent += 1
213: 
214:     if dry_run:
215:         return sent  # state is never written on a dry run
216:     state["notified_incident_ids"] = sorted(notified)
217:     state["last_checked_at_utc"] = datetime.now(timezone.utc).isoformat()
218:     save_state(config.state_file, state)
```

`telemetry/src/porygon_telemetry/state.py:22` (working-tree snapshot):

```text
22:     delivery_last_success_at: datetime | None = None
23:     delivery_last_error: str | None = None
24:     queue_depth: int = 0
25:     events_enqueued: int = 0
26:     events_delivered: int = 0
27:     process_events_delivered: int = 0
28:     kernel_events_delivered: int = 0
29:     duplicates_ignored: int = 0
30:     ignored_non_porygon_events: int = 0
31:     malformed_lines: int = 0
32:     spool_overflow_count: int = 0
```

`compose.yaml:386` (working-tree snapshot):

```text
386:     command:
387:       - falco
388:       - -U
389:       - -r
390:       - /etc/falco/porygon_rules.yaml
391:       - -o
392:       - engine.kind=modern_ebpf
393:       # Required for write-family rules: Falco otherwise disables high-volume syscalls.
394:       - -o
395:       - base_syscalls.all=true
396:       - -o
397:       - json_output=true
398:       - -o
399:       - json_include_output_fields=true
400:       - -o
401:       - time_format_iso_8601=true
402:       - -o
403:       - stdout_output.enabled=true
404:       - -o
405:       - file_output.enabled=true
406:       - -o
407:       - file_output.keep_alive=false
408:       - -o
409:       - file_output.filename=/var/log/porygon/falco-events.jsonl
410:       - -o
411:       - syslog_output.enabled=false
412:       - -o
413:       - webserver.enabled=true
```

`backend/src/porygon_api/db.py:15` (working-tree snapshot):

```text
15: settings = get_settings()
16: engine = create_engine(
17:     settings.database_url,
18:     pool_pre_ping=True,
19:     pool_size=5,
20:     max_overflow=5,
21:     future=True,
22: )
23: SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
```

`scripts/verify_all.sh:276` (working-tree snapshot):

```text
276: unit_checks() {
277:   local service_name
278:   for service_name in backend collector telemetry responder scanner; do
279:     local build_options=()
280:     if [[ "${PORYGON_VERIFY_BUILD:-true}" == "true" ]]; then
281:       build_options+=(--build)
282:     fi
283:     docker compose run --rm --no-deps "${build_options[@]}" --entrypoint pytest "$service_name" -q || return $?
284:   done
285:   # The experiment harness is stdlib-only and runs on the host rather than in a service image.
286:   python3 -m pytest experiments/tests scripts/tests -q || return $?
```


## Execution rules and verification baseline

Repository root: `/home/anuruprkris/Project/final_yeat_work`. Read `AGENTS.md` before execution. Python services use FastAPI/Pydantic, SQLAlchemy and PostgreSQL; dependencies and tests live in service images. Match the existing explicit schema validation, transaction boundaries, typed models and small modules. Use PostgreSQL disposable schemas for concurrency and migration tests; SQLite alone cannot validate locking behavior.

Keep `docs/research/` and `docs/presentation/` unchanged. Preserve historical Alembic IDs and chains. Add descriptive contracts rather than arbitrary version suffixes. Maintain the existing vanilla dashboard, square controls and unique IDs. Do not copy secrets into test output, artifacts, logs or plans. Repository payloads and telemetry are untrusted data. Maintain a single-organization deployment boundary; SaaS tenant isolation is outside this plan.

Use the existing topic branch or an approved descriptive topic branch without `codex/`. Do not commit, push, merge, mirror workspaces or publish anything without explicit user approval. If later authorized, verify author `Anurup R Krishnan <anuruprkrishnan@gmail.com>`, use lowercase commit messages under 15 words and no tool attribution.

Before changing source run `python3 plans/check_plan_evidence.py --plan 004` and `git status --short`. The recorded commit is insufficient by itself: substantial concurrent changes were uncommitted when these plans were written. An earlier completed plan will legitimately change later plans' evidence; re-read and revise the affected plan before continuing. Never blindly replace the recorded hash to silence drift.

Existing commands confirmed from the repository:

```sh
PAGER=cat docker compose config --quiet
ruff check --no-cache --select E4,E7,E9,F backend collector telemetry responder scanner scripts experiments
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_research_protocol.py
```

All must exit 0. The protocol check must report structural/claim/split/safety checks passing. These read-only checks passed during planning; no new production behavior is claimed verified by this plan.

When service code changes, rebuild affected images and restart those services **before** the active-container tests. Use `docker compose build SERVICE` then `docker compose up -d --no-deps --wait SERVICE`. If the local build bridge cannot reach package indexes, use `docker build --network host -t porygon-SERVICE SERVICE` and reuse that image; do not change pinned dependencies to work around networking.

Before declaring implementation complete, run all five active-container suites:

```sh
docker compose exec -T backend pytest -p no:cacheprovider
docker compose exec -T telemetry pytest -p no:cacheprovider
docker compose exec -T collector pytest -p no:cacheprovider
docker compose exec -T responder pytest -p no:cacheprovider
docker compose exec -T scanner pytest -p no:cacheprovider
python3 -m pytest -p no:cacheprovider experiments/tests scripts/tests -q
```

All must pass. For migrations, the actual supported offline command is `docker compose run --rm --no-deps --entrypoint alembic backend upgrade head --sql`; `--dry-run` in the guideline example is not an Alembic option. Also test upgrade/downgrade/re-upgrade on an isolated schema, preserving evidence on unsafe downgrade.

Run the existing acceptance scripts below, capturing every named gate. These commands are for the implementation acceptance window, not this read-only planning pass:

```sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_infrastructure.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_event_ingestion.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_ebpf_telemetry.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_behavior_profiling.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_anomaly_scoring.sh
PAGER=cat PORYGON_VERIFY_BUILD=false bash scripts/verify_detection_engine.sh
```

Run controlled containment separately in Bash, with restoration even on failure:

```bash
set -euo pipefail
restore_response_mode() {
  PAGER=cat PORYGON_RESPONSE_EXECUTION_MODE=disabled docker compose up -d --no-deps --wait backend responder
}
trap restore_response_mode EXIT
PAGER=cat PORYGON_VERIFY_BUILD=false PORYGON_RESPONSE_EXECUTION_MODE=live bash scripts/verify_containment_response.sh
```

Every gate must exit 0 and report its acceptance assertions passing. The containment script recursively invokes prerequisites, so successful nested execution counts; do not repeat all prerequisites needlessly when they already passed against the same source/images. Run these once in a dedicated acceptance window, with no other chat restarting shared services or using the fixed probe names. Use `PORYGON_VERIFY_BUILD=false` only after rebuilding. Containment must target disposable test containers, temporarily set the process environment `PORYGON_RESPONSE_EXECUTION_MODE=live`, and use a shell EXIT trap to restore backend/responder to `disabled`; never persist that mode in `.env`. No production workload is an acceptance target.

For this plan's new commands below, **NEW** means the executor must create that entry point/test in the stated step; it is not an existing capability. Artifacts go under ignored `artifacts/` paths and contain no secrets.

## Scope

In scope: backend new `notifications.py`, `notification_worker.py`, `health_metrics.py`, model/schema/config changes and additive migrations; telemetry/collector metrics and byte/age-aware spool reporting; scanner/responder health metrics; Falco metrics configuration; `scripts/incident_alerts.py` as a compatibility consumer; new release/restore/load verifiers, `scripts/tests/`, `experiments/benchmarks/`, `.github/workflows/` (new), dependency lock/constraints artifacts, service Dockerfiles, and `docs/operations/`. Add `compose.lab.yaml` for isolated multi-node lab services if needed. No broker, Kubernetes deployment, SaaS tenancy, broad UI redesign or production data deletion.

## Service-level objectives to test, not claims already achieved

First declare the benchmark host CPU/RAM/kernel/disk, selected rules and workload. Separate all observed kernel syscalls, Falco-matching events and backend-persisted records. Initial engineering target: three isolated Linux nodes feeding one control plane; 100 selected events/second/node sustained for 60 minutes, then a 5x 60-second burst, no unexplained loss between measured boundaries, p95 receipt-to-assessment under 10 seconds after the fixed window closes, and a 30-minute control-plane outage recovered without duplicate logical results. These are proposed lab targets, not a capacity guarantee. Scale the load upward to find a measured saturation point; if resources cannot support the target, record the actual limit and bottleneck before changing architecture.

Measure sensor CPU/RSS, workload throughput/latency delta against monitoring-disabled controls, database connections/query timing, spool bytes/oldest age, disk growth and end-to-end delay. Store all trials, including failures. A lower alert rate is not a performance improvement if events were dropped.

## Steps

### 1. Make sensor and processing coverage visible

Enable version-compatible Falco metrics/drop reporting and ingest a separate health stream, not fake process evidence. Export bounded-cardinality counters/gauges for read/spooled/delivered/persisted counts, kernel drop deltas, queue bytes/age, dead letters, clock skew, reconciliation lag, assessment lag and worker claims. Boot/counter reset must be represented. No PID/container/command line as unbounded metric labels. Propagate coverage state into assessments from plan 002.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_health_coverage.py -q`, telemetry/collector focused tests and pinned Falco validation → reset/drop/outage cases report degraded/unknown, never clean. `GET /metrics` or the selected internal metrics endpoint must expose only the documented schema and no secret values.

Use the official [Falco metrics documentation](https://falco.org/docs/concepts/metrics/) and [drop troubleshooting](https://falco.org/docs/troubleshooting/dropping/) for the installed version. File-to-database equality does not establish kernel-to-file completeness.

### 2. Persist incident notifications in the incident transaction

Add an outbox row atomically with incident creation or a material severity transition, keyed by incident plus transition/revision plus destination. A worker claims and retries it with backoff, jitter, bounded attempts, dead-letter status and stable delivery ID. Start with one generic JSON webhook and local test sink; HMAC-sign timestamp plus exact payload bytes. Destination URLs come from authorized configuration, never telemetry. Enforce configured egress policy and explicit timeouts; redact destination credentials. The receiver must deduplicate the stable ID because a crash after successful delivery but before acknowledgement can cause redelivery. Do not promise exactly-once external delivery.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_notification_outbox.py -q` → transaction rollback produces no outgoing message, duplicate revisions enqueue once, restart retries, crash-after-delivery redelivers the same ID, secret fields absent. **NEW** `python3 scripts/verify_notifications.py --local-sink` → no external messages sent, signature/retry/dead-letter assertions pass. Preserve existing SMTP CLI functionality until migration is documented.

### 3. Add restore and upgrade drills

Create runbooks and scripts that back up PostgreSQL plus policy/profile/model artifacts and record compatibility hashes. Verify a restore into a **new** Compose project/volume, never the current database. Include response receipt volumes in the recovery design; unresolved intents need operator review, not assumed re-execution. Test additive database upgrade with recorded data, immutable policy hashes and rollback constraints. State an initial tested RPO/RTO target before the drill; report measured recovery time and actual evidence coverage.

Verify: **NEW** `python3 scripts/verify_restore.py --disposable` → restored row counts and selected hashes match, permissions persist, raw secrets never enter reports, and the original database/volumes are unchanged. The verifier must refuse the active project name or active volume names as restore destinations.

### 4. Build an isolated capacity/failure harness

Add `experiments/benchmarks/run.py` with explicit scenario/seed/rate/duration/output options and a fixed fixture matrix. Exercise exec plus each supported kernel family, backend/adapter outages, disk-full/backpressure, database restart and slow notification sinks. Use independent node identities and authenticated host bindings. Record observed boundaries, not a claimed global denominator for unobservable syscalls. Dead letters and rejected inputs count separately from legitimate capture loss.

Verify: **NEW** `python3 -m experiments.benchmarks.run --help` → exit 0; **NEW** `python3 -m pytest experiments/tests/test_benchmark_contract.py -q` → missing loss boundaries or hardware metadata fail validation. A real run under a new run ID must produce a self-validating report with every target marked pass/fail/unknown. Decide on a broker only if repeated measurements show the existing durable store cannot meet the declared envelope after query/batch work.

### 5. Establish reproducible CI and release artifacts

Add hash-pinned direct/transitive dependency constraints or lockfiles per service, and make Docker builds consume them. Keep a documented update workflow; do not pin stale libraries blindly. Add CI stages for static checks, five service suites, PostgreSQL integration/migrations, protocol integrity, schema compatibility, secret scanning, dependency advisories and image SBOM generation. Live eBPF/containment jobs run on an isolated privileged runner, never untrusted pull-request code with repository secrets. Release images bind source SHA, dependency/image digests and SBOM/provenance manifests. Document supported Linux/kernel/Docker combinations from tested data.

Verify: **NEW** `python3 scripts/check_release_manifest.py --manifest "$PORYGON_RELEASE_MANIFEST"` → source, dependency and image references resolve and match. Build twice in a clean environment and compare locked dependency graphs and declared metadata; do not claim bit-for-bit image reproducibility unless measured. Complete the full baseline, then a seven-day unattended observe-only soak with a daily canary and gap accounting.

## Test plan and exemplar

Follow mixed outbox tests in `telemetry/tests/test_kernel_channels.py`, existing atomic spool tests, PostgreSQL fixture isolation and `scripts/verification_api.py` transport patterns. Test notification receiver duplicates/signatures/time skew; queue byte limits; monotonic counter resets; source loss versus downstream retries; restore with unknown response intent; migration of an existing evidence database. Unit tests must never contact a real webhook, SMTP provider or external account.

## Done criteria

- [ ] A failed sensor or dropped-event interval becomes visible within two heartbeat periods and appears in affected assessment coverage.
- [ ] A transactional notification can survive outage/restart with stable IDs and no silent disappearance; dead letters are visible.
- [ ] A disposable restore drill proves selected evidence/profile/policy hashes and records RPO/RTO.
- [ ] The declared three-node lab envelope and saturation experiment have validated raw measurements; seven-day soak accounts for gaps.
- [ ] CI verifies pinned dependencies, migrations and safe boundaries; release manifest verifier passes.
- [ ] Full rebuilt-container/acceptance verification passes with no shared-workspace interference.

## STOP conditions

Stop if a benchmark or restore script targets active user data, if metrics require unbounded sensitive labels, or if a notification test would send externally. Stop if no trustworthy source denominator exists; label that boundary unknown instead of a zero-loss result. A failed performance target is evidence to investigate, not permission to add NATS/Kafka or adjust reported numbers. Stop on drift, scope creep or repeated verification failure.

## Maintenance notes

Re-run capacity/overhead tests after changing Falco capture rules, especially high-volume write-family capture enabled with `base_syscalls.all=true`. Document notification delivery semantics for every adapter. Restore drills and credential revocation are recurring release exercises. The small lab remains the supported deployment until a separate fleet acceptance matrix passes.
