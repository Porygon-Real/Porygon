# Continuous detection

Porygon can continuously assess explicitly enrolled containers without manual
score or detection requests. The API and standalone worker share one assessment
service and PostgreSQL work registry. Assessment never approves containment.

## Deployment

Apply migrations with the normal backend entrypoint. Assessment is disabled by
default. Enable the API-owned worker with `PORYGON_ASSESSMENT_ENABLED=true`, or run
a separate worker using the same backend environment and private database:

```bash
docker compose exec -T backend python -m porygon_api.window_worker
```

`--once` processes one bounded tick; `--owner NAME` assigns a diagnostic lease
owner. Multiple workers coordinate through row locks and `SKIP LOCKED`, not a
process-local leader. Each loop closes all sessions before waiting. Do not enable
this until the target/profile workflow below is ready.

| Setting | Default | Meaning |
|---|---:|---|
| `PORYGON_ASSESSMENT_ENABLED` | false | API lifespan worker |
| `PORYGON_ASSESSMENT_POLL_SECONDS` | 2 | Poll interval |
| `PORYGON_ASSESSMENT_JOBS_PER_TICK` | 10 | Scheduling and claim batch bound |
| `PORYGON_ASSESSMENT_LEASE_SECONDS` | 120 | Finite generation lease |
| `PORYGON_ASSESSMENT_MAX_ATTEMPTS` | 5 | Bounded retries |
| `PORYGON_ASSESSMENT_ALLOWED_LATENESS_SECONDS` | 10 | Default initial event-time delay |
| `PORYGON_ASSESSMENT_HEARTBEAT_MAX_AGE_SECONDS` | 60 | Operational heartbeat freshness |

## Target and profile workflow

All writes require an explicit human credential, including in local compatibility
mode. Enrolled roles are enforced by the method/path inventory. Admin enrolls an
exact host/full 64-character container ID with an immutable image digest using
`POST /operator/v1/assessment-targets`:

```json
{
  "docker_host_id": "actual-docker-daemon-id",
  "container_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "image_digest": "example/app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "start_at": "2026-10-26T12:00:00Z",
  "window_seconds": 30,
  "allowed_lateness_seconds": 10
}
```

The timestamp establishes fixed, consecutive `[start,end)` windows. Choose an
observation start after the intended training and shadow intervals. Inventory
must match the exact host, container and digest. A whitelist of normalized
collector security settings is hashed: user, privileges, read-only filesystem,
capabilities, security options, namespace modes and mount identities. Environment,
labels, commands, process IDs, restart counters and changing IPs are excluded.
Missing or malformed security fields remain unknown. Identity/context changes
require a newly reviewed enrollment; they never silently borrow another profile.

An analyst proposes a candidate through
`POST /operator/v1/assessment-targets/{target_id}/profiles`:

```json
{
  "reference": "approved benign workload collection record",
  "intervals": [
    {"name": "known-benign-collection", "label": "benign",
     "start_at": "2026-10-26T10:00:00Z", "end_at": "2026-10-26T10:10:00Z"}
  ],
  "minimum_process_events": 10,
  "minimum_nonempty_windows": 2
}
```

Only named, explicitly benign intervals from that exact target are selected.
Overlapping intervals and contaminated labels are refused. The command-line
feature contract requires at least 80% command evidence. Quality failures remain
visible candidates and cannot be promoted. Scope, interval names, provenance,
feature artifact hash and verified proposer are immutable. Ordinary runtime
observations never become trusted training automatically.

Submit a disjoint completed benign interval to
`POST .../profiles/{enrollment_id}/shadow`. It records the selected evidence hash,
candidate score and current active profile score, when present. It does not
choose a winner. Admin explicitly calls `.../activate`; `.../rollback` restores a
previously approved immutable artifact. Candidate/shadow/active/retired state is
separate from legacy digest-wide profile status. Actual transitions append audit
history; replaying an unchanged activation is a no-op.

## Scheduling and recovery

Targets have durable checkpoints. Scheduling atomically creates unique jobs and
advances the checkpoint. A job identity binds host, full container ID, digest,
security context, profile content hash, scoring and detector/allowlist/custom-rule
configuration, fixed interval and explicit late-data revision. A worker claims a
finite lease generation. Expired work is reclaimable; stale generations cannot
publish results. Failed work uses bounded exponential backoff and attempt limits.

Scoped scoring and detection share one transaction with incident/evidence linkage
and job completion. Errors or lost lease ownership roll everything back. Detector
hashes actually used by evaluation must match the scheduled configuration.
Configuration drift yields explicit unavailable work, requiring an analyst's
reviewed reprocess request. It never silently changes a result under an old key.

Each scoped score records its exact selected event IDs. Later manual detection
uses that frozen selection, and refuses missing retained evidence. Late arrivals
do not mutate an existing result. Request a new revision through
`POST /operator/v1/assessment-targets/{target_id}/reprocess`:

```json
{"window_start":"2026-10-26T12:00:00Z","revision":1,"reason":"reviewed late evidence"}
```

The original window must actually have been scheduled. Revisions advance by one;
replaying the same revision returns the same job. Retention overtaking a window
makes it unavailable rather than retrospectively clean.

## Coverage and visibility

Source-drop completeness is **unknown**. A recent heartbeat does not establish
historical event completeness. Missing/stale collector or telemetry heartbeats,
missing security fields, empty process observations and changed/unprofiled images
are explicit. Findings can coexist with degraded coverage. No state means
"proven benign". Kernel event counts remain visible for otherwise idle windows;
they do not extend the frozen statistical model or manufacture process evidence.

Bounded read APIs:

- `GET /api/v1/assessment-targets`
- `GET /api/v1/assessment-targets/{target_id}/profiles`
- `GET /api/v1/assessment-targets/{target_id}/audit`
- `GET /api/v1/assessment-jobs?target_id=...&limit=100`
- `GET /api/v1/assessment-worker/status`

The dashboard shows worker availability, pending work and unknown coverage.
Admin disables only a chosen target with `POST .../assessment-targets/{id}/disable`.
Evidence is retained; disabling does not delete historical results.

## Controlled acceptance

After rebuilding, use an isolated stack with the API worker disabled and response
execution disabled. The verifier starts and stops its own standalone worker and
creates only labelled disposable canaries:

```bash
python3 scripts/verify_continuous_detection.py
```

For enrolled mode, pass `--operator-token-file /private/admin.token`,
`--sensor-token-file /private/telemetry.token` and the enrolled `--sensor-instance`.
The verifier uses private backend transport, never exposes internal gateway
routes, and never invokes score-compute or detection-run endpoints. It checks
unattended incidents, worker outage/recovery, unique assessment keys, a clearly
labelled synthetic late event plus explicit revision/replay, and unprofiled
coverage. It disables only its own targets and removes only its own canaries;
results remain as auditable evidence under ignored `artifacts/local/`.

PostgreSQL disposable-schema tests exercise multi-worker claims and migration
round-trips. SQLite tests provide fast transaction and deterministic logic checks;
they do not prove PostgreSQL locking. No broker, Kubernetes, automatic profile
learning or automatic containment is part of this lifecycle.
