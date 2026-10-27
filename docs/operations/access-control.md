# Local access control and incident accountability

Porygon's local deployment uses separate internal-service and operator credentials. Compose passes an explicit environment allowlist to every service. It still reads `.env` for variable substitution, but no service imports the entire file.

## Credential distribution

| Service | Credential kinds received |
|---|---|
| PostgreSQL | PostgreSQL database configuration only |
| Backend | Its database credential, internal and operator API credentials, optional AI-provider credential |
| Collector, telemetry, responder, scanner | Internal service API credential only |
| Gateway, Falco and event-volume initializer | No Porygon API or database credential |

The backend's optional AI model is explicitly mapped. An unset or blank model selects the configured provider's existing default. All service `Settings` fields have explicit Compose mappings; changing a setting requires updating the mapping and its regression test. Runtime inspection checks should print environment key names or booleans only, never resolved credential values.

Removing wholesale injection does not revoke credentials that older service environments already received. Before a real deployment using this configuration, rotate previously overdistributed credentials through the operator's approved secret-management process. Never publish old or replacement values in logs or reports.

## Local compatibility subjects

`require_internal_token` and `require_operator_token` retain constant-time credential comparison and the existing header names. Successful authentication now returns a typed immutable principal:

| Credential | Subject | Kind |
|---|---|---|
| Internal service credential | `local-internal` | service |
| Operator credential | `local-operator` | operator |

These subjects identify shared credentials only in explicit local compatibility mode. Enrolled mode uses individual human roles and separately provisioned service purposes with host and instance assignments, as documented below. It disables the shared compatibility tokens and protects reads. Remote OIDC remains outside this deployment mode.

The public gateway continues to reject `/internal` routes. The operator status endpoints require the operator credential; an internal credential cannot authenticate as an operator. Direct trusted Python calls use the corresponding stable local subject because FastAPI dependencies do not execute for in-process calls.

## Incident transitions

The single status endpoints and the bulk resolution endpoint share the same row-locked transition helper. The authoritative `acknowledged_by`, `closed_by` and evidence actor are derived from the authenticated principal. The legacy request `actor` field remains accepted for request compatibility but does not select the authoritative audit identity.

Accepted lifecycle transitions are:

- open to acknowledged, resolved or dismissed;
- acknowledged to resolved or dismissed;
- an identical requested status is a no-op;
- resolved and dismissed episodes cannot be reopened by a status request.

A successful change updates the incident timestamp and appends one ordered status-change evidence item in the same transaction. The item records previous and new states, verified local subject, principal kind and operator note. A transaction rollback preserves both the original state and its evidence. Repeating the same single-incident target status does not duplicate evidence or change its closure timestamp.

## Bounded bulk resolution

`POST /operator/v1/incidents/clean-all` is retained as the compatibility path. It resolves at most `limit` active incidents per request: default 100, minimum 1, maximum 500. `note` is an optional query parameter with a nonempty default and a maximum of 4,000 characters.

The response retains `resolved_count` and `status`, and adds `more_pending` and `batch_limit`. It counts actual transitions, including zero. Rows locked by another transition are skipped; they can remain pending for a later operator request. The whole selected batch commits atomically. Each resolved incident has its own evidence item and updated timestamp.

The dashboard calls this action **Resolve batch**, reloads server state after success and reports whether another batch remains. It does not mark every visible incident resolved optimistically. A repeated bulk request can select the next remaining batch; unlike retrying an identical single-incident transition, it is deliberately not an idempotency-keyed operation. Clients must not automatically replay an unknown-outcome batch request as though it referred to the same target set.

Resolution records the end of an investigation workflow. It does not certify that a workload is safe, reverse containment, or prove remediation.

## Verification

```sh
python3 -m pytest scripts/tests/test_service_environment.py -q
docker compose config --quiet
docker compose exec -T backend pytest tests/test_auth_permissions.py tests/test_incident_transitions.py -q
```

HTTP tests exercise the actual router/dependency stack and confirm that missing/wrong credentials and invalid batch limits leave incident state and evidence unchanged. Authorized tests verify that a caller-supplied actor cannot override the local principal. PostgreSQL tests must also run with `PORYGON_TEST_POSTGRES=1` against the existing uniquely named disposable-schema fixture to validate row-lock races. Full rebuild, active-container suites and acceptance commands remain required by `AGENTS.md` before an implementation is declared complete.

## Enrolled access mode

`PORYGON_ACCESS_MODE=local` explicitly retains the shared laboratory credentials.
`authenticated` disables those credentials, requires individual human credentials
for reads, raw evidence, OpenAPI and documentation, and permits service credentials
only for their enrolled purpose. Health endpoints remain public. Unknown handlers
are denied until listed in `backend/src/porygon_api/permissions.py`.
Human roles are viewer (reads), analyst (assessment, investigation and external AI),
responder (also containment decisions), and admin (also configuration and enrollment).
Service purposes are collector, telemetry, scanner and responder; each enrollment
binds one instance to one Docker host. These are administrative assignments, not
hardware attestation. Use actual Docker daemon IDs for responder host assignments;
the responder verifies that ID before touching a container.

Provision while still in local mode, using a trusted local terminal:

```bash
python3 scripts/porygon_credentials.py --bootstrap-env .env enroll \
  --subject human:anurup --role admin --output /private/admin.token
python3 scripts/porygon_credentials.py --admin-token-file /private/admin.token enroll \
  --subject service:collector --service collector --instance local-collector-01 \
  --host DOCKER_DAEMON_ID --output /private/collector.token \
  --worker-env /private/collector.env
```

Repeat service enrollment for telemetry, scanner and responder with their configured
instance IDs and distinct output paths. Token files and worker env files are created
exclusively with mode 0600. Secrets are generated locally, submitted once for hashing,
and never returned by the enrollment API. Metadata output contains only fingerprints.
Keep the private files outside the repository. Concatenate the four worker env files
into a new private 0600 file using shell redirection after `umask 077`; never print them.
Launch with both the original deployment env file and the private worker env file:

```bash
docker compose --env-file .env --env-file /private/workers.env \
  -f compose.yaml -f compose.authenticated.yaml up -d --build
```

The overlay requires all four scoped worker inputs without a shared-token fallback.
Enroll before switching; shared legacy worker tokens fail closed in authenticated mode.
The dashboard token control accepts a human token and keeps it in memory for that tab.
Logout or reload clears it. No bearer token belongs in a URL or browser storage.

Use the CLI `list`, `revoke CREDENTIAL_ID`, or
`rotate CREDENTIAL_ID --output /private/replacement.token --overlap-seconds 60`.
Update the corresponding worker env file privately before the overlap expires.
Revocation and expiry are checked on every request. Rotation preserves the stable
subject and bindings; audit authors come from that verified subject, not request fields.
A response target's host is frozen when recommended and copied to its execution;
legacy jobs lacking a host are accessible only through local compatibility.
Remote OIDC and TLS termination are outside this self-hosted bearer access mode.

The complete method/path/action matrix is executable source in
`backend/src/porygon_api/permissions.py`; `test_route_permissions.py` expands
included routers and rejects unclassified routes. CORS preflight is not enabled
for this same-origin dashboard. Trailing-slash requests pass the canonical route's
authorization before redirect. A registry database failure returns 503 rather than
falling back to anonymous or legacy access.

The optional local scenario runner in `scripts/serve_dashboard.py` is disabled in
authenticated mode, including when demo mode is enabled. It is a local laboratory
workflow rather than an enrolled worker purpose.

After switching, verify that authenticated reads succeed while anonymous reads and
OpenAPI are rejected:

```bash
python3 scripts/porygon_credentials.py --admin-token-file /private/admin.token verify
```

This verifier reports only paths, status codes and pass/fail results; it performs
no mutations and prints no credential material. The CLI rejects non-loopback HTTP
origins; remote provisioning requires HTTPS.
