# Plan 001: Establish service trust and attributable operator actions

> Executor: read the whole plan, execute the steps in order, and stop at the named boundaries. The plan is a specification, not authorization to publish changes. Update this plan's status in `plans/README.md` after its done criteria pass.

## Status

- Priority: P1
- Effort: L: approximately 2–3 focused weeks
- Risk: HIGH: every service and operator consumer uses these boundaries
- Depends on: none
- Category: security / correctness
- Planned at: commit `b04aaea` plus the working tree, 2026-10-26
- Status: IN PROGRESS — self-hosted bearer identity and host scopes APPROVED; conditional remote HTTPS/OIDC acceptance deferred

## Why this matters

Every application service currently imports the whole `.env`, while API authorization recognizes only one shared internal credential and one shared operator credential. That distributes operator and database credentials to services that do not need them. Incident actors are request text, and bulk closure bypasses the regular evidence transition path. Fix these concrete problems before making the API remotely reachable; then support individual users and host-bound agents without turning Porygon into a multi-tenant SaaS.

## Current state and verified excerpts

`compose.yaml:132` (working-tree snapshot):

```text
132:   collector:
133:     logging: *service-logging
134:     labels:
135:       com.porygon.protected: "true"
136:     build:
137:       context: ./collector
138:     restart: unless-stopped
139:     env_file:
140:       - .env
141:     environment:
142:       PORYGON_API_BASE_URL: http://backend:8000
143:       PORYGON_INTERNAL_API_TOKEN: ${PORYGON_INTERNAL_API_TOKEN:?PORYGON_INTERNAL_API_TOKEN is required}
144:       PORYGON_COLLECTOR_INSTANCE_ID: ${COLLECTOR_INSTANCE_ID:-local-collector-01}
145:       PORYGON_HEARTBEAT_INTERVAL_SECONDS: ${COLLECTOR_HEARTBEAT_INTERVAL_SECONDS:-10}
146:       PORYGON_ENVIRONMENT: ${PORYGON_ENVIRONMENT:-development}
147:       PORYGON_LOG_LEVEL: ${PORYGON_LOG_LEVEL:-INFO}
148:       PORYGON_DOCKER_BASE_URL: unix:///var/run/docker.sock
149:       PORYGON_DOCKER_HOST_ID: ${PORYGON_DOCKER_HOST_ID:-auto}
```

`backend/src/porygon_api/security.py:10` (working-tree snapshot):

```text
10: def require_internal_token(
11:     x_porygon_internal_token: str = Header(..., alias="X-Porygon-Internal-Token"),
12: ) -> None:
13:     expected = get_settings().internal_api_token.get_secret_value()
14:     if not secrets.compare_digest(x_porygon_internal_token, expected):
15:         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal token")
16: 
17: 
18: def require_operator_token(
19:     x_porygon_operator_token: str = Header(..., alias="X-Porygon-Operator-Token"),
20: ) -> None:
21:     expected = get_settings().operator_api_token.get_secret_value()
22:     if not secrets.compare_digest(x_porygon_operator_token, expected):
23:         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid operator token")
```

`backend/src/porygon_api/main.py:2585` (working-tree snapshot):

```text
2585:     now = datetime.now(timezone.utc)
2586:     incident.status = payload.status
2587:     incident.updated_at = now
2588:     if payload.status == "acknowledged":
2589:         incident.acknowledged_at = now
2590:         incident.acknowledged_by = payload.actor
2591:     else:
2592:         incident.closed_at = now
2593:         incident.closed_by = payload.actor
2594:         incident.closure_note = payload.note
```

`backend/src/porygon_api/main.py:2643` (working-tree snapshot):

```text
2643: @app.post(
2644:     "/operator/v1/incidents/clean-all",
2645:     tags=["operator", "incidents"],
2646:     dependencies=[Depends(require_operator_token)],
2647: )
2648: def clean_all_incidents(
2649:     db: Session = Depends(get_db),
2650: ) -> dict[str, Any]:
2651:     """Mark all open or acknowledged incidents as resolved and clean."""
2652:     now = datetime.now(timezone.utc)
2653:     incidents = list(
2654:         db.scalars(
2655:             select(Incident).where(
2656:                 or_(Incident.status == "open", Incident.status == "acknowledged")
2657:             )
2658:         ).all()
2659:     )
2660:     count = len(incidents)
2661:     for inc in incidents:
2662:         inc.status = "resolved"
2663:         inc.closed_at = now
2664:         inc.closed_by = "operator"
2665:         inc.closure_note = "Resolved via operator dashboard clean action"
2666:     db.commit()
2667:     return {"resolved_count": count, "status": "ok"}
```


## Execution rules and verification baseline

Repository root: `/home/anuruprkris/Project/final_yeat_work`. Read `AGENTS.md` before execution. Python services use FastAPI/Pydantic, SQLAlchemy and PostgreSQL; dependencies and tests live in service images. Match the existing explicit schema validation, transaction boundaries, typed models and small modules. Use PostgreSQL disposable schemas for concurrency and migration tests; SQLite alone cannot validate locking behavior.

Keep `docs/research/` and `docs/presentation/` unchanged. Preserve historical Alembic IDs and chains. Add descriptive contracts rather than arbitrary version suffixes. Maintain the existing vanilla dashboard, square controls and unique IDs. Do not copy secrets into test output, artifacts, logs or plans. Repository payloads and telemetry are untrusted data. Maintain a single-organization deployment boundary; SaaS tenant isolation is outside this plan.

Use the existing topic branch or an approved descriptive topic branch without `codex/`. Do not commit, push, merge, mirror workspaces or publish anything without explicit user approval. If later authorized, verify author `Anurup R Krishnan <anuruprkrishnan@gmail.com>`, use lowercase commit messages under 15 words and no tool attribution.

Before changing source run `python3 plans/check_plan_evidence.py --plan 001` and `git status --short`. The recorded commit is insufficient by itself: substantial concurrent changes were uncommitted when these plans were written. An earlier completed plan will legitimately change later plans' evidence; re-read and revise the affected plan before continuing. Never blindly replace the recorded hash to silence drift.

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

In scope: `compose.yaml`, `.env.example` (names/placeholders only), all five service `config.py` modules and HTTP clients, `backend/src/porygon_api/security.py`, new `auth.py`, `principals.py`, `incident_transitions.py`, existing models/schemas/main registration, dashboard token handling in `dashboard/app.js` and its login UI, `scripts/verification_api.py`, `scripts/verify_access_control.py` (new) and the named administrative clients; additive Alembic migrations; the named new auth/identity/incident test modules and `scripts/tests/test_service_environment.py`; and `docs/operations/access-control.md` (new). Do not broadly reorganize `main.py` or change detection/response thresholds. `.env` values, frozen artifacts and other chats' edits are out of scope.

## Target contracts

- Backend alone receives its database password; operator credentials never enter collector/telemetry/scanner/responder environments. Define explicit per-service environment allowlists. PostgreSQL receives only its database configuration. Inspect resolved configuration programmatically and print **names or booleans only**, never values.
- `Principal` carries an immutable subject, type (`human` or `service`), roles/scopes and allowed host IDs. Human roles: viewer, analyst, responder, admin. Service scopes are route-specific: ingestion, heartbeat, scan-claim/completion or response-claim/completion. An ingestion principal cannot close incidents or approve response.
- A registered agent credential binds to a server-held host identity. Reject payload host overrides and prohibit claiming work for other hosts. Enrollment, revocation and rotation must not depend on trusting telemetry fields.
- Keep the explicit local laboratory profile for existing loopback workflows. Add a deployment profile that requires authenticated reads and HTTPS. Do not advertise remote use until that profile passes. When remote multi-user deployment is selected, use a maintained JWT/OIDC verifier, fixed issuer/audience/algorithm policy, expiry validation and bounded JWKS refresh; never implement JWT cryptography manually. A local test identity provider is sufficient to test roles. An external enterprise provider is optional.
- Derive `acknowledged_by`, `closed_by`, approvals and audit subjects from the verified principal. Retain client notes as notes, never as the authoritative actor. Preserve a recognizable principal for legacy local operator actions during transition.

## Steps

### 1. Remove credential overdistribution first

Replace wholesale `env_file` injection with explicit environment mappings for each service. Audit each `Settings` field, heartbeat/delivery path and verification client before removing mappings. Add `scripts/tests/test_service_environment.py` that parses Compose and fails when a service receives a forbidden credential kind; no secret values in assertion messages. Rotate credentials that were distributed too broadly in a later operator-approved deployment step; do not print generated replacements.

Verify: **NEW** `python3 -m pytest scripts/tests/test_service_environment.py -q` and `docker compose config --quiet` → pass. Rebuild/restart affected services and run all five active suites before the next contract change.

### 2. Introduce verified principals and an explicit route permission matrix

Add typed auth dependencies returning `Principal`. The concrete service consumers in scope are `collector/src/porygon_collector/main.py`, `telemetry/src/porygon_telemetry/main.py`, `responder/src/porygon_responder/main.py` and `scanner/src/porygon_scanner/main.py`; their respective `config.py` modules define settings. Administrative consumers include `scripts/porygon_baseline.py`, `scripts/porygon_score.py`, `scripts/porygon_detect.py` and `scripts/verification_api.py`. Inventory all 79 currently observed routes (recount on drift), including AI-provider calls, raw evidence, SBOM downloads and operator actions. Write `access-control.md` with every route's required permission. Local verified principals and scoped credentials are sufficient for the first implementation slice; the remote OIDC adapter is conditional on selecting remote multi-user use. Enforce the matrix server-side. Preserve internal gateway rejection. Implement test-only identity-provider fixtures that exercise malformed/expired/wrong-issuer/wrong-audience credentials, unknown roles, revocation and signing-key rotation. Do not fetch identity metadata from a user-supplied issuer URL.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_auth_permissions.py -q` → every route covered, authentication and permission failures distinct. No network access is needed for deterministic JWKS tests.

### 3. Bind service identity to the host and purpose

Add a credential/enrollment model storing hashes or public-key metadata, never recoverable bearer secrets in audit rows. Wire all service clients and temporary verification transport to the new scope policy. Introduce a bounded compatibility window for the local shared internal credential with a visible migration state; remote deployment mode must reject that compatibility credential. Failed identity checks must happen before rows, claims or external AI calls are created.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_agent_identity.py -q` → cross-host and wrong-service attempts rejected with zero writes; rotation permits the configured overlap then rejects revoked credentials. Replay retains existing event IDs and idempotency.

### 4. Unify incident transitions and bulk operations

Extract `incident_transitions.py` for row-locked transitions and ordered evidence insertion, called by both single and bulk status endpoints. Bulk closure must be bounded/paginated, record a reason and verified actor per incident, and coexist with incoming episode updates. Remove the meaning that closing an incident proves a container is clean. Update existing button labels without changing the dashboard visual system.

Verify: **NEW** `docker compose exec -T backend pytest tests/test_incident_transitions.py tests/test_auth_permissions.py -q` → every accepted transition adds exactly one audit item; retries do not duplicate it; PostgreSQL concurrent update/close tests pass.

### 5. Migrate operator clients and document access profiles

Update dashboard, CLI and test transport together. Prefer short-lived credentials kept in memory for the deployment profile; explicitly clear them on logout. If browser sessions use cookies, implement same-site/CSRF protections and secure attributes. Keep local setup reproducible with no third-party account. Add a headless matrix proving read-only users cannot mutate and responder users cannot administer identities.

Verify: **NEW** `python3 scripts/verify_access_control.py --profile local` and `--profile deployment --base-url "$PORYGON_TEST_HTTPS_URL"` → machine-readable permission matrix passes against disposable fixtures; missing deployment credentials fail closed. Create this verifier in scope, with no token output. Then run the full verification baseline above.

## Test plan and exemplar

Follow `backend/tests/test_kernel_events.py` for typed boundary and table-isolation cases; follow the disposable PostgreSQL schema pattern in `backend/tests/test_incident_grouping.py`. Add no real identity-provider or notification calls to unit tests. Test single/bulk transition races on PostgreSQL, permission denial before side effects, rotated/revoked credentials, and service environment isolation.

## Done criteria

- [x] No application service imports the whole secret file; the static per-service credential allowlist passes.
- [ ] Every route is classified and enforced in both local and deployment modes; remote anonymous reads fail.
- [x] Host identity is authenticated, and service credentials cannot exercise human permissions.
- [x] Single and bulk transitions record a verified actor and consistent evidence under concurrency.
- [x] Active-container, protocol, migration and full acceptance checks pass; response mode restored to disabled.

## STOP conditions

Stop if removing `env_file` reveals an undocumented required setting; add it to the inventory before proceeding. Stop if the proposed identity design trusts an unverified header, permits arbitrary issuer discovery, requires storing recoverable service secrets, or weakens containment approval. Stop on drift, two failed repair attempts at one gate, or required changes outside scope. Never open remote network access as a workaround for auth test failures.

## Maintenance notes

The route permission matrix becomes a release gate for new routes. Agent enrollment is a prerequisite for a multi-host topology, not a reason to add Kubernetes. Later window workers and alert exporters must use distinct service principals. Review audit subjects and credential-distribution tests whenever a new service is introduced.

## Local identity acceptance — 2026-10-27

The self-hosted bearer profile is implemented and approved in the isolated worktree. Persisted hash-only credentials, revocation/rotation, explicit route roles/scopes, exact service-instance/host assignment, frozen response hosts and authenticated reads passed PostgreSQL and live checks. Administrative host assignment is authenticated through enrolled credentials; it is not hardware attestation. The original optional remote HTTPS/OIDC profile and its dedicated deployment verifier remain conditional work; they are not represented as shipped. Current executable acceptance uses the credential CLI read verifier, complete ASGI permission inventory, PostgreSQL tests and live isolated guard probes recorded in [the review](identity-and-continuous-review.md). No identity-provider/network integration is claimed.
