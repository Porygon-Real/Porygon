# Experiment runtime binding

Real-container pilot, study, and confirmatory collection commands require an explicit `--compose-project` and `--docker-context`. This prevents an experiment command from finding services by a global container name or silently using Compose's default `porygon` project.

Before pulling workload images or creating a run network/container, the runner verifies the selected local Unix-socket Docker context, daemon ID, and one container for each required service in the selected Compose project: backend, collector, Falco, gateway, Postgres, responder, scanner, and telemetry. It checks the Compose project and service labels, the isolated worktree directory and `compose.yaml` label, running state, and health where a service defines a healthcheck. The base API URL must match the selected project's loopback gateway port. Remote Docker contexts and non-loopback API endpoints are refused.

The runner refuses pre-existing trial container or run-network names. Run and environment artifacts bind the Compose project, context, daemon, compose-file digest, gateway endpoint, service container IDs, and image IDs. A resumed pilot must match the saved binding, source fingerprint, run matrix, seed, protocol digest, and pinned workload image identities. Older artifacts without this binding remain unsupported for resume; the runner does not add provenance retroactively.

The private API bridge uses the exact validated backend container ID and Docker context for internal routes. Public API requests use the matching selected loopback gateway. Docker container environment/config values are not inspected or stored by the binding preflight.

For example, after starting the isolated Compose project from this worktree, a small exploratory pilot can be invoked as:

```bash
.venv/bin/python -m experiments.run pilot \
  --compose-project porygon-service-trust \
  --docker-context default \
  --base-url http://127.0.0.1:8000 \
  --workloads WL-NGX-V1 \
  --scenarios SCN-EXEC \
  --variants baseline \
  --replicas 1
```

Use the name of the actual local Docker context and the port reported by that project's gateway. A preflight refusal is a stop condition; do not substitute another project, context, or API endpoint to make the command proceed.

Pilot and study commands remain exploratory and record `research_eligible=false`. This runtime binding does not satisfy the frozen protocol's independent-review, pilot/power-lock, or collection-plan gates. Confirmatory planning and collection require the same explicit project/context and the preauthorized immutable plan.
