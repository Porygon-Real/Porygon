#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Internal checks use Docker exec; the public gateway intentionally rejects /internal/.
if [[ -z "${PORYGON_VERIFY_BASE_URL:-}" ]]; then
  exec python3 scripts/verification_api.py bash "$0" "$@"
fi

RUN_ID="${PORYGON_VERIFY_RUN_ID:-$(date -u +%Y%m%dt%H%M%Sz)-$$}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ && "$RUN_ID" != *..* ]] \
  || { echo "[FAIL] Verification run identifier is invalid" >&2; exit 2; }
PROBE_NAME="porygon-ingest-${RUN_ID}"
PROBE_NETWORK="porygon-ingest-net-${RUN_ID}"
PROBE_IMAGE="alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
PROBE_EXECUTIONS="${PORYGON_INGEST_EXECUTIONS:-40}"
COLLECTOR_CONSTRAINED=false
LOCAL_ARTIFACT_DIR="artifacts/local"
PROBE_EVENTS_PATH="${LOCAL_ARTIFACT_DIR}/ingest-${RUN_ID}-events.json"
PROBE_EVENTS_AFTER_PATH="${LOCAL_ARTIFACT_DIR}/ingest-${RUN_ID}-events-after.json"
DAEMON_EVENTS_PATH="${LOCAL_ARTIFACT_DIR}/ingest-${RUN_ID}-docker-events.jsonl"
EVIDENCE_DIR="${LOCAL_ARTIFACT_DIR}/ingest-${RUN_ID}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cleanup_all() {
  docker rm -f "$PROBE_NAME" >/dev/null 2>&1 || true
  docker network rm "$PROBE_NETWORK" >/dev/null 2>&1 || true
  rm -f "$PROBE_EVENTS_PATH" "$PROBE_EVENTS_AFTER_PATH" "$DAEMON_EVENTS_PATH"
  if [[ "$COLLECTOR_CONSTRAINED" == true ]]; then
    docker compose up --detach backend >/dev/null 2>&1 || true
    docker compose up --detach --no-deps --force-recreate collector >/dev/null 2>&1 || true
  fi
}
trap cleanup_all EXIT

[[ -f .env ]] || fail ".env is missing. Run: cp .env.example .env, then replace the placeholder secrets."
if grep -q 'replace-with-' .env; then
  fail ".env still contains placeholder secrets. Replace them before verification."
fi

for command in docker curl python3 stat; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is not installed"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is not available"

socket_path="$(grep -E '^DOCKER_SOCKET_PATH=' .env | tail -1 | cut -d= -f2- || true)"
socket_path="${socket_path:-/var/run/docker.sock}"
[[ -S "$socket_path" ]] || fail "Docker socket not found at $socket_path"

configured_gid="$(grep -E '^DOCKER_GID=' .env | tail -1 | cut -d= -f2- || true)"
actual_gid="$(stat -c '%g' "$socket_path")"
[[ -n "$configured_gid" ]] || fail "DOCKER_GID is missing from .env. Set it to: $actual_gid"
[[ "$configured_gid" == "$actual_gid" ]] || fail "DOCKER_GID=$configured_gid does not match socket GID $actual_gid"

cleanup_all
umask 077
mkdir -p artifacts
mkdir -p "$LOCAL_ARTIFACT_DIR"
mkdir -p "$EVIDENCE_DIR"

docker compose config --quiet
pass "Compose configuration is valid"

# A caller may prebuild images separately (for example with a local build network).
build_options=()
if [[ "${PORYGON_VERIFY_BUILD:-true}" == "true" ]]; then
  build_options+=(--build)
fi
docker compose up --detach "${build_options[@]}" --wait
pass "PostgreSQL, backend, and Docker collector reached healthy state"

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="${PORYGON_VERIFY_BASE_URL:-http://127.0.0.1:${backend_port}}"

collector_host_id="${PORYGON_DOCKER_HOST_ID:-$(grep -E '^PORYGON_DOCKER_HOST_ID=' .env | tail -1 | cut -d= -f2- || true)}"
if [[ -z "$collector_host_id" || "$collector_host_id" == "auto" ]]; then
  collector_host_id="$(docker info --format '{{.ID}}')"
fi
collector_instance_id="${COLLECTOR_INSTANCE_ID:-$(grep -E '^COLLECTOR_INSTANCE_ID=' .env | tail -1 | cut -d= -f2- || true)}"
collector_instance_id="${collector_instance_id:-local-collector-01}"
delivery_retry_max="${PORYGON_DELIVERY_RETRY_MAX_SECONDS:-$(grep -E '^PORYGON_DELIVERY_RETRY_MAX_SECONDS=' .env | tail -1 | cut -d= -f2- || true)}"
delivery_retry_max="${delivery_retry_max:-60}"
heartbeat_interval="${COLLECTOR_HEARTBEAT_INTERVAL_SECONDS:-$(grep -E '^COLLECTOR_HEARTBEAT_INTERVAL_SECONDS=' .env | tail -1 | cut -d= -f2- || true)}"
heartbeat_interval="${heartbeat_interval:-10}"
[[ "$delivery_retry_max" =~ ^[0-9]+$ && "$heartbeat_interval" =~ ^[0-9]+$ ]] || fail "Collector retry and heartbeat intervals must be numeric"
outbox_drain_timeout="$((delivery_retry_max + 2 * heartbeat_interval + 5))"

collector_queue_depth() {
  local services_json
  services_json="$(curl --fail --silent --show-error "${base_url}/api/v1/services")"
  SERVICES_JSON="$services_json" \
  EXPECTED_DOCKER_HOST_ID="$collector_host_id" \
  EXPECTED_COLLECTOR_INSTANCE_ID="$collector_instance_id" \
  HEARTBEAT_MAX_AGE="$((heartbeat_interval * 3))" \
    python3 - <<'PY'
import json, os, sys
from datetime import datetime, timezone

try:
    services=json.loads(os.environ['SERVICES_JSON'])
    matches=[row for row in services
        if row.get('service_name')=='collector'
        and row.get('instance_id')==os.environ['EXPECTED_COLLECTOR_INSTANCE_ID']
        and row.get('docker_host_id')==os.environ['EXPECTED_DOCKER_HOST_ID']
        and (row.get('service_metadata') or {}).get('capability')=='event-ingestion']
    if len(matches)!=1 or matches[0].get('status')!='healthy':
        raise ValueError
    observed=datetime.fromisoformat(matches[0]['last_seen_at']).astimezone(timezone.utc)
    age=(datetime.now(timezone.utc)-observed).total_seconds()
    if age < 0 or age > int(os.environ['HEARTBEAT_MAX_AGE']):
        raise ValueError
    depth=matches[0]['service_metadata'].get('queue_depth')
    if type(depth) is not int or depth < 0:
        raise ValueError
    delta=observed-datetime(1970, 1, 1, tzinfo=timezone.utc)
    observed_ns=((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
    print(f'{depth} {observed_ns}')
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    print('-1 -1')
PY
}

wait_for_empty_outbox() {
  local stage="$1" depth="-1" observed_ns="-1" snapshot
  local wait_started_ns="$(date +%s%N)" deadline=$((SECONDS + outbox_drain_timeout))
  while (( SECONDS < deadline )); do
    snapshot="$(collector_queue_depth)"
    read -r depth observed_ns <<< "$snapshot"
    if [[ "$depth" == "0" && "$observed_ns" =~ ^[0-9]+$ ]] \
      && (( observed_ns >= wait_started_ns )); then
      FINAL_QUEUE_DEPTH="$depth"
      FINAL_QUEUE_OBSERVED_AT_NS="$observed_ns"
      pass "Collector reported a fresh empty outbox ${stage}"
      return 0
    fi
    sleep 2
  done
  fail "Collector did not report a fresh empty outbox ${stage} within its retry bound (last host-scoped depth: $depth)"
}

curl --fail --silent --show-error "${base_url}/health/live" >/dev/null
curl --fail --silent --show-error "${base_url}/health/ready" >/dev/null
pass "Backend liveness and database readiness checks passed"

collector_uid="$(docker compose exec -T collector id -u </dev/null | tr -d '\r')"
[[ "$collector_uid" != "0" ]] || fail "Collector is running as root"

backend_mounts="$(docker inspect "$(docker compose ps -q backend)" --format '{{json .Mounts}}')"
if [[ "$backend_mounts" == *"docker.sock"* ]]; then
  fail "Backend must not have Docker socket access"
fi
collector_mounts="$(docker inspect "$(docker compose ps -q collector)" --format '{{json .Mounts}}')"
[[ "$collector_mounts" == *"docker.sock"* ]] || fail "Collector Docker socket mount is missing"
pass "Docker access is isolated to the non-root collector service"

# Preserve a clean spool before lowering the cap; stale rows survive container recreation.
wait_for_empty_outbox "before lowering the spool cap"

PORYGON_SPOOL_MAX_EVENTS=100 docker compose up \
  --detach --no-deps --force-recreate --wait collector >/dev/null
COLLECTOR_CONSTRAINED=true
configured_spool_limit="$(docker compose exec -T collector python - <<'PY'
from porygon_collector.config import get_settings
print(get_settings().spool_max_events)
PY
)"
configured_spool_limit="$(echo "$configured_spool_limit" | tr -d '\r' | tail -1)"
[[ "$configured_spool_limit" == "100" ]] || fail "Collector spool limit was not constrained to 100"
pass "Collector spool was temporarily constrained to 100 events"
wait_for_empty_outbox "after collector recreation"

docker image inspect "$PROBE_IMAGE" >/dev/null 2>&1 || docker pull "$PROBE_IMAGE" >/dev/null
expected_repo_digest="$(docker image inspect "$PROBE_IMAGE" --format '{{index .RepoDigests 0}}')"
[[ "$expected_repo_digest" == *@sha256:* ]] || fail "Could not resolve a repository digest for $PROBE_IMAGE"
pass "Pulled probe image has immutable repository digest $expected_repo_digest"

docker network create "$PROBE_NETWORK" >/dev/null

# Force an ingestion outage. Events generated below must survive in the collector's SQLite outbox.
overflow_before="$(docker compose exec -T collector python - <<'PY'
import json, urllib.request
print(json.load(urllib.request.urlopen('http://127.0.0.1:8001/status'))['spool_overflow_count'])
PY
)"
overflow_before="$(echo "$overflow_before" | tr -d '\r' | tail -1)"
[[ "$overflow_before" =~ ^[0-9]+$ ]] || fail "Could not read pre-run overflow count"
run_started_epoch="$(date +%s)"
docker compose stop backend >/dev/null

docker create \
  --name "$PROBE_NAME" \
  --label io.porygon.ingest.probe=true \
  --label "io.porygon.ingest.run=${RUN_ID}" \
  "$PROBE_IMAGE" sleep 300 >/dev/null
full_container_id="$(docker inspect "$PROBE_NAME" --format '{{.Id}}')"
docker start "$PROBE_NAME" >/dev/null
for execution in $(seq 1 "$PROBE_EXECUTIONS"); do
  docker exec "$PROBE_NAME" sh -c "echo porygon-ingest-${RUN_ID}-${execution}" >/dev/null
done
docker network connect "$PROBE_NETWORK" "$PROBE_NAME"
docker network disconnect "$PROBE_NETWORK" "$PROBE_NAME"
docker stop --time 2 "$PROBE_NAME" >/dev/null
docker rm "$PROBE_NAME" >/dev/null
run_finished_epoch="$(date +%s)"

docker events \
  --since "$run_started_epoch" \
  --until "$((run_finished_epoch + 1))" \
  --format '{{json .}}' > "$DAEMON_EVENTS_PATH"
daemon_metrics="$(DAEMON_EVENTS_PATH="$DAEMON_EVENTS_PATH" PROBE_NAME="$PROBE_NAME" FULL_CONTAINER_ID="$full_container_id" python3 - <<'PY'
import json, os
with open(os.environ['DAEMON_EVENTS_PATH'], encoding='utf-8') as handle:
    observed=[json.loads(line) for line in handle if line.strip()]
events=[]
for event in observed:
    actor=event.get('Actor') or {}
    attributes=actor.get('Attributes') or {}
    is_container=(
        event.get('Type') == 'container'
        and attributes.get('name') == os.environ['PROBE_NAME']
    )
    is_network=(
        event.get('Type') == 'network'
        and attributes.get('container') == os.environ['FULL_CONTAINER_ID']
    )
    if is_container or is_network:
        events.append(event)
actions=[str(event.get('Action') or '').split(':', 1)[0] for event in events]
print(json.dumps({'count': len(events), 'actions': sorted(set(actions))}, separators=(',', ':')))
PY
)"
daemon_event_count="$(DAEMON_METRICS="$daemon_metrics" python3 - <<'PY'
import json, os
print(json.loads(os.environ['DAEMON_METRICS'])['count'])
PY
)"
(( daemon_event_count > 100 )) || fail "Canary produced only $daemon_event_count Docker events; saturation was not exercised"

spool_metrics=""
for _ in $(seq 1 45); do
spool_metrics="$(docker compose exec -T -e PROBE_NAME="$PROBE_NAME" -e EXPECTED_DOCKER_HOST_ID="$collector_host_id" collector python - <<'PY'
import json, os, sqlite3, urllib.request
connection=sqlite3.connect('/var/lib/porygon/outbox.db')
rows=connection.execute('SELECT payload FROM outbox').fetchall()
payloads=[json.loads(row[0]) for row in rows]
probe=[item for item in payloads if item.get('container_name') == os.environ['PROBE_NAME']
       and item.get('docker_host_id') == os.environ['EXPECTED_DOCKER_HOST_ID']]
status=json.load(urllib.request.urlopen('http://127.0.0.1:8001/status',timeout=3))
print(json.dumps({
    'outbox_count': len(payloads),
    'canary_count': len(probe),
    'spool_overflow_count': status['spool_overflow_count'],
    'docker_host_id': status['docker_host_id'],
}, separators=(',', ':')))
PY
)"
  spooled_count="$(SPOOL_METRICS="$spool_metrics" python3 - <<'PY'
import json, os
print(json.loads(os.environ['SPOOL_METRICS'])['outbox_count'])
PY
)"
  [[ "$spooled_count" == "100" ]] && break
  sleep 1
done
canary_spooled_count="$(SPOOL_METRICS="$spool_metrics" python3 - <<'PY'
import json, os
print(json.loads(os.environ['SPOOL_METRICS'])['canary_count'])
PY
)"

write_saturation_diagnostic() {
  local reason="$1" metrics="${2:-$spool_metrics}"
  umask 077
  SPOOL_METRICS="$metrics" \
  PROBE_EXECUTIONS="$PROBE_EXECUTIONS" \
  PROBE_RUN_ID="$RUN_ID" \
  PROBE_EVENT_COUNT="$daemon_event_count" \
  CONFIGURED_LIMIT="$configured_spool_limit" \
  INITIAL_QUEUE_DEPTH="0" \
  OVERFLOW_BEFORE="$overflow_before" \
  OVERFLOW_AFTER="${overflow_after:-}" \
  OVERFLOW_DELTA="${overflow_delta:-}" \
  REASON="$reason" \
    python3 - <<'PY' > "$EVIDENCE_DIR/saturation-failure.json"
import json, os

try:
    metrics=json.loads(os.environ['SPOOL_METRICS'])
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    metrics={}
document={
    'schema_version':'porygon.ingestion-saturation-diagnostic.v1',
    'run_id':os.environ['PROBE_RUN_ID'],
    'reason':os.environ['REASON'],
    'configured_event_limit':int(os.environ['CONFIGURED_LIMIT']),
    'initial_queue_depth':int(os.environ['INITIAL_QUEUE_DEPTH']),
    'daemon_probe_event_count':int(os.environ['PROBE_EVENT_COUNT']),
    'requested_exec_operations':int(os.environ['PROBE_EXECUTIONS']),
    'observed_outbox_count':metrics.get('outbox_count'),
    'observed_current_run_canary_count':metrics.get('canary_count'),
    'overflow_before':int(os.environ['OVERFLOW_BEFORE']),
    'overflow_after':int(os.environ['OVERFLOW_AFTER']) if os.environ['OVERFLOW_AFTER'] else None,
    'overflow_delta':int(os.environ['OVERFLOW_DELTA']) if os.environ['OVERFLOW_DELTA'] else None,
    'observed_overflow_counter':metrics.get('spool_overflow_count'),
}
print(json.dumps(document,indent=2,sort_keys=True))
PY
}

if [[ "$spooled_count" != "100" ]]; then
  write_saturation_diagnostic "outbox_limit_not_reached"
  fail "Constrained collector outbox did not reach its 100-event limit; sanitized counters saved under $EVIDENCE_DIR"
fi
if ! [[ "$canary_spooled_count" =~ ^[0-9]+$ ]] || (( canary_spooled_count <= 0 )); then
  write_saturation_diagnostic "current_run_canary_missing"
  fail "Constrained collector outbox reached capacity without current-run host-scoped canaries; sanitized counters saved under $EVIDENCE_DIR"
fi

overflow_after="$(docker compose exec -T collector python - <<'PY'
import json, urllib.request
print(json.load(urllib.request.urlopen('http://127.0.0.1:8001/status'))['spool_overflow_count'])
PY
)"
overflow_after="$(echo "$overflow_after" | tr -d '\r' | tail -1)"
[[ "$overflow_after" =~ ^[0-9]+$ ]] || fail "Could not read post-run overflow count"
overflow_delta="$((overflow_after - overflow_before))"
if (( overflow_delta <= 0 )); then
  write_saturation_diagnostic "overflow_counter_did_not_increase"
  fail "Collector reached its limit without recording saturation; sanitized counters saved under $EVIDENCE_DIR"
fi
python3 scripts/verification_receipts.py write \
  --stage saturation \
  --run-id "$RUN_ID" \
  --host-id "$collector_host_id" \
  --directory "$EVIDENCE_DIR" \
  --field "configured_event_limit=$configured_spool_limit" \
  --field "observed_outbox_count=$spooled_count" \
  --field "current_run_canary_count=$canary_spooled_count" \
  --field "overflow_before=$overflow_before" \
  --field "overflow_after=$overflow_after" \
  --field "overflow_delta=$overflow_delta" \
  --field "docker_api_event_count=$daemon_event_count" \
  --field "requested_exec_operations=$PROBE_EXECUTIONS" \
  --field "initial_queue_depth=0" >/dev/null
pass "Collector recorded saturation and retained exactly 100 queued events without advancing past failures"

docker compose up --detach --wait backend >/dev/null

for _ in $(seq 1 90); do
  curl --fail --silent --show-error --get \
    --data-urlencode "container_name=${PROBE_NAME}" \
  --data-urlencode "docker_host_id=${collector_host_id}" \
    --data-urlencode "limit=500" \
    --output "$PROBE_EVENTS_PATH" \
    "${base_url}/api/v1/events" || true
  if PROBE_EVENTS_PATH="$PROBE_EVENTS_PATH" EXPECTED_DIGEST="$expected_repo_digest" RUN_ID="$RUN_ID" EXPECTED_DOCKER_HOST_ID="$collector_host_id" python3 - <<'PY'
import json, os, sys
try:
    with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
        events = json.load(handle)
except Exception:
    sys.exit(1)
actions = {event.get('action') for event in events}
required = {'create', 'start', 'exec_create', 'exec_start', 'die', 'destroy', 'connect', 'disconnect'}
if not required.issubset(actions):
    sys.exit(1)
expected = os.environ['EXPECTED_DIGEST']
container_events = [e for e in events if e.get('container_id')]
if not container_events or any(e.get('image_digest') != expected for e in container_events):
    sys.exit(1)
if any(e.get('docker_host_id') != os.environ['EXPECTED_DOCKER_HOST_ID'] for e in events):
    sys.exit(1)
if len({e['event_id'] for e in events}) != len(events):
    sys.exit(1)
if not all(isinstance(e.get('raw_event'), dict) for e in events):
    sys.exit(1)
if not any(os.environ['RUN_ID'] in (e.get('command') or '') for e in events):
    sys.exit(1)
PY
  then
    break
  fi
  sleep 2
done

PROBE_EVENTS_PATH="$PROBE_EVENTS_PATH" EXPECTED_DIGEST="$expected_repo_digest" RUN_ID="$RUN_ID" EXPECTED_DOCKER_HOST_ID="$collector_host_id" python3 - <<'PY' || fail "Required probe events or digest enrichment were not stored"
import json, os

with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
    events = json.load(handle)
actions = {event.get('action') for event in events}
required = {'create', 'start', 'exec_create', 'exec_start', 'die', 'destroy', 'connect', 'disconnect'}
missing = sorted(required - actions)
assert not missing, f"missing actions: {missing}"
expected = os.environ['EXPECTED_DIGEST']
container_events = [e for e in events if e.get('container_id')]
assert container_events
assert all(e.get('image_digest') == expected for e in container_events)
assert all(e.get('docker_host_id') == os.environ['EXPECTED_DOCKER_HOST_ID'] for e in events)
assert len({e['event_id'] for e in events}) == len(events)
assert all(isinstance(e.get('raw_event'), dict) for e in events)
assert any(os.environ['RUN_ID'] in (e.get('command') or '') for e in events)
print(len(events))
PY
pass "Lifecycle, exec, and network actions were normalized with the correct image digest"

inserted_count="$(PROBE_EVENTS_PATH="$PROBE_EVENTS_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
    print(len(json.load(handle)))
PY
)"
[[ "$inserted_count" == "$daemon_event_count" ]] || fail \
  "Docker exposed $daemon_event_count canary events but PostgreSQL stored $inserted_count"
pass "Every canary event observed at the Docker API boundary reached PostgreSQL exactly once"

count_before="$(PROBE_EVENTS_PATH="$PROBE_EVENTS_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
    print(len(json.load(handle)))
PY
)"

docker compose restart collector >/dev/null
for _ in $(seq 1 60); do
  collector_health="$(docker inspect \
    --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
    "$(docker compose ps -q collector)")"
  [[ "$collector_health" == "healthy" ]] && break
  sleep 1
done
[[ "$collector_health" == "healthy" ]] || fail "Collector did not become healthy after replay restart"
sleep 5

curl --fail --silent --show-error --get \
  --data-urlencode "container_name=${PROBE_NAME}" \
    --data-urlencode "docker_host_id=${collector_host_id}" \
  --data-urlencode "limit=500" \
  --output "$PROBE_EVENTS_AFTER_PATH" \
  "${base_url}/api/v1/events"
count_after="$(PROBE_EVENTS_PATH="$PROBE_EVENTS_AFTER_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
    items=json.load(handle)
assert len({item['event_id'] for item in items}) == len(items)
print(len(items))
PY
)"
[[ "$count_before" == "$count_after" ]] || fail "Event replay changed probe count from $count_before to $count_after"
pass "Collector replay did not duplicate stored events"
replay_row_growth="$((count_after - count_before))"

wait_for_empty_outbox "after backend recovery"

python3 scripts/verification_receipts.py write \
  --stage persistence \
  --run-id "$RUN_ID" \
  --host-id "$collector_host_id" \
  --directory "$EVIDENCE_DIR" \
  --field "api_event_count=$inserted_count" \
  --field "postgres_row_count=$inserted_count" \
  --field "replay_count_before=$count_before" \
  --field "replay_count_after=$count_after" \
  --field "replay_row_growth=$replay_row_growth" \
  --field "final_queue_depth=$FINAL_QUEUE_DEPTH" \
  --field "final_queue_observed_at_ns=$FINAL_QUEUE_OBSERVED_AT_NS" >/dev/null

docker compose up --detach --no-deps --force-recreate --wait collector >/dev/null
COLLECTOR_CONSTRAINED=false
pass "Collector spool limit was restored after the saturation drill"

curl --fail --silent --show-error --get \
  --data-urlencode "container_name=${PROBE_NAME}" \
  --data-urlencode "docker_host_id=${collector_host_id}" \
  "${base_url}/api/v1/events/summary" \
  > "${EVIDENCE_DIR}/probe-summary.json"
cp "$PROBE_EVENTS_AFTER_PATH" "${EVIDENCE_DIR}/probe-events.json"
curl --fail --silent --show-error "${base_url}/api/v1/images" > "${EVIDENCE_DIR}/images.json"
curl --fail --silent --show-error "${base_url}/api/v1/containers" > "${EVIDENCE_DIR}/containers.json"
docker compose ps > "${EVIDENCE_DIR}/services.txt"
docker compose images > "${EVIDENCE_DIR}/images.txt"

python3 scripts/verification_receipts.py validate \
  --run-id "$RUN_ID" \
  --host-id "$collector_host_id" \
  --directory "$EVIDENCE_DIR" >/dev/null || fail "Durable saturation or persistence receipts are missing, stale, or mismatched"

RUN_ID="$RUN_ID" \
PROBE_NAME="$PROBE_NAME" \
PROBE_EXECUTIONS="$PROBE_EXECUTIONS" \
DAEMON_METRICS="$daemon_metrics" \
SPOOL_METRICS="$spool_metrics" \
SPOOL_LIMIT="$configured_spool_limit" \
OVERFLOW_DELTA="$overflow_delta" \
INSERTED_COUNT="$inserted_count" \
REPLAY_ROW_GROWTH="$replay_row_growth" \
python3 - <<'PY'
import json, os
from pathlib import Path
import secrets

daemon=json.loads(os.environ['DAEMON_METRICS'])
spool=json.loads(os.environ['SPOOL_METRICS'])
document={
    'schema_version': 'porygon.capture-integrity.v1',
    'run_id': os.environ['RUN_ID'],
    'canary': {
        'container_name': os.environ['PROBE_NAME'],
        'exec_operations_issued': int(os.environ['PROBE_EXECUTIONS']),
    },
    'boundaries': {
        'docker_api_events_observed': daemon['count'],
        'docker_api_actions_observed': daemon['actions'],
        'collector_spool_limit': int(os.environ['SPOOL_LIMIT']),
        'collector_events_retained_at_saturation': spool['outbox_count'],
        'canary_events_retained_at_saturation': spool['canary_count'],
        'collector_overflow_attempts_observed': int(os.environ['OVERFLOW_DELTA']),
        'postgres_canary_rows_after_recovery': int(os.environ['INSERTED_COUNT']),
        'postgres_row_growth_after_replay': int(os.environ['REPLAY_ROW_GROWTH']),
    },
    'dead_letter': {
        'status': 'not_applicable',
        'count': None,
        'reason': 'The Docker collector has no dead-letter path; schema acceptance is proven by database equality.',
    },
    'unmeasured_boundaries': [
        'Docker daemon loss before publication on the events API',
        'Host failure and Docker history rollover outside this bounded run',
        'Kernel and Falco drops; those belong to the eBPF telemetry measurement path',
    ],
}
target=Path('artifacts/event-ingestion-capture-integrity.json')
temporary=target.with_name(f'.{target.name}.{secrets.token_hex(6)}.tmp')
temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n', encoding='utf-8')
temporary.chmod(0o600)
temporary.replace(target)
PY

printf '\nEvent ingestion verification complete.\n'
