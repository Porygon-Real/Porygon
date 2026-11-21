#!/bin/bash
# Collect batch 2 of the runtime monitoring dataset, unattended, start to finish.
#
#   1. download the native arm64 images (retried, then substituted)
#   2. start the sensor watchdog, which repairs the Falco path and invalidates
#      any run that overlapped a gap
#   3. run the batch 4 images at a time, re-planning after every pass so that a
#      failed or repeated image is replaced from the reserve list and any
#      invalidated run is collected again
#   4. export both batches in one pass, then validate
#
# It never waits for a person: anything it cannot fix is written to
# datasets/runtime/NEEDS_ATTENTION.md and the rest carries on. Start it detached
# so it outlives the shell that launched it:
#
#   nohup caffeinate -i -s scripts/runtime/run_batch2.sh > datasets/runtime/logs/batch2-run.log 2>&1 &

set -u
cd "$(dirname "$0")/../.." || exit 1
ROOT=$PWD
PY=$ROOT/.venv/bin/python
LOGS=$ROOT/datasets/runtime/logs
RUNTIME=$ROOT/datasets/runtime
mkdir -p "$LOGS"
export PORYGON_RT_BATCH=batch2
# These two exist only for smoke tests and recipe checks; a dataset run must use
# the real dataset paths even if the launching shell had them set.
unset PORYGON_RT_RAW_ROOT PORYGON_RT_RUN_LOG
MAX_PASSES=${MAX_PASSES:-4}
PARALLEL=${PARALLEL:-4}

say() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [batch2] $*"; }

log_fix() {  # step, failed, action, result
  "$PY" - "$1" "$2" "$3" "$4" <<'PYEOF'
import sys
sys.path.insert(0, "scripts/runtime")
from rt_common import log_event
log_event(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], batch="batch2")
PYEOF
}

ensure_stack() {
  if ! docker info >/dev/null 2>&1; then
    say "Docker is not responding; starting Docker Desktop"
    open -a Docker
    for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 10; done
    log_fix docker "docker info failed" "started Docker Desktop and waited for the daemon" \
            "$(docker info >/dev/null 2>&1 && echo ok || echo 'still unavailable')"
  fi
  if ! make runtime-up >>"$LOGS/batch2-stack.log" 2>&1; then
    say "make runtime-up reported a problem; retrying the services once"
    docker compose up -d --wait postgres backend gateway collector telemetry falco falco-events-init \
      >>"$LOGS/batch2-stack.log" 2>&1
    log_fix stack "make runtime-up failed" "docker compose up -d --wait for the runtime services" \
            "$(docker compose ps --format '{{.Service}}:{{.Health}}' | tr '\n' ' ')"
  fi
}

incomplete() {  # prints the planned keys that are not yet complete
  "$PY" - <<'PYEOF'
import json, sys
sys.path.insert(0, "scripts/runtime")
from rt_common import RAW_ROOT, RUNTIME_ROOT, read_json
plan = read_json(RUNTIME_ROOT / "batch2-plan.json", {}) or {}
for key in plan.get("selected", []):
    if (read_json(RAW_ROOT / key / "status.json", {}) or {}).get("phase") != "complete":
        print(key)
PYEOF
}

say "=== pre-flight"
ensure_stack
"$PY" -u scripts/runtime/preflight_batch2.py >>"$LOGS/batch2-preflight.log" 2>&1; rc=$?
say "pre-flight exit $rc (details in datasets/runtime/batch2-preflight.json)"

say "=== 1/4 prefetch (native arm64)"
"$PY" -u scripts/runtime/prefetch_arm64.py --batch2 >>"$RUNTIME/prefetch-batch2.log" 2>&1; rc=$?
say "prefetch exit $rc; any tag still missing is substituted from the reserve list"

say "=== 2/4 sensor watchdog"
"$PY" -u scripts/runtime/watchdog_batch2.py >>"$LOGS/batch2-watchdog.log" 2>&1 &
WATCHDOG=$!
say "watchdog pid $WATCHDOG"
cleanup_watchdog() { kill "$WATCHDOG" 2>/dev/null; wait "$WATCHDOG" 2>/dev/null; }
trap cleanup_watchdog EXIT

say "=== 3/4 batch"
for pass in $(seq 1 "$MAX_PASSES"); do
  ensure_stack
  if ! "$PY" scripts/runtime/plan_batch2.py >>"$LOGS/batch2-plan.log" 2>&1; then
    say "the planner would not produce a plan (see batch2-plan.log); retrying the prefetch once"
    "$PY" -u scripts/runtime/prefetch_arm64.py --batch2 >>"$RUNTIME/prefetch-batch2.log" 2>&1
    if ! "$PY" scripts/runtime/plan_batch2.py >>"$LOGS/batch2-plan.log" 2>&1; then
      say "still no plan; recording it and going straight to export"
      log_fix plan "plan_batch2.py produced no plan after a second prefetch" \
              "see datasets/runtime/logs/batch2-plan.log and prefetch-batch2.json" \
              "no batch 2 image was collected in this run"
      {
        printf '\n## The batch 2 planner produced no plan (%s)\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'plan_batch2.py exited non-zero twice, once after a repeated prefetch, so no image was\n'
        printf 'selected and nothing was collected. prefetch-batch2.json has no finished_at, which means\n'
        printf 'the arm64 download did not run to completion.\n\n### Proposed command(s)\n\n'
        printf '```bash\n.venv/bin/python scripts/runtime/prefetch_arm64.py --batch2\n'
        printf '.venv/bin/python scripts/runtime/plan_batch2.py\nscripts/runtime/run_batch2.sh\n```\n'
      } >> "$RUNTIME/NEEDS_ATTENTION.md"
      break
    fi
  fi
  planned=$(incomplete)
  if [ -z "$planned" ]; then
    say "pass $pass: every planned image is complete"
    break
  fi
  # shellcheck disable=SC2086
  say "pass $pass: running $(echo $planned | wc -w | tr -d ' ') image(s): $(echo $planned | tr '\n' ' ')"
  # shellcheck disable=SC2086
  "$PY" -u scripts/runtime/run_batch.py --batch batch2 --parallel "$PARALLEL" $planned \
    >>"$LOGS/batch2-batch.log" 2>&1; rc=$?
  say "pass $pass finished with exit $rc"
  if [ -f "$RUNTIME/batch2-stop" ]; then
    say "batch2-stop is present; no further passes"
    break
  fi
done

say "=== stopping the watchdog before the final checks"
cleanup_watchdog
trap - EXIT

say "=== final cleanup: batch 2 containers and networks only"
docker ps -a --filter "label=porygon.runtime" --format '{{.Names}}'"$(printf '\t')"'{{.Label "porygon.runtime"}}' \
  | awk -F'\t' '$2 ~ /^batch2/ {print $1}' | while read -r name; do
      say "removing leftover batch 2 container $name"
      docker rm --force "$name" >/dev/null 2>&1
      log_fix cleanup "leftover batch 2 container $name" "removed it by exact name and batch 2 label" "removed"
    done
docker network ls --filter "label=porygon.runtime" --format '{{.Name}}'"$(printf '\t')"'{{.Label "porygon.runtime"}}' \
  | awk -F'\t' '$2 ~ /^batch2/ {print $1}' | while read -r net; do
      say "removing leftover batch 2 network $net"
      docker network rm "$net" >/dev/null 2>&1
      log_fix cleanup "leftover batch 2 network $net" "removed it by exact name and batch 2 label" "removed"
    done

say "=== 4/4 export, readme and validate"
"$PY" -u scripts/runtime/export.py >>"$LOGS/batch2-export.log" 2>&1; rc=$?
say "export exit $rc"
"$PY" -u scripts/runtime/update_readme_batch2.py >>"$LOGS/batch2-readme.log" 2>&1; rc=$?
say "readme exit $rc"
# A second export so manifest.json covers the updated readme.
"$PY" -u scripts/runtime/export.py >>"$LOGS/batch2-export.log" 2>&1; rc=$?
say "export (manifest refresh) exit $rc"
"$PY" -u scripts/runtime/validate.py >"$LOGS/batch2-validate.log" 2>&1; rc=$?
say "validate exit $rc ($(tail -1 "$LOGS/batch2-validate.log"))"
"$PY" -u scripts/runtime/verify_batch1_unchanged.py >"$LOGS/batch2-verify-batch1.log" 2>&1; rc=$?
say "batch 1 unchanged check exit $rc ($(tail -1 "$LOGS/batch2-verify-batch1.log"))"
"$PY" -u scripts/dataset/validate.py >"$LOGS/batch2-dataset-validate.log" 2>&1; rc=$?
say "static dataset validate exit $rc ($(tail -1 "$LOGS/batch2-dataset-validate.log"))"

say "=== done"
