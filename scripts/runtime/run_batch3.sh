#!/bin/bash
# Collect batch 3 of the runtime monitoring dataset, unattended, start to finish.
#
# Same protocol as batches 1 and 2, judged by the same detection matcher (v5):
#   0. pre-flight, and a check that the running backend reports matcher v5
#   1. download the native arm64 images (retried, then substituted)
#   2. start the sensor watchdog
#   3. run the batch 4 images at a time; the matcher is checked before every image
#   4. export all three batches in one pass, update the readme, validate, and
#      prove batches 1 and 2 did not change
#
# Porygon's images are never rebuilt here: services are only started from the
# images that already exist (--no-build), so the running backend stays the one
# that judged batches 1 and 2. It never waits for a person: anything it cannot fix
# is written to datasets/runtime/NEEDS_ATTENTION.md and the rest carries on. The
# one exception is a matcher check failing, which stops collection.
#
#   nohup caffeinate -i -s scripts/runtime/run_batch3.sh > artifacts/runtime-batch3/batch3-run.log 2>&1 &

set -u
cd "$(dirname "$0")/../.." || exit 1
ROOT=$PWD
PY=$ROOT/.venv/bin/python
LOGS=$ROOT/datasets/runtime/logs
RUNTIME=$ROOT/datasets/runtime
mkdir -p "$LOGS"
# Logs written while export computes manifest.json live outside datasets/, so the
# manifest never covers a file that is still growing.
OUT=$ROOT/artifacts/runtime-batch3
mkdir -p "$OUT"
export PORYGON_RT_BATCH=batch3
export PORYGON_RT_REQUIRE_MATCHER=1
unset PORYGON_RT_RAW_ROOT PORYGON_RT_RUN_LOG
SERVICES="postgres backend gateway collector telemetry falco falco-events-init"
MAX_PASSES=${MAX_PASSES:-4}
PARALLEL=${PARALLEL:-4}

say() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [batch3] $*"; }

log_fix() {  # step, failed, action, result
  "$PY" - "$1" "$2" "$3" "$4" <<'PYEOF'
import sys
sys.path.insert(0, "scripts/runtime")
from rt_common import log_event
log_event(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], batch="batch3")
PYEOF
}

attention() {  # title, body
  { printf '\n## %s (%s)\n\n%s\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$2"; } >> "$RUNTIME/NEEDS_ATTENTION.md"
}

stack_healthy() {
  local bad
  bad=$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null \
        | awk '$1 ~ /^(postgres|backend|gateway|collector|telemetry|falco)$/ && ($2 != "running" || ($3 != "" && $3 != "healthy"))')
  local count
  count=$(docker compose ps --format '{{.Service}}' 2>/dev/null | grep -cE '^(postgres|backend|gateway|collector|telemetry|falco)$')
  [ -z "$bad" ] && [ "$count" -eq 6 ]
}

ensure_stack() {
  if ! docker info >/dev/null 2>&1; then
    say "Docker is not responding; starting Docker Desktop"
    open -a Docker
    for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 10; done
    log_fix docker "docker info failed" "started Docker Desktop and waited for the daemon" \
            "$(docker info >/dev/null 2>&1 && echo ok || echo 'still unavailable')"
  fi
  if ! stack_healthy; then
    say "runtime services not all healthy; starting them from the existing images (no rebuild)"
    # shellcheck disable=SC2086
    docker compose up -d --no-build --wait $SERVICES >>"$LOGS/batch3-stack.log" 2>&1
    log_fix stack "runtime services not all healthy" "docker compose up -d --no-build --wait (no rebuild)" \
            "$(docker compose ps --format '{{.Service}}:{{.Health}}' | tr '\n' ' ')"
  fi
}

incomplete() {
  "$PY" - <<'PYEOF'
import sys
sys.path.insert(0, "scripts/runtime")
from rt_common import RAW_ROOT, RUNTIME_ROOT, read_json
plan = read_json(RUNTIME_ROOT / "batch3-plan.json", {}) or {}
for key in plan.get("selected", []):
    if (read_json(RAW_ROOT / key / "status.json", {}) or {}).get("phase") != "complete":
        print(key)
PYEOF
}

say "=== pre-flight"
ensure_stack
if ! "$PY" scripts/runtime/matcher_guard.py --batch batch3 --when preflight >>"$LOGS/batch3-matcher.log" 2>&1; then
  say "the running backend does not report matcher v5; batch 3 is NOT run"
  log_fix matcher "pre-flight matcher check failed (see batch3-matcher-checks.jsonl)" \
          "did not start batch 3, as the plan requires" "stopped"
  attention "Batch 3 not started: the backend is not on matcher v5" \
"The pre-flight check read the detection matcher revision from the running backend and it was not
porygon.detection.matcher.v5 (details in batch3-matcher-checks.jsonl). Batch 3 must be judged by the
same matcher as batches 1 and 2, so nothing was collected. No file was changed.

### Proposed command(s)

\`\`\`bash
docker compose exec -T backend python -c \"import porygon_api.detection as d; print(d.MATCHER_REVISION)\"
\`\`\`"
  exit 1
fi
"$PY" -u scripts/runtime/preflight_batch3.py >>"$LOGS/batch3-preflight.log" 2>&1; rc=$?
say "pre-flight exit $rc (details in datasets/runtime/batch3-preflight.json)"

say "=== 1/4 prefetch (native arm64)"
"$PY" -u scripts/runtime/prefetch_arm64.py --batch3 >>"$RUNTIME/prefetch-batch3.log" 2>&1; rc=$?
say "prefetch exit $rc"

say "=== 2/4 sensor watchdog"
"$PY" -u scripts/runtime/watchdog_batch3.py >>"$LOGS/batch3-watchdog.log" 2>&1 &
WATCHDOG=$!
cleanup_watchdog() { kill "$WATCHDOG" 2>/dev/null; wait "$WATCHDOG" 2>/dev/null; }
trap cleanup_watchdog EXIT

say "=== 3/4 batch"
for pass in $(seq 1 "$MAX_PASSES"); do
  ensure_stack
  if ! "$PY" scripts/runtime/plan_batch3.py >>"$LOGS/batch3-plan.log" 2>&1; then
    "$PY" -u scripts/runtime/prefetch_arm64.py --batch3 >>"$RUNTIME/prefetch-batch3.log" 2>&1
    if ! "$PY" scripts/runtime/plan_batch3.py >>"$LOGS/batch3-plan.log" 2>&1; then
      log_fix plan "plan_batch3.py produced no plan after a second prefetch" "see logs/batch3-plan.log" \
              "no further batch 3 image collected"
      attention "The batch 3 planner produced no plan" "See logs/batch3-plan.log and prefetch-batch3.json."
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
  "$PY" -u scripts/runtime/run_batch.py --batch batch3 --parallel "$PARALLEL" $planned \
    >>"$LOGS/batch3-batch.log" 2>&1; rc=$?
  say "pass $pass finished with exit $rc"
  if [ -f "$RUNTIME/batch3-stop" ]; then
    say "batch3-stop is present; no further passes"
    break
  fi
done

say "=== stopping the watchdog"
cleanup_watchdog
trap - EXIT

say "=== final cleanup: batch 3 containers and networks only"
docker ps -a --filter "label=porygon.runtime" --format '{{.Names}}'"$(printf '\t')"'{{.Label "porygon.runtime"}}' \
  | awk -F'\t' '$2 ~ /^batch3/ {print $1}' | while read -r name; do
      docker rm --force "$name" >/dev/null 2>&1
      log_fix cleanup "leftover batch 3 container $name" "removed it by exact name and batch 3 label" "removed"
    done
docker network ls --filter "label=porygon.runtime" --format '{{.Name}}'"$(printf '\t')"'{{.Label "porygon.runtime"}}' \
  | awk -F'\t' '$2 ~ /^batch3/ {print $1}' | while read -r net; do
      docker network rm "$net" >/dev/null 2>&1
      log_fix cleanup "leftover batch 3 network $net" "removed it by exact name and batch 3 label" "removed"
    done

say "=== final matcher check"
"$PY" scripts/runtime/matcher_guard.py --batch batch3 --when end >>"$LOGS/batch3-matcher.log" 2>&1; rc=$?
say "final matcher check exit $rc"

say "=== 4/4 export, readme and validate"
"$PY" -u scripts/runtime/export.py >"$OUT/batch3-export.tmp" 2>&1; rc=$?
say "export exit $rc"
"$PY" -u scripts/runtime/update_readme_batch3.py >"$OUT/batch3-readme.tmp" 2>&1; rc=$?
say "readme exit $rc ($(tail -1 "$OUT/batch3-readme.tmp"))"
"$PY" -u scripts/runtime/export.py >>"$OUT/batch3-export.tmp" 2>&1; rc=$?
say "export (manifest refresh) exit $rc"
"$PY" -u scripts/runtime/validate.py >"$OUT/batch3-validate.tmp" 2>&1; rc=$?
say "validate exit $rc ($(tail -1 "$OUT/batch3-validate.tmp"))"
"$PY" -u scripts/runtime/verify_batches_unchanged.py >"$OUT/batch3-verify12.tmp" 2>&1; rc=$?
say "batches 1 and 2 unchanged check exit $rc ($(tail -1 "$OUT/batch3-verify12.tmp"))"
"$PY" -u scripts/runtime/verify_batch1_unchanged.py >"$OUT/batch3-verify1.tmp" 2>&1; rc=$?
say "batch 1 unchanged check exit $rc ($(tail -1 "$OUT/batch3-verify1.tmp"))"
"$PY" -u scripts/dataset/validate.py >"$OUT/batch3-dataset-validate.tmp" 2>&1; rc=$?
say "static dataset validate exit $rc ($(tail -1 "$OUT/batch3-dataset-validate.tmp"))"
say "=== done"
