# Behavioral profiling and scoring

## Profile identity

Profiles are tied to an immutable image digest and a feature schema. The historical schemas `porygon.behaviour.v1` and `porygon.behaviour.command-lineage` remain readable and reproducible. Existing scores retain the algorithm version and scoring configuration that created them. New managed-profile candidates default to `porygon.behaviour.support-aware`; operators can explicitly select `porygon.behaviour.command-lineage` for compatibility. The internal baseline CLI still defaults to the historical `porygon.behaviour.v1` schema.

A schema identifies the feature extractor as well as its data shape. Command-lineage and support-aware profiles bind the extractor contract hash into the feature document. The support-aware schema has its own bounded command-shape descriptors; it never stores raw command argument values or hashes of those values. An unsupported schema or mismatched extractor hash is rejected rather than reinterpreted.

## Historical distance scoring

The historical distance algorithms compare aggregate categorical distributions using the base-2 square-root Jensen–Shannon distance:

\[
D(P,Q)=\sqrt{\tfrac12 KL_2(P\parallel M)+\tfrac12 KL_2(Q\parallel M)},\qquad M=\tfrac12(P+Q).
\]

The distance is symmetric and bounded in `[0, 1]`. Empty observed families are unavailable evidence; they are not treated as a normal zero distribution. A nonempty family with no baseline support is maximally unsupported. The scorer renormalizes configured family and group weights across available evidence. `porygon.distance.v1` and `porygon.distance.command-lineage` retain their historical weights and outputs.

Before replacing the isolated backend image, retain the accepted baseline/scoring/command-shape sources in a fresh ignored verification directory. After source freeze, compare those hash-verified modules against current legacy outputs on benign and novel fixtures:

```bash
.venv/bin/python scripts/verify_legacy_scoring_reference.py \
  --reference-dir "$LEGACY_REFERENCE_DIR" \
  --manifest artifacts/local/remaining-verification/release-validation-20261030t151041z-1026137/manifest/release-manifest.json
```

The verifier checks the accepted source tree and each archived file before importing them under an isolated package prefix. It compares legacy features, manifests, model hashes, scoring configs, observation keys, scores, components and explanations. It does not reuse fixtures from the current scorer as expected outputs.

## Support-aware distance scoring

`porygon.behaviour.support-aware` uses the purpose-named scorer `porygon.distance.support-aware`. It records raw category counts, contributing-event counts, token mass, missing/unknown counts, process/runtime event counts, command evidence coverage, and fitted-window counts. Fitted windows are observations within an interval; they are not independent runs.

The support-aware scorer compares counts after a deterministic bounded-support mapping. It selects at most 128 tokens from the baseline/observation union by descending combined count with lexical tie-breaking; only counts outside that retained set are pooled into one `OTHER` bucket. A fixed-total `alpha = 0.5` uniform prior uses the same mixture weight for both distributions, `alpha / (min(N_baseline, N_observation) + alpha)`. This keeps identical empirical proportions at zero distance when sample sizes differ while letting the smaller sample control the shared smoothing weight. All empirical event mass remains represented, while an attacker cannot increase smoothing mass by introducing an arbitrary number of new tokens. The score includes the weighted aggregate distance and, when sufficiently supported, the maximum supported short-window distance. That maximum is an uncalibrated behavioral signal, not a false-positive probability.

The initial support contract requires at least 20 baseline process events, at least 20 contributing baseline events for a categorical family, at least 3 observed process/family events, at least 3 eligible categorical families, and at least 80% usable command evidence. Modern profile intervals are capped at 30 days, 4,096 windows and 100,000 events; those bounds are included in the feature contract and checked before per-window allocation. A sparse interval over the bound is rejected, not truncated or treated as many independent runs. Malformed, oversized, token-limited, nesting-limited, and absent command lines are tracked as fallback or unavailable rather than usable. Temporal comparison divides each native scoring window into up to four deterministic segments; a supported segment needs at least three process events and three events for an eligible family. Temporal feature output is capped at 4,096 segment records and 100,000 events. If those bounds are exceeded, the temporal component is marked unsupported; valid aggregate evidence remains available.

These are explicit engineering gates, not empirically calibrated thresholds. Insufficient baseline or observation support persists as `insufficient_data`; it is not converted to a baseline-like score. Structural process, runtime, and kernel rules remain independently evaluable. The advisory classifier currently accepts only `porygon.behaviour.v1`; other profile contracts report that incompatibility and do not get silently transformed for classifier input.

Continuous assessment currently requires an enrolled, quality-passing managed profile before it creates an anomaly score and detection run. With that profile present, `insufficient_data` skips only the behavioral-distance rule; process, runtime, custom and selected kernel rules can still be evaluated. A target without any profile is marked unprofiled and the scheduled worker does not create a detection run, so it has no continuous baseline-independent rule coverage yet. Workbench preview can evaluate an explicit bounded selection, but it is not a continuous alert. Do not claim always-on structural coverage for unprofiled targets.

## Numeric and score-band interpretation

Numeric deviations use the configured median, standard deviation, robust scale derived from the 95th percentile, scale floors, and z-score tolerance/saturation in the persisted scoring configuration. Score bands are descriptive routing labels from that configuration. Neither the legacy bands nor the support-aware temporal maximum establish probability of compromise or empirical calibration. Operators must review the event evidence and support/coverage explanations.

## Operator workflow

Select a schema explicitly when building a profile and retain the returned feature and scoring contract with the profile. The managed-profile workflow uses the support-aware schema by default; historical profiles are not rewritten. The CLI accepts both historical and support-aware contracts:

```bash
python3 scripts/porygon_baseline.py build --feature-schema porygon.behaviour.support-aware ...
python3 scripts/porygon_score.py compute --algorithm porygon.distance.support-aware ...
```

Use `insufficient_data` and coverage explanations to distinguish unavailable telemetry from baseline-like behavior. A score is behavioral evidence only and does not trigger automatic containment.

For one observed, owned disposable-container window, `scripts/verify_support_aware_live.py` reads the actual selected event IDs, derives support/coverage/temporal metadata, and computes a non-persisted score. It requires a managed support-aware baseline whose approved host and container exactly match the observed target and whose benign training sample meets the support gates. An optional legacy profile ID produces an explicit historical comparison through that profile's own feature and algorithm contract. The verifier does not create profiles or scores, promote models, or invoke response actions.

### Preparing a fresh owned target

Use a new disposable target for this workflow. Existing acceptance targets are often removed and cannot be reused as managed baseline scope. Run this only in the isolated `porygon-service-trust` project after the joint verification window opens. Keep containment disabled. The cached backend image ID is an acceptable immutable target identity when that local build has no repository digest; the managed target records `local:sha256:<image-id>` and selects events by exact `image_id` under the same host and container. Repository digests continue to use the existing digest path. Never pull an image for this check.

The ignored executable `artifacts/local/prepare_support_aware_live.py` automates this path from the selected backend image ID. It creates an owned internal network and bounded target, generates 30 benign executions in both the baseline and separate observation windows, requires 20 resolved events across at least three five-second buckets, proposes a managed support-aware candidate without activating it, writes a private receipt, and removes only its labeled target and network. It reads `PORYGON_OPERATOR_API_TOKEN` from the process environment or `.env` without printing it. Invoke it only during the joint verification window:

```bash
.venv/bin/python artifacts/local/prepare_support_aware_live.py "$DOCKER_CONTEXT" "$API_ORIGIN"
```

The explicit `list_owned_window_events.py` and `verify_support_aware_live.py` commands below remain useful for inspecting an already prepared target and profile.

Create an internal network and a bounded disposable container with no mounts. The target stays alive for profile and observation collection; its only work is local Python process creation.

```bash
set -eu
RUN_ID="support-aware-$(date -u +%Y%m%dT%H%M%SZ)"
NETWORK="porygon-attack-control-${RUN_ID}"
docker --context "$DOCKER_CONTEXT" network create --internal \
  --label "io.porygon.attack-control.run=${RUN_ID}" "$NETWORK"
TARGET_ID=$(docker --context "$DOCKER_CONTEXT" run -d --pull=never \
  --network "$NETWORK" --name "$RUN_ID" \
  --label "io.porygon.attack-control.run=${RUN_ID}" \
  --label io.porygon.owned-disposable=true \
  --label com.porygon.protected=false \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --pids-limit=32 --memory=128m --cpus=0.5 \
  --entrypoint python "$IMAGE_ID" -c 'import time; time.sleep(3600)')
HOST_ID=$(docker --context "$DOCKER_CONTEXT" info --format '{{.ID}}')
```

Generate 30 benign process executions, spaced across at least three five-second windows. Record controller start/end times, then allow ingestion to finish. Use the event lister to confirm at least 20 resolved events for this exact daemon, container and digest, with actual timestamps across at least three distinct five-second buckets. Build training bounds from the first/last observed event timestamps with a small margin, and ensure those bounds cover at least three windows.

```bash
WORKLOAD_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for index in $(seq 1 30); do
  docker --context "$DOCKER_CONTEXT" exec "$TARGET_ID" \
    python -c 'import os; os.getpid()' >/dev/null
  sleep 0.55
done
WORKLOAD_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
```

After telemetry ingestion, list the actual IDs and timestamps. The lister validates the isolated stack binding, exact target label, no mounts, and the target's owned internal network; it emits no command arguments. Require at least 20 rows and at least three nonempty five-second buckets, then set training bounds around the first and last actual event timestamps.

```bash
.venv/bin/python scripts/list_owned_window_events.py \
  --compose-project porygon-service-trust \
  --docker-context "$DOCKER_CONTEXT" --api-origin "$API_ORIGIN" \
  --host "$HOST_ID" --container "$TARGET_ID" --image-digest "$IMAGE_DIGEST" \
  --start "$WORKLOAD_START" --end "$WORKLOAD_END"
```

Enroll the exact host/container/digest through `POST /operator/v1/assessment-targets` with a completed timezone-aware `start_at` and `window_seconds: 5`. Its JSON fields are `docker_host_id: HOST_ID`, `container_id: TARGET_ID`, `image_digest: IMAGE_DIGEST`, `start_at: WORKLOAD_START`, and `allowed_lateness_seconds: 0`. Then propose, without activating, a managed candidate through `POST /operator/v1/assessment-targets/{target_id}/profiles` with this body shape:

```json
{
  "intervals": [
    {
      "name": "owned-benign-sample",
      "label": "benign",
      "start_at": "FIRST_EVENT_MINUS_MARGIN",
      "end_at": "LAST_EVENT_PLUS_MARGIN"
    }
  ],
  "feature_schema_version": "porygon.behaviour.support-aware",
  "reference": "owned disposable target benign baseline",
  "minimum_process_events": 20,
  "minimum_nonempty_windows": 3
}
```

Supply actual event-derived timestamp values for the bounds, covering only the benign workload. Keep the returned `profile_id`, `artifact_hash`, and complete quality checks. Stop if the event list or quality report misses any support requirement; do not lower thresholds or add attack-shaped events to training.

Generate a separate completed window on the same still-running target, wait for collection, and call:

```bash
.venv/bin/python scripts/verify_support_aware_live.py \
  --compose-project porygon-service-trust \
  --docker-context "$DOCKER_CONTEXT" --api-origin "$API_ORIGIN" \
  --host "$HOST_ID" --container "$TARGET_ID" --image-digest "$IMAGE_DIGEST" \
  --profile-id "$SUPPORT_PROFILE_ID" --start "$OBSERVATION_START" --end "$OBSERVATION_END"
```

The receipt must show the exact selected event IDs, support and missingness, temporal component status, and aggregate score. It is an integration observation, not a measured attack-detection rate. To confirm legacy compatibility, pass `--legacy-profile-id` for an existing quality-passing historical profile with the same image digest; this comparison uses that profile's own schema and algorithm. Do not activate the candidate or promote a model for this check. After preserving the receipt, inspect the run label and remove only this target and its matching internal network.
