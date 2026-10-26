# Command and lineage scoring

`porygon.behaviour.command-lineage` is an opt-in profile feature contract. Its paired algorithm is `porygon.distance.command-lineage`. Existing builds default to `porygon.behaviour.v1`, and existing profile hashes, distance weights, score IDs and recorded results retain their original meaning. No stored profile is automatically upgraded or activated.

## Building and selecting profiles

Add `--feature-schema porygon.behaviour.command-lineage` to a baseline build command. The API equivalent is `feature_schema_version` in `POST /internal/v1/baselines/build`. Profiles start as drafts and follow the existing explicit activation workflow. Scoring automatically selects the extractor and algorithm recorded on the selected profile; callers cannot reinterpret a legacy profile using the new algorithm.

The public definition is available at `/api/v1/anomaly-scores/config?feature_schema_version=porygon.behaviour.command-lineage`. Omitting the query parameter returns the unchanged legacy definition. Each stored score includes the selected scoring configuration. The new categorical-family weights assign 0.20 to command shape and 0.20 to verified sequence edges; the other family weights sum to 0.60. Top-level numeric, novelty and categorical weights remain unchanged. These weights define distance measurements; the contract introduces no automatic containment action.

## Command descriptors

Command shapes use a finite vocabulary: known program and flag names, shell operators, inline-shell syntax, and coarse value categories such as HTTP URLs, absolute paths, temporary paths and numbers. Unknown programs, flag names and values become opaque categories. The new command-shape family contains no argument values, URL hosts, query strings, credentials, literal inline scripts, or hashes of those values. Existing process/executable metadata retains its original feature representation; raw telemetry is stored under the existing retention policy. Changing a credential without changing its structural category leaves its command features unchanged.

The extractor reads at most 32,768 characters and 256 tokens per command, and limits nested shell parsing to two levels. Oversized, malformed and token-limited inputs produce explicit fixed markers. Quoted pipe characters stay arguments. Supported inline-shell flags and BusyBox/Toybox dispatch are handled without executing commands, expanding variables, opening files or contacting URLs. This is a bounded syntax representation, not shell evaluation or a reconstruction of program semantics.

At least 80% of process events must contain command evidence for a new-contract training profile to pass quality checks. Observation windows below this coverage are stored as `insufficient_data` with no score. Parser-limit markers count as observed command evidence and remain visible in the feature distribution. Coverage is recorded alongside each profile and observation.

## Causal sequences

A sequence pair requires an observed `parent_event_id` linking two selected process events. Both events must have the same nonempty container ID, Docker host ID and sensor instance ID, with the parent no later than the child. Both must fall in the same fixed profile window. Timestamp adjacency, process-group membership and shared session IDs do not establish a causal edge.

Unobserved parents, links crossing windows and conflicting scopes contribute no pair. Missing sequence families are excluded by the existing scoring availability rules. The number of verified edges is recorded explicitly; an absent edge does not reconstruct an unobserved fork.

Deferred parent reconciliation can change lineage while retaining the same event IDs. New-contract observation keys therefore bind the selected feature-document hash in addition to event IDs, profile identity, window and scoring configuration. Recomputing after a link repair creates a new reproducible score when its feature content changes. Stored historical scores remain intact.

## Model and detection integration

The existing random-forest classifier retains its original feature contract and drift scale. New-contract scores do not feed that classifier automatically, and direct document classification rejects incompatible schemas. Container event classification selects legacy-scale scores for its drift input. Training and evaluating a classifier on the new contract is a separate model change.

Custom detection rules preserve raw executable paths for `executable_path` and `parent_executable_path`, including BusyBox/Toybox binaries. Basename rules still resolve dispatched applets. Path-bearing comparisons, including `contains`, use case-sensitive Linux path semantics. The matcher identity is `porygon.detection.matcher.raw-multicall-paths`; existing stored detection runs are preserved.

## Verification

Regression tests cover fixed-vocabulary privacy, credential substitutions, nested shells, malformed/large inputs, quoted operators, interleaved processes, host/sensor/container isolation, absent lineage, repaired-link score identity, insufficient evidence and legacy hash compatibility. PostgreSQL integration exercises profile creation and activation, both scoring contracts, idempotent replay and parent reconciliation in a disposable schema. New run-environment fingerprints include the baseline and command extractor source files.
