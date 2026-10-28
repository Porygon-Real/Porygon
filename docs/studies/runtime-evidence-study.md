# Runtime evidence study pathway

The immutable historical documents in `docs/research/` remain unchanged. The
engineering runner now distinguishes the frozen profile-scope matrix from the
prospective runtime-evidence design in
`experiments/protocols/runtime-evidence-study.json`. No new study measurements,
trained-model promotion or scientific superiority follow from source code.

## Frozen collection

The original protocol constructs IDs first and SHA-256 sorts within each
workload-version-mode-scenario stratum using seed 20260820. Exact fit,
calibration, five pilot and confirmatory allocations are recorded before any
image pull. Ten clean independent fit and calibration runs, at least three
same-digest replicas per split, all six workload versions/four modes, runtime
scenarios and required benign hard negatives are enumerated. Confirmatory counts
use max(30, power lock) for benign cells and max(20, power lock) for controlled
scenario cells. Dedicated labelled fit-scenario observations may enter only
copied contamination sensitivity references; primary references remain clean.
Pilot observations never train, calibrate or enter confirmatory outcomes.

The runner refuses until independent protocol reviews are frozen and a feasible
ART-DES-001 lock matches its current enumeration/protocol hashes. The lock also
binds `analysis_policy_sha256`, because the historical prose leaves some feature
aggregation and request-quality choices undefined. Supply a reviewed policy with
contract `porygon.frozen-analysis-policy`, implementation
`full-frozen-fields-mean-component-ranks-max-run`, explicit window/quality
thresholds, minimum fit/calibration counts (at least ten), minimum replicas (at
least three), alpha 0.05, missing component policy `abstain`, quality justification
and review reference. There are no silently chosen scientific quality constants.
The separate `analysis_review` record must name an actual independent human,
record decision/reference/time before locking, and bind exact policy, source-tree
and sample-size-result hashes. Existing protocol reviews do not approve new
analysis choices. Missing review refuses collection; no approval is generated.
Bind the policy and `--analysis-review PATH` when deliberately creating a sample lock using
`python3 -m experiments.sample_size build --analysis-policy PATH ...`.

`python3 -m experiments.confirmatory plan --run-id NAME --sample-lock PATH --analysis-policy PATH --output PLAN`
performs prelaunch design gates. Collection is a separate explicit command:
`python3 -m experiments.confirmatory collect --plan PLAN --run-dir NEW_DIR`.
It never retags an existing pilot directory. Distinct workload drivers implement
concurrent HTTP bursts, Redis pipelines, read-only nginx configuration,
persistence and PostgreSQL tuning; their configuration is source-hashed.
Interrupted/mistimed actions and generator failures remain failed runs.

Exact snapshots bind assigned host, full container ID, digest, integer nanosecond
interval and selected event IDs. A bounded query refuses truncation. Two channel
queries can exclude later arrivals; they do not prove capture completeness.
Raw arguments/inspect payloads are omitted. Known multicall applets are reduced
to a bounded applet projection sufficient for built-in rules; unknown projections
abstain. Fixed-window features preserve six categorical families, observed sets,
five numeric summaries and empty windows. Fit windows are pooled by their actual
runs, never by one time range spanning calibration/test runs or gaps.

The reviewed implementation computes mean available Hellinger categorical shift,
mean novelty, Laplace-smoothed sequence surprisal and two-sided empirical numeric
tails. Fit-window component ranks fuse by an unweighted mean; calibration uses
independent maximum-window run blocks. Missing required components cause
abstention. Required rules/novelty/frequency/sequence/calibrated/hybrid comparators
and feature/context/fallback ablations are distinct outputs. The policy/code
hash must be reviewed before collection; this is an explicit implementation
choice, not a retroactive assertion that the historical prose specified it all.

`python3 -m experiments.confirmatory replay RUN_DIR` uses saved snapshots only.
It validates path confinement, immutable hashes, the original source/policy and
all planned/failed trials before reproducing tables. FPR and recall retain all
planned denominators, unresolved-outcome bounds and conditional intervals.
Incomplete paired families abstain; they do not silently select complete cases.
Scope co-primary tests, detector comparisons and ablations have predeclared
separate Holm families. Controlled prevalence is not deployment precision.
Cross-workload misapplication and copied-fit contamination are separate
sensitivity outputs, with unavailable injection support explicit.

The default claim map is deliberately unevaluated until scientific review.
`python3 scripts/validate_paper_evidence.py --run-dir RUN_DIR` verifies links and
hashes; it separately reports whether scientific claims have been reviewed.
Successful software replay does not convert an unevaluated claim into support.

## Prospective extension

`python3 -m experiments.validate_study_plan --plan experiments/protocols/runtime-evidence-study.json --check-sources`
checks the design and recorded primary-source coordinates offline. The current
proposal is design-pending: no image/run matrix, measured pilot sample size or
precollection approval has been invented. `--for-collection` refuses these
missing prerequisites. Family-held-out and forward-in-time evaluation keep fit,
calibration and test deployment groups separate before window extraction.
Controller labels, release/host/day groups, negative controls, resource controls,
missingness and multiplicity are mandatory. Freeze a real cohort only after the
software and scientific design are reviewed.

## Local dataset preparation

`python3 -m experiments.export_study prepare --run-dir RUN_DIR --output NEW_DIR --rights RIGHTS_JSON`
requires a rights record: `dataset_license: CC-BY-4.0`,
`dataset_rights: owned-or-permission-recorded`, real approving actor/reference and
an explicit third-party image/software license inventory. It exports whitelisted
fields with deterministic host/container pseudonyms and proves the transformation
preserves declared result tables. Original private backups, enrollment material,
raw arguments and arbitrary inspect payloads never enter that export.
`python3 -m experiments.export_study replay NEW_DIR` reproduces the exported
results offline. The command prepares local files and does not upload/publish.
Third-party software/content retains its own license; the dataset license applies
only to material the rights record permits.
