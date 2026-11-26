# Release and recovery

Service images install a checked-in Python 3.13 dependency graph, including test
and build dependencies, using wheel hashes. Local project installation disables
resolution and build isolation. `pip check` runs during the final image build.
The graph was resolved from the accepted active image metadata, then bound to
non-yanked PyPI wheel hashes; this is dependency identity, not an advisory verdict.
To update intentionally, rebuild the selected dependency graph in an isolated
project, run `python3 scripts/lock_service_dependencies.py --service backend`,
review manifest/lock changes and run the final acceptance battery. The updater
never installs packages. Scanner's OS packages/base image also require image
identity and an SBOM; Python locks do not make the whole image bit-reproducible.

CI runs five service suites and PostgreSQL integration, source/protocol checks,
secret patterns, dependency advisory checks and SBOM generation. Kernel and
containment acceptance require a manual trusted-main dispatch to a disposable
privileged runner protected by the `isolated-acceptance` environment. Never run
untrusted pull-request code on that runner. Action tags and runner images remain
part of the separately reviewed CI supply chain.

A local release manifest uses contract `porygon.release-manifest`, source
`commit` plus a `files` mapping of repository-relative SHA-256 identities, and
exactly five `services` entries. Each records `image_id`, `lock_sha256`,
`sbom_path` relative to the manifest directory and `sbom_sha256`. Generate SBOMs
from the exact local images using the CI SBOM tool. Run
`python3 scripts/check_release_manifest.py --manifest PATH` before distribution.
The verifier checks local identities; acceptance/soak results require their own
measured artifacts and are never inferred from the manifest.

## Private restore drill

Run `python3 scripts/verify_restore.py --disposable --output artifacts/local/restore-UNIQUE`
only in the intended isolated acceptance project. Initial targets are RPO 3600s
and RTO 600s, recorded before execution. The script holds a read-only exported
PostgreSQL snapshot across row hashes and `pg_dump`, backs up response receipts
using SQLite's online backup API, then restores only a fresh labeled PostgreSQL
volume/container with network `none`. It refuses active/existing destinations.
No application or responder starts against restored credentials. Every unresolved
intent and cached response receipt needs operator reconciliation before a
restored system may enable response. The database and receipt snapshots are
individually consistent, not a distributed atomic snapshot; a response that
straddles them must be reviewed, never automatically replayed.

Backup files contain private operational data. Keep the output directory mode
0700, files 0600, encrypt storage with the deployment's backup system, and never
include these dumps in public research artifacts. Keep notification destination
keys, enrollment bootstrap materials and external secrets in the separately
managed secret backup, not a release manifest. A measured drill report records
source/restore row counts and hashes, snapshot age, elapsed time, failures and
whether source container/volume identities were preserved. It does not require a
running source database to stop receiving heartbeats. Restored temporary objects
are removed only if their unique ownership label still matches this invocation.

## Alert delivery

Enable notifications only with an operator-maintained private regular JSON file.
Each entry needs `destination_id`, HTTPS `url`, `connect_ip`, `hmac_secret` (at
least 32 characters), and optional `minimum_severity`. `connect_ip` is a literal
globally routable address approved by the operator; TLS verifies the hostname in
`url`. This avoids delivery-time DNS and rebinding. Update the configuration when
an approved destination's address changes; changed identities require explicit
repair rather than silently sending old deliveries to a new destination. The
local verifier alone may use literal loopback HTTP with `allow_loopback: true`.
No redirect is followed. HMAC covers timestamp plus a period plus exact payload
bytes. Receivers must verify freshness/signature and deduplicate the stable
`X-Porygon-Delivery-ID`; delivery is at least once. Config errors remain durable
and cannot roll back an incident. Repair is an audited admin operation.

## Supported deployment evidence

Docker-first Linux with the pinned Falco modern eBPF image is the declared
engineering target. Kernel/Docker/CPU combinations, three-node throughput,
saturation and the seven-day observe-only soak are supported only after their
actual environment and failure-accounting reports are retained. No Kubernetes
support or fleet capacity is implied by these source changes.

## Event ingestion verification receipts

`scripts/verify_event_ingestion.sh` writes private, atomic stage receipts to
`artifacts/local/ingest-RUN_ID/`. The saturation receipt is written as soon as
the bounded spool reaches its configured cap with current-run canaries and a
positive overflow delta. The persistence receipt follows exact API/PostgreSQL
count reconciliation, replay idempotence, and a fresh empty-outbox observation.
Each receipt binds the run ID, Docker host ID, current source commit and tree,
and verifier-script digest; it contains only validated counters, never events,
commands, or credentials. Files and their run directory are mode `0600` and
`0700`. Reusing a run ID cannot replace an earlier stage receipt.

The verifier refuses to report completion unless both receipts are present,
nonempty, current (under 24 hours), and agree on source, host, run and event
counts. The persistence receipt requires API, PostgreSQL, pre-replay and
post-replay unique counts to agree, with zero replay growth and an empty queue;
the saturation canary count must be positive and no larger than the configured
cap. A failed later stage leaves earlier receipts available for diagnosis;
their presence alone does not mean the entire verifier completed. The existing
`artifacts/event-ingestion-capture-integrity.json` schema and the public
`artifacts/verification-manifest.json` contract remain unchanged. The aggregate
runner separately updates an ignored local stage ledger after each gate so a
later failure or interruption does not erase earlier gate outcomes.

## Local provenance build recipe

After source completion and the accepted verification window, capture the source
identity under the ignored local artifact directory. This recipe records identity;
it does not publish an image or claim a completed soak:

```sh
mkdir -p artifacts/local/release
python3 scripts/source_identity.py > artifacts/local/release/source.json
PORYGON_RELEASE_COMMIT=$(python3 -c 'import json; print(json.load(open("artifacts/local/release/source.json"))["commit"])')
PORYGON_RELEASE_TREE=$(python3 -c 'import json; print(json.load(open("artifacts/local/release/source.json"))["tree_sha256"])')
for PORYGON_RELEASE_SERVICE in backend collector telemetry responder scanner; do
  PORYGON_RELEASE_LOCK=$(sha256sum "$PORYGON_RELEASE_SERVICE/requirements.lock" | cut -d' ' -f1)
  docker build --build-arg SOURCE_COMMIT="$PORYGON_RELEASE_COMMIT" \
    --build-arg SOURCE_TREE_SHA256="$PORYGON_RELEASE_TREE" \
    --build-arg DEPENDENCY_LOCK_SHA256="$PORYGON_RELEASE_LOCK" \
    -t "porygon-release-$PORYGON_RELEASE_SERVICE" "$PORYGON_RELEASE_SERVICE"
done
```

Use the resulting exact image IDs with `scripts/build_release_manifest.py` and
installed Syft to generate local SPDX SBOMs and binding receipts. Each receipt
binds its image ID, source-tree digest and SBOM digest. It is locally generated
provenance, not a signed third-party attestation. The verifier rejects source,
lock, image-label, receipt or SBOM identity drift. Plans are advisor metadata and
are excluded from source identity; all other nonignored files, including new
untracked source, Compose, dashboard and root configuration, are bound.

## Capacity and failure lab

Use `python3 -m experiments.benchmarks.run --lab-spec SPEC --scenario sustained --rate 100 --duration 3600 --output NEW_DIR`
(or the equivalent `experiments.benchmarks.lab --spec SPEC` entry point). This
starts a bounded local measurement against already prepared disposable targets;
it does not provision a company deployment. `burst` requests five times the
base operation rate for its declared duration. Operation rate and selected Falco
record rate are separate units; only event-time-filtered observed selected
records determine the throughput result. Downstream drain time does not reduce
that generation-interval rate.

The JSON specification has contract `porygon.benchmark-lab`, exactly one
`control_plane` with optional Docker `context`, exact full `backend` and optional
`postgres` container IDs, and `nodes`. Each node declares `host_id`, optional
Docker `context`, exact full `target`, `telemetry`, `falco` and independent
`observer` IDs, plus `hardware_declaration` containing actual `cpu_model`,
`disk_model_or_media` and `filesystem`. Architecture and Docker storage driver
are recorded under their own names. A hardware declaration is operator-supplied;
Docker/kernel/boot/rules identities are measured. Distinct kernel boot IDs and
Docker daemon IDs are required for distinct Linux nodes.

Every selected container must belong to a `porygon-lab-*` or
`porygon-benchmark-*` Compose project and carry
`com.porygon.benchmark-opt-in=true`; workload and network-peer targets also need
`com.porygon.benchmark=disposable`. The harness refuses ordinary active projects.
Prepare the observer with the same immutable telemetry image, a read-only root
filesystem, the exact shared Falco log volume mounted read-only, and no writable
mounts or service credentials. Keep it separate from the adapter being stopped.
The observer runs only normalization/readback against the log volume. It receives
four nonsecret capture settings, not the sensor's environment. A network scenario
requires an opted-in peer on the same private Docker network with a listening
port; the declared peer address must match its inspected container address.

The lab supports exec, successful outbound connections, memfd creation and
positive writes to an inert `/etc/porygon-benchmark-write` inside the disposable
workload. Memfd creation is not called executable-memory use. Control-plane,
adapter and database interruptions restore only exact opted-in IDs; a shared
control-plane outage is injected once. Disk pressure uses a separate owned,
network-disabled, bounded-tmpfs container and never fills an existing spool or
host filesystem. The slow webhook fixture sends only to its own literal
loopback sink. Do not treat those focused fault boundaries as proof of all
possible hardware failures.

Trace files retain failures, source-observer resets, kernel/output drop-counter
intervals, source/database ID-set hashes, unique logical job counts, bounded spool
and resource samples, and exact PostgreSQL per-node assessment percentiles.
Failed/unavailable jobs cannot improve the latency denominator. The maximum
per-node p95 is labelled explicitly; it is not misrepresented as the pooled
p95. Observer overhead is present and declared. Missing fields or reset intervals
produce `unknown`; observed failures produce `fail`.

The source observer holds at most two million event identities and timestamps;
exceeding that bound fails the measurement. Assessment state counts and exact
percentiles use SQL aggregates, so the seven-day schedule does not silently
truncate a 5,000-row history. A soak uses a daily controller marker, requires
successful matching selected canary sequences and all seven day bins, and checks
both interval endpoints. No seven-day result exists until it is actually run.
The proposed envelope remains three nodes, 100 selected records/s/node for one
hour, a fivefold one-minute burst, zero unexplained discrepancy across matching
measured boundaries, p95 successful assessment under ten seconds after window
close, and recovery after a thirty-minute control-plane outage. Kernel-global
capture completeness remains unknown even when those bounded gates pass.

Assessment delay subtracts event-host window timestamps from control-plane
completion timestamps and therefore depends on aligned host clocks. Negative
lags are counted as clock anomalies and make the latency result unknown; they
are never clipped to zero. Nonnegative values do not establish a clock-sync
precision guarantee. Record the lab's actual clock synchronization and any
alignment measurements alongside the traces when interpreting a latency result.

Periodic lab samples and bounded recovery polls use row counts, grouped
assessment states/coverage and health; they do not select event IDs or compute a
full-window percentile. Recovery waits for the source-window persisted count,
assessment queue state and a health observation through the source-window end,
then performs one bounded exact snapshot per node. That final snapshot materializes
the exact sorted event-ID set, checks duplicate logical assessments and computes
the exact percentile over successful selected jobs. A mismatch remains a failure;
unavailable fields remain unknown or fail the measurement. A recovery timeout is
recorded even though one exact final attempt is still retained for diagnosis.

Each trace and summary records periodic/exact snapshot counts, identity query
statement counts, IDs materialized, percentile query counts, backend query elapsed
time and whole-sample observer elapsed time. The pre-change source path can be
reconstructed as two identity selects and a full-window percentile query per
capture, but no live pre-change timing baseline was collected. These instrumentation
counts and test-double results are not evidence of a production speedup; compare
observer cost only in a later controlled measurement with workload and settings
recorded.
