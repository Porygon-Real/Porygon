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
