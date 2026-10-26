# Local image scanning

Scan requests accept either `repository@sha256:<manifest-digest>` or `local:sha256:<64-hex-digits>`. `image_identity` is the canonical request field; `image_digest` remains an accepted legacy alias. Responses include `image_identity` and `identity_kind`; historical `image_digest` fields retain the same serialized identity string for compatibility. Conflicting aliases are rejected.

A local identity wraps the daemon's exact full image ID. Classic stores expose configuration digests; containerd stores can expose manifest/index digests. The scanner preserves the Docker descriptor rather than relabelling every ID as a config digest. Docker documents the [containerd store](https://docs.docker.com/engine/storage/containerd/), and containerd's [command reference](https://github.com/containerd/nerdctl/blob/main/docs/command-reference.md) describes its ID semantics. Registry identities still require a matching `RepoDigests` entry. Tags and truncated IDs are not scan identities.

## Queueing a local target

Use `python3 scripts/porygon_scan.py create --help` to inspect the arguments. Supply `--image-identity local:sha256:<64-hex-digits>`, `--requested-by`, and the target `--docker-host-id`. Obtain the full ID with `docker image inspect IMAGE --format '{{.Id}}'`; the automatic host identity comes from `docker info --format '{{.ID}}'`. A configured `PORYGON_DOCKER_HOST_ID` overrides that logical identity consistently across collector, telemetry and scanner.

An undeployed image can be queued without first creating a container or fabricating an inventory entry. In that case, the Docker host is required. The matching scanner verifies image availability and the complete Docker image ID before analysis. Known identities on multiple hosts also require explicit host selection.

New cache keys include the Docker host, immutable image identity, scanner/version and scan reference. Historical repository-based cache keys are reused only on their original host. `--scan-reference` requests a distinct immutable scan when a new analysis is needed. Both `scans` and `findings` accept `--image-identity` as an alias for their historical filter.

## Verification and provenance

The scanner discovers its Docker daemon identity and claims only matching jobs. Legacy workers without a host field can still consume repository jobs; they cannot claim local targets. The worker verifies the full Docker image ID before and after analysis, checks Trivy's reported `Metadata.ImageID`, and sends the target and host identities with the completion. The backend validates local provenance before committing findings and serializes completion, renewal and failure transitions.

Trivy runs with `--image-src docker`, restricting image acquisition to the selected Docker daemon. Its [container-image documentation](https://trivy.dev/docs/dev/guide/target/container_image/) describes the source-selection flag. Vulnerability databases and threat intelligence retain their existing update paths and recorded provenance.

Local SBOMs, reports and findings retain the `local:` identity. Deployment/runtime exposure is resolved by image ID and host, rather than pretending an absent repository digest exists. Repository exposure is also host-scoped. A container or process on another daemon does not increase the target's exposure stage.

## Acceptance

`python3 scripts/verify_local_image_scan.py` exports a disposable cached Alpine root filesystem, imports it as a new image with no repository digest, queues it without deployment, checks duplicate-request identity, and verifies a real Trivy report and CycloneDX SBOM. It removes its disposable source container, imported image and temporary archive afterward. The saved scan and artifact hashes remain available for review.
