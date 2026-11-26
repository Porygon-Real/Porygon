#!/usr/bin/env python3
"""Scan an undeployed imported image with no repository digest through the live API."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from uuid import uuid4

from porygon_scan import _load_env, request


def docker(*arguments: str) -> str:
    return subprocess.check_output(["docker", *arguments], text=True).strip()


def main() -> int:
    _load_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-image", default="alpine:3.20")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/local/local-sparse-validation/local-scan.json"),
    )
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()
    base = f"http://127.0.0.1:{os.getenv('BACKEND_PORT', '8000')}"
    run_id = uuid4().hex
    source = None
    image_id = None
    created_image = False
    try:
        base_id = docker("image", "inspect", args.base_image, "--format", "{{.Id}}")
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", base_id)
        source = docker(
            "create",
            "--network",
            "none",
            "--label",
            "com.porygon.test=local-scan-source",
            base_id,
            "true",
        )
        with tempfile.TemporaryDirectory(prefix="porygon-local-scan-") as directory:
            archive = Path(directory) / "rootfs.tar"
            subprocess.run(["docker", "export", "--output", str(archive), source], check=True)
            imported = docker("image", "import", str(archive))
            image_id = json.loads(docker("image", "inspect", imported))[0]["Id"]
            created_image = True
        image = json.loads(docker("image", "inspect", image_id))[0]
        assert image["Id"] == image_id and not image.get("RepoDigests")
        assert not docker("ps", "--all", "--filter", "ancestor=" + image_id, "--format", "{{.ID}}")
        logical_host = os.getenv("PORYGON_DOCKER_HOST_ID", "auto")
        host = docker("info", "--format", "{{.ID}}") if logical_host == "auto" else logical_host
        identity = "local:" + image_id
        payload = {
            "image_identity": identity,
            "docker_host_id": host,
            "requested_by": "verification",
            "scan_reference": "local-acceptance-" + run_id,
        }
        first = request("POST", base + "/operator/v1/image-scans", operator=True, payload=payload)
        repeated = request(
            "POST", base + "/operator/v1/image-scans", operator=True, payload=payload
        )
        assert first["scan_id"] == repeated["scan_id"]
        assert first["identity_kind"] == "local_image_id"
        deadline = time.monotonic() + args.timeout
        detail = None
        while time.monotonic() < deadline:
            detail = request("GET", base + "/api/v1/image-scans/" + first["scan_id"])
            if detail["scan"]["status"] in {"completed", "failed"}:
                break
            time.sleep(2)
        assert detail is not None and detail["scan"]["status"] == "completed", detail
        scan = detail["scan"]
        assert scan["image_identity"] == identity and scan["image_id"] == image_id
        assert scan["scanner_metadata"]["docker_host_id"] == host
        assert scan["scanner_metadata"]["image_identity"]["repo_digests"] == []
        assert scan["scanner_metadata"]["image_identity"]["identity_kind"] == "local_image_id"
        assert "config_digest" not in scan["scanner_metadata"]["image_identity"]
        assert scan["scanner_metadata"]["image_identity"]["docker_descriptor"] == image.get("Descriptor")
        report = request("GET", base + "/api/v1/image-scans/" + scan["scan_id"] + "/report")
        sbom = request("GET", base + "/api/v1/image-scans/" + scan["scan_id"] + "/sbom")
        assert report["document"]["Metadata"]["ImageID"] == image_id
        assert sbom["document"]["bomFormat"] == "CycloneDX"
        assert sbom["identity_kind"] == "local_image_id"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(
                {
                    "base_image_id": base_id,
                    "local_image_id": image_id,
                    "docker_host_id": host,
                    "deployed": False,
                    "scan": scan,
                    "report_sha256": report["document_sha256"],
                    "sbom_sha256": sbom["document_sha256"],
                    "sbom_components": sbom["component_count"],
                },
                indent=2,
            )
            + "\n"
        )
        print(
            f"[PASS] Undeployed local image scanned by full Docker image ID; duplicate request reused its scan; {sbom['component_count']} SBOM components"
        )
        return 0
    finally:
        if source:
            subprocess.run(
                ["docker", "rm", "--force", source],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if created_image:
            subprocess.run(
                ["docker", "image", "rm", image_id],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    raise SystemExit(main())
