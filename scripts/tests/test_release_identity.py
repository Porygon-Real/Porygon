"""Release identities bind source, service role, dependency graph and actual SBOM bytes."""

import hashlib
import json
from types import SimpleNamespace
import pytest
from scripts import check_release_manifest as release


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    source = {
        "commit": "c" * 40,
        "tree_sha256": "d" * 64,
        "files": {"app.py": digest(root / "app.py")},
    }
    output = tmp_path / "release"
    output.mkdir()
    services = {}
    images = {}
    for index, service in enumerate(release.SERVICES):
        (root / service).mkdir()
        (root / service / "requirements.lock").write_text("fixture==1\n")
        image = "sha256:" + str(index + 1) * 64
        lock = digest(root / service / "requirements.lock")
        sbom = output / (service + ".json")
        sbom.write_text(
            json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": service}]})
        )
        receipt = output / (service + ".binding.json")
        receipt.write_text(
            json.dumps(
                {
                    "tool": "syft",
                    "image_id": image,
                    "source_tree_sha256": source["tree_sha256"],
                    "sbom_sha256": digest(sbom),
                }
            )
        )
        services[service] = {
            "image_id": image,
            "lock_sha256": lock,
            "sbom_path": sbom.name,
            "sbom_sha256": digest(sbom),
            "sbom_binding_path": receipt.name,
            "sbom_binding_sha256": digest(receipt),
        }
        images[image] = {
            "Id": image,
            "Config": {
                "Labels": {
                    "com.porygon.service": service,
                    "org.opencontainers.image.revision": source["commit"],
                    "com.porygon.source-tree-sha256": source["tree_sha256"],
                    "com.porygon.dependency-lock-sha256": lock,
                }
            },
        }
    manifest = output / "release.json"
    manifest.write_text(
        json.dumps(
            {
                "contract": "porygon.release-manifest",
                "source": source,
                "services": services,
            }
        )
    )
    monkeypatch.setattr(release, "ROOT", root)
    monkeypatch.setattr(release, "source_identity", lambda: source)

    def fake_run(args, **kwargs):
        assert kwargs["timeout"] == 30
        if args[:3] == ["git", "cat-file", "-e"]:
            return SimpleNamespace(stdout=b"")
        if args[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(stdout=json.dumps([images[args[-1]]]).encode())
        raise AssertionError("No build/push/run is allowed in manifest validation")

    monkeypatch.setattr(release.subprocess, "run", fake_run)
    return root, output, manifest, images


def test_matching_identity_passes_and_source_tamper_is_refused(bundle):
    root, _output, manifest, _images = bundle
    assert release.validate(manifest)["valid"]
    (root / "app.py").write_text("value = 2\n")
    with pytest.raises(ValueError, match="Source hash"):
        release.validate(manifest)


def test_swapped_service_image_role_and_altered_sbom_are_refused(bundle):
    _root, output, manifest, images = bundle
    images["sha256:" + "1" * 64]["Config"]["Labels"]["com.porygon.service"] = "scanner"
    with pytest.raises(ValueError, match="provenance"):
        release.validate(manifest)
    images["sha256:" + "1" * 64]["Config"]["Labels"]["com.porygon.service"] = "backend"
    (output / "backend.json").write_text("{}")
    with pytest.raises(ValueError, match="SBOM hash"):
        release.validate(manifest)


def test_release_paths_cannot_escape_or_follow_symlinks(bundle):
    root, output, _manifest, _images = bundle
    (output / "link").symlink_to(root / "app.py")
    for name in ("../source/app.py", str(root / "app.py"), "link"):
        with pytest.raises(ValueError):
            release.confined(output, name)
