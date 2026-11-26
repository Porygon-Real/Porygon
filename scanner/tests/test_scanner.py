import pytest

from porygon_scanner.scanner import (
    database_cache_metadata,
    extract_cves,
    merge_intel,
    parse_epss,
    parse_kev,
)


def test_parse_epss_and_kev() -> None:
    epss = parse_epss(
        {
            "data": [
                {
                    "cve": "CVE-2025-12345",
                    "epss": "0.42",
                    "percentile": "0.91",
                    "date": "2026-07-21",
                }
            ]
        }
    )
    kev = parse_kev(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2025-12345",
                    "dateAdded": "2026-01-01",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }
    )
    merged = merge_intel(["CVE-2025-12345"], epss, kev, source_metadata={"partial": False})[0]
    assert merged["epss_score"] == 0.42
    assert merged["kev"] is True
    assert merged["source_metadata"]["epss_record_returned"] is True
    assert merged["source_metadata"]["kev_record_returned"] is True


def test_extract_cves_is_sorted_and_unique() -> None:
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2025-0002"},
                    {"VulnerabilityID": "CVE-2025-0001"},
                    {"VulnerabilityID": "CVE-2025-0002"},
                ]
            }
        ]
    }
    assert extract_cves(report) == ["CVE-2025-0001", "CVE-2025-0002"]


def test_extract_cves_drops_non_cve_vulnerability_ids() -> None:
    # Some scanners/plugins emit vendor-specific advisory IDs (e.g. GHSA-*) in
    # the same field; only well-formed CVE IDs should be treated as CVEs.
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2025-0003"},
                    {"VulnerabilityID": "GHSA-xxxx-yyyy-zzzz"},
                    {"VulnerabilityID": "CVE-2025-1"},  # too few digits, not a valid CVE ID
                ]
            }
        ]
    }
    assert extract_cves(report) == ["CVE-2025-0003"]


def test_database_cache_metadata_hashes_reproducibility_files(tmp_path) -> None:
    db = tmp_path / "db"
    db.mkdir()
    (db / "metadata.json").write_text('{"UpdatedAt":"2026-07-21"}')
    (db / "trivy.db").write_bytes(b"database-content")
    records = database_cache_metadata(str(tmp_path))
    assert [row["path"] for row in records] == ["db/metadata.json", "db/trivy.db"]
    assert all(len(row["sha256"]) == 64 for row in records)


def _scanner(image_id, digests):
    from types import SimpleNamespace
    from porygon_scanner.scanner import TrivyScanner

    scanner = object.__new__(TrivyScanner)
    image = SimpleNamespace(
        id=image_id, attrs={"Id": image_id, "RepoDigests": digests, "RepoTags": ["local:latest"]}
    )
    scanner.client = SimpleNamespace(images=SimpleNamespace(get=lambda target: image))
    return scanner


def test_local_full_id_does_not_require_repo_digests_or_mutable_tags():
    image_id = "sha256:" + "a" * 64
    scanner = _scanner(image_id, [])
    result = scanner.verify_image(image_id=image_id, image_digest="local:" + image_id)
    assert result["identity_kind"] == "local_image_id"
    assert result["image_id"] == image_id
    assert result["repo_digests"] == []


def test_local_id_and_registry_digest_are_never_interchangeable():
    import pytest
    from porygon_scanner.scanner import ScanError

    image_id = "sha256:" + "a" * 64
    scanner = _scanner(image_id, [])
    for target in (
        "local:sha256:" + "b" * 64,
        "local:sha256:abc",
        "repo@sha256:" + "a" * 64,
        image_id,
    ):
        with pytest.raises(ScanError) as error:
            scanner.verify_image(image_id=image_id, image_digest=target)
        assert error.value.code == "image_identity_mismatch"


def test_trivy_uses_only_the_verified_docker_daemon(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from porygon_scanner.scanner import TrivyScanner

    captured = []
    monkeypatch.setattr(
        "porygon_scanner.scanner.subprocess.run",
        lambda command, **kwargs: captured.append(command) or SimpleNamespace(returncode=0),
    )
    scanner = object.__new__(TrivyScanner)
    scanner.trivy_binary = "trivy"
    scanner.cache_dir = str(tmp_path)
    scanner.timeout_seconds = 30
    scanner._run_trivy(image_id="sha256:" + "a" * 64, output=tmp_path / "report.json")
    assert captured[0][captured[0].index("--image-src") + 1] == "docker"
    assert captured[0][-1] == "sha256:" + "a" * 64


@pytest.mark.parametrize("reported_id", [None, "sha256:" + "b" * 64])
def test_scanner_rejects_reports_without_the_verified_image_id(tmp_path, reported_id):
    import json
    import pytest
    from porygon_scanner.scanner import ScanError

    image_id = "sha256:" + "a" * 64
    scanner = _scanner(image_id, [])
    scanner._run_trivy = lambda *, image_id, output: output.write_text(
        json.dumps({"Metadata": {"ImageID": reported_id}})
    )
    scanner._convert_to_cyclonedx = lambda *, report, output: output.write_text("{}")
    with pytest.raises(ScanError) as error:
        scanner.scan(image_id=image_id, image_digest="local:" + image_id)
    assert error.value.code == "image_identity_mismatch"


def test_containerd_descriptor_ids_are_preserved_without_relabelling_as_config():
    image_id = "sha256:" + "a" * 64
    scanner = _scanner(image_id, [])
    image = scanner.client.images.get(image_id)
    image.attrs["Descriptor"] = {
        "digest": image_id,
        "mediaType": "application/vnd.oci.image.index.v1+json",
    }
    result = scanner.verify_image(image_id=image_id, image_digest="local:" + image_id)
    assert result["docker_descriptor"] == image.attrs["Descriptor"]
    assert "config_digest" not in result


def test_local_registry_hostname_retains_repository_digest_validation():
    image_id = "sha256:" + "a" * 64
    target = "local:5000/team/app@sha256:" + "b" * 64
    result = _scanner(image_id, [target]).verify_image(image_id=image_id, image_digest=target)
    assert result["identity_kind"] == "repository_digest"
