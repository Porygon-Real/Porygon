from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from experiments import runtime_binding as target


def _services(project: str | None = None, *, missing: str | None = None):
    values = []
    for service in target.REQUIRED_SERVICES:
        if service == missing:
            continue
        port = (
            {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8000"}]}
            if service == "gateway"
            else {}
        )
        values.append(
            {
                "Id": f"container-{service}",
                "Name": f"/{project or 'study'}-{service}-1",
                "Image": f"image-{service}",
                "State": {"Status": "running", "Health": {"Status": "healthy"}},
                "Config": {
                    "Labels": {
                        target.PROJECT_LABEL: project or "study",
                        target.SERVICE_LABEL: service,
                        target.WORKDIR_LABEL: str(target.ROOT),
                        target.CONFIG_FILES_LABEL: str(target.ROOT / "compose.yaml"),
                    }
                },
                "NetworkSettings": {"Ports": port},
            }
        )
    return values


def _install_docker(monkeypatch, *, project="study", endpoint="unix:///var/run/docker.sock", missing=None):
    values = _services(project, missing=missing)

    def fake_run(context, *args, timeout=30):
        if args[:3] == ("context", "inspect", "test-context"):
            value = "test-context" if args[-1] == "{{.Name}}" else endpoint
            return SimpleNamespace(returncode=0, stdout=value, stderr="")
        if args[:2] == ("info", "--format"):
            return SimpleNamespace(returncode=0, stdout="daemon-fixture", stderr="")
        if args[:1] == ("ps",):
            return SimpleNamespace(
                returncode=0,
                stdout="\n".join(item["Id"] for item in values),
                stderr="",
            )
        if args[:1] == ("inspect",):
            selected = set(args[1:])
            rows = [item for item in values if item["Id"] in selected]
            return SimpleNamespace(returncode=0, stdout=json.dumps(rows), stderr="")
        raise AssertionError(f"unexpected Docker preflight command: {args}")

    monkeypatch.setattr(target, "_run", fake_run)
    return values


def test_binding_requires_explicit_nonprimary_project_and_context(monkeypatch):
    calls = []
    monkeypatch.setattr(target, "_run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(target.RuntimeBindingError, match="primary"):
        target.resolve_runtime_binding("porygon", "test-context", "http://127.0.0.1:8000")
    with pytest.raises(target.RuntimeBindingError, match="context"):
        target.resolve_runtime_binding("study", "", "http://127.0.0.1:8000")
    assert calls == []


def test_binding_requires_local_unix_socket(monkeypatch):
    _install_docker(monkeypatch, endpoint="tcp://remote.invalid:2376")
    with pytest.raises(target.RuntimeBindingError, match="local Unix-socket"):
        target.resolve_runtime_binding("study", "test-context", "http://127.0.0.1:8000")


def test_binding_rejects_missing_or_foreign_project_services(monkeypatch):
    _install_docker(monkeypatch, missing="telemetry")
    with pytest.raises(target.RuntimeBindingError, match="telemetry"):
        target.resolve_runtime_binding("study", "test-context", "http://127.0.0.1:8000")

    _install_docker(monkeypatch, project="porygon")
    with pytest.raises(target.RuntimeBindingError, match="foreign container"):
        target.resolve_runtime_binding("study", "test-context", "http://127.0.0.1:8000")


def test_binding_rejects_unhealthy_or_wrong_worktree_service(monkeypatch):
    values = _install_docker(monkeypatch)
    values[0]["State"]["Health"]["Status"] = "starting"
    with pytest.raises(target.RuntimeBindingError, match="not healthy"):
        target.resolve_runtime_binding("study", "test-context", "http://127.0.0.1:8000")

    values = _install_docker(monkeypatch)
    values[0]["Config"]["Labels"][target.WORKDIR_LABEL] = "/tmp/another-project"
    with pytest.raises(target.RuntimeBindingError, match="isolated worktree"):
        target.resolve_runtime_binding("study", "test-context", "http://127.0.0.1:8000")


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:9000",
        "http://192.0.2.20:8000",
        "http://localhost:8000",
        "https://127.0.0.1:8000",
    ],
)
def test_binding_rejects_api_origin_not_bound_to_gateway(monkeypatch, base_url):
    _install_docker(monkeypatch)
    with pytest.raises(target.RuntimeBindingError):
        target.resolve_runtime_binding("study", "test-context", base_url)


def test_binding_hash_and_resume_comparison_cover_all_target_identities(monkeypatch):
    _install_docker(monkeypatch)
    first = target.resolve_runtime_binding(
        "study", "test-context", "http://127.0.0.1:8000"
    )
    document = first.to_dict()
    restored = target.binding_from_document(document)
    assert restored == first
    assert target.binding_from_document(document).sha256 == first.sha256

    drifted = dict(document)
    drifted["services"] = dict(document["services"])
    drifted["services"]["backend"] = dict(document["services"]["backend"])
    drifted["services"]["backend"]["container_id"] = "replacement"
    with pytest.raises(target.RuntimeBindingError, match="changed"):
        target.assert_binding_matches(first, target.binding_from_document(drifted))
    drifted_daemon = dict(document)
    drifted_daemon["daemon_id"] = "other-daemon"
    with pytest.raises(target.RuntimeBindingError, match="changed"):
        target.assert_binding_matches(first, target.binding_from_document(drifted_daemon))


def test_ipv6_loopback_binding_is_canonical_and_family_matched(monkeypatch):
    values = _install_docker(monkeypatch)
    gateway = next(item for item in values if item["Config"]["Labels"][target.SERVICE_LABEL] == "gateway")
    gateway["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostIp"] = "::1"
    binding = target.resolve_runtime_binding(
        "study", "test-context", "http://[::1]:8000"
    )
    assert binding.api_origin == "http://[::1]:8000"


def test_binding_rejects_legacy_document_without_schema():
    with pytest.raises(target.RuntimeBindingError, match="resume is refused"):
        target.binding_from_document({"compose_project": "study"})


def test_run_target_collision_check_reads_names_only_and_fails_closed(monkeypatch):
    calls = []
    state = {"containers": "", "networks": ""}

    def fake_run(context, *args, timeout=30):
        calls.append(args)
        if args[:1] == ("ps",):
            return SimpleNamespace(returncode=0, stdout=state["containers"], stderr="")
        if args[:2] == ("network", "ls"):
            return SimpleNamespace(returncode=0, stdout=state["networks"], stderr="")
        raise AssertionError(f"unexpected command: {args}")

    monkeypatch.setattr(target, "_run", fake_run)
    binding = SimpleNamespace(docker_context="test-context")
    target.require_run_targets_absent(binding, ["trial-a", "trial-b"], "network-a")
    assert "inspect" not in [arg for call in calls for arg in call]

    state["containers"] = "trial-b\n"
    with pytest.raises(target.RuntimeBindingError, match="container name already exists"):
        target.require_run_targets_absent(binding, ["trial-a", "trial-b"], "network-a")
    state["containers"] = ""
    state["networks"] = "network-a\n"
    with pytest.raises(target.RuntimeBindingError, match="network name already exists"):
        target.require_run_targets_absent(binding, ["trial-a"], "network-a")
