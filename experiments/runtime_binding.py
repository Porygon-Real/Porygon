"""Explicit, inspected binding between a study run and one Compose project."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

from experiments.artifacts import canonical_json, sha256_file

ROOT = Path(__file__).resolve().parents[1]
PROJECT_LABEL = "com.docker.compose.project"
SERVICE_LABEL = "com.docker.compose.service"
WORKDIR_LABEL = "com.docker.compose.project.working_dir"
CONFIG_FILES_LABEL = "com.docker.compose.project.config_files"
REQUIRED_SERVICES = (
    "backend",
    "collector",
    "falco",
    "gateway",
    "postgres",
    "responder",
    "scanner",
    "telemetry",
)
SCHEMA_VERSION = "porygon.experiment.runtime-binding"


class RuntimeBindingError(RuntimeError):
    """A study target cannot be proved to belong to the explicitly selected stack."""


@dataclass(frozen=True)
class RuntimeBinding:
    compose_project: str
    docker_context: str
    docker_transport: str
    daemon_id: str
    compose_file_sha256: str
    api_origin: str
    services: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "compose_project": self.compose_project,
            "docker_context": self.docker_context,
            "docker_transport": self.docker_transport,
            "daemon_id": self.daemon_id,
            "compose_file_sha256": self.compose_file_sha256,
            "api_origin": self.api_origin,
            "services": self.services,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode()).hexdigest()

    def docker_argv(self, *args: str) -> list[str]:
        return ["docker", "--context", self.docker_context, *args]


def _run(context: str, *args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "--context", context, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _required_output(context: str, *args: str, timeout: int = 30) -> str:
    try:
        completed = _run(context, *args, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise RuntimeBindingError(
            f"Docker target preflight failed ({type(error).__name__})"
        ) from error
    if completed.returncode != 0:
        raise RuntimeBindingError("Docker target preflight failed")
    return completed.stdout.strip()


def _validate_selectors(project: str, context: str) -> None:
    if not isinstance(project, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{1,62}", project
    ):
        raise RuntimeBindingError("An explicit valid Compose project name is required")
    if project == "porygon":
        raise RuntimeBindingError("The primary Compose project is not a study target")
    if not isinstance(context, str) or not context.strip() or context != context.strip():
        raise RuntimeBindingError("An explicit Docker context is required")


def _service_inspection(value: dict[str, Any], project: str, service: str) -> dict[str, Any]:
    labels = (value.get("Config") or {}).get("Labels") or {}
    if labels.get(PROJECT_LABEL) != project or labels.get(SERVICE_LABEL) != service:
        raise RuntimeBindingError("Inspected container labels do not match the selected service")
    working_dir = labels.get(WORKDIR_LABEL)
    if not working_dir or Path(working_dir).resolve() != ROOT.resolve():
        raise RuntimeBindingError("Compose service was not created from this isolated worktree")
    config_files = labels.get(CONFIG_FILES_LABEL, "").split(",")
    expected_compose = str((ROOT / "compose.yaml").resolve())
    if len(config_files) != 1 or str(Path(config_files[0]).resolve()) != expected_compose:
        raise RuntimeBindingError("Compose service does not use the isolated worktree compose.yaml")
    state = value.get("State") or {}
    if state.get("Status") != "running":
        raise RuntimeBindingError(f"Selected Compose service is not running: {service}")
    health = (state.get("Health") or {}).get("Status")
    if health is not None and health != "healthy":
        raise RuntimeBindingError(f"Selected Compose service is not healthy: {service}")
    names = value.get("Name", "").lstrip("/")
    container_id = value.get("Id")
    image_id = value.get("Image")
    if not names or not container_id or not image_id:
        raise RuntimeBindingError(f"Selected Compose service identity is incomplete: {service}")
    identity: dict[str, Any] = {
        "container_id": container_id,
        "container_name": names,
        "image_id": image_id,
        "state": state["Status"],
        "health": health,
    }
    if service == "gateway":
        ports = value.get("NetworkSettings", {}).get("Ports") or {}
        mappings = ports.get("8080/tcp") or []
        if len(mappings) != 1:
            raise RuntimeBindingError("Selected gateway must have exactly one published API port")
        identity["published_api_port"] = {
            "host_ip": mappings[0].get("HostIp"),
            "host_port": mappings[0].get("HostPort"),
        }
    return identity


def _validate_api_origin(base_url: str, gateway: dict[str, Any]) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeBindingError("Study API must use a loopback HTTP gateway origin")
    published = gateway["published_api_port"]
    if published.get("host_ip") not in {"127.0.0.1", "::1"}:
        raise RuntimeBindingError("Selected gateway is not published on loopback")
    try:
        url_port = parsed.port
        host_port = int(published["host_port"])
    except (TypeError, ValueError) as error:
        raise RuntimeBindingError("Study API and gateway ports are invalid") from error
    if (
        url_port is None
        or url_port != host_port
        or parsed.hostname != published["host_ip"]
    ):
        raise RuntimeBindingError("Study API endpoint does not match the selected gateway")
    hostname = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
    return f"http://{hostname}:{url_port}"


def resolve_runtime_binding(
    compose_project: str, docker_context: str, base_url: str
) -> RuntimeBinding:
    """Read-only preflight; no image, network, or workload is created here."""
    _validate_selectors(compose_project, docker_context)
    context_name = _required_output(
        "default",
        "context",
        "inspect",
        docker_context,
        "--format",
        "{{.Name}}",
    )
    if context_name != docker_context:
        raise RuntimeBindingError("Docker context name did not validate exactly")
    endpoint = _required_output(
        "default",
        "context",
        "inspect",
        docker_context,
        "--format",
        "{{.Endpoints.docker.Host}}",
    )
    endpoint_url = urlsplit(endpoint)
    if (
        endpoint_url.scheme != "unix"
        or endpoint_url.netloc
        or not endpoint_url.path.startswith("/")
    ):
        raise RuntimeBindingError("Only a local Unix-socket Docker context is supported")
    daemon_id = _required_output(docker_context, "info", "--format", "{{.ID}}")
    if not daemon_id:
        raise RuntimeBindingError("Selected Docker daemon returned no stable identity")
    ids_text = _required_output(
        docker_context,
        "ps",
        "--all",
        "--quiet",
        "--filter",
        f"label={PROJECT_LABEL}={compose_project}",
    )
    ids = sorted(set(ids_text.split()))
    if not ids:
        raise RuntimeBindingError("Selected Compose project has no containers")
    inspection_text = _required_output(
        docker_context, "inspect", *ids, timeout=60
    )
    try:
        inspections = json.loads(inspection_text)
    except json.JSONDecodeError as error:
        raise RuntimeBindingError("Selected Compose inspection is not valid JSON") from error
    found: dict[str, list[dict[str, Any]]] = {service: [] for service in REQUIRED_SERVICES}
    for item in inspections:
        labels = (item.get("Config") or {}).get("Labels") or {}
        if labels.get(PROJECT_LABEL) != compose_project:
            raise RuntimeBindingError("Selected project inspection included a foreign container")
        service = labels.get(SERVICE_LABEL)
        if service in found:
            found[service].append(item)
    missing = [name for name, items in found.items() if len(items) != 1]
    if missing:
        raise RuntimeBindingError(
            "Selected Compose project must have exactly one container per required service: "
            + ", ".join(missing)
        )
    services = {
        service: _service_inspection(items[0], compose_project, service)
        for service, items in found.items()
    }
    api_origin = _validate_api_origin(base_url, services["gateway"])
    return RuntimeBinding(
        compose_project,
        docker_context,
        "local-unix-socket",
        daemon_id,
        sha256_file(ROOT / "compose.yaml"),
        api_origin,
        services,
    )


def binding_from_document(document: dict[str, Any]) -> RuntimeBinding:
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeBindingError("Run has no supported runtime binding; resume is refused")
    try:
        binding = RuntimeBinding(
            compose_project=document["compose_project"],
            docker_context=document["docker_context"],
            docker_transport=document["docker_transport"],
            daemon_id=document["daemon_id"],
            compose_file_sha256=document["compose_file_sha256"],
            api_origin=document["api_origin"],
            services=document["services"],
        )
    except (KeyError, TypeError) as error:
        raise RuntimeBindingError("Run runtime binding is incomplete") from error
    _validate_selectors(binding.compose_project, binding.docker_context)
    if (
        set(binding.services) != set(REQUIRED_SERVICES)
        or not binding.daemon_id
        or binding.docker_transport != "local-unix-socket"
    ):
        raise RuntimeBindingError("Run runtime binding identities are incomplete")
    return binding


def assert_binding_matches(expected: RuntimeBinding, actual: RuntimeBinding) -> None:
    if expected.to_dict() != actual.to_dict():
        raise RuntimeBindingError(
            "Selected Docker project, daemon, gateway, or service identity changed; resume is refused"
        )


def require_run_targets_absent(
    binding: RuntimeBinding, container_names: list[str], network_name: str
) -> None:
    """Refuse name collisions without inspecting container environment/config."""
    if len(set(container_names)) != len(container_names):
        raise RuntimeBindingError("Planned trial container names are not unique")
    existing = set(
        _required_output(
            binding.docker_context, "ps", "--all", "--format", "{{.Names}}"
        ).splitlines()
    )
    if existing.intersection(container_names):
        raise RuntimeBindingError("A planned trial container name already exists")
    networks = _required_output(
        binding.docker_context,
        "network",
        "ls",
        "--format",
        "{{.Name}}",
        "--filter",
        f"name=^{network_name}$",
    )
    if network_name in networks.splitlines():
        raise RuntimeBindingError("A planned experiment network name already exists")
