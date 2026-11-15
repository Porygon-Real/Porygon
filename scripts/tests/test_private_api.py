import base64
import json
from types import SimpleNamespace
import urllib.error
import urllib.request

import pytest

from scripts import private_api


def test_internal_requests_preserve_method_body_and_service_authentication(monkeypatch):
    def execute(command, **options):
        assert command[:6] == ["docker", "compose", "exec", "-T", "backend", "python"]
        payload = json.loads(options["input"])
        assert payload["path"] == "/internal/v1/example?dry_run=true"
        assert payload["method"] == "POST"
        assert payload["headers"]["X-porygon-internal-token"] == "test-token"
        assert base64.b64decode(payload["body"]) == b'{"test":true}'
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "status": 200,
                    "content_type": "application/json",
                    "body": base64.b64encode(b'{"ok":true}').decode(),
                }
            )
        )

    monkeypatch.setattr(private_api.subprocess, "run", execute)
    request = urllib.request.Request(
        "http://127.0.0.1:8000/internal/v1/example?dry_run=true",
        data=b'{"test":true}',
        headers={"X-Porygon-Internal-Token": "test-token"},
    )
    with private_api.open_api(request) as response:
        assert response.status == 200
        assert json.load(response) == {"ok": True}


def test_bound_internal_request_targets_exact_validated_backend_id(monkeypatch):
    binding = SimpleNamespace(
        services={"backend": {"container_id": "backend-container-fixture"}},
        docker_argv=lambda *args: ["docker", "--context", "study-context", *args],
    )

    def execute(command, **options):
        assert command == [
            "docker",
            "--context",
            "study-context",
            "exec",
            "-i",
            "backend-container-fixture",
            "python",
            "-c",
            private_api.BRIDGE,
        ]
        assert json.loads(options["input"])["path"] == "/internal/v1/example"
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "status": 200,
                    "content_type": "application/json",
                    "body": base64.b64encode(b'{"bound":true}').decode(),
                }
            )
        )

    monkeypatch.setattr(private_api.subprocess, "run", execute)
    request = urllib.request.Request("http://127.0.0.1:8000/internal/v1/example")
    with private_api.open_api(request, runtime_binding=binding) as response:
        assert json.load(response) == {"bound": True}


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/api/v1/events",
        "https://remote.invalid/internal/v1/example",
    ],
)
def test_public_and_explicit_remote_routes_keep_their_original_transport(
    monkeypatch, url
):
    marker = object()
    monkeypatch.setattr(
        private_api.urllib.request, "urlopen", lambda request, timeout: marker
    )
    assert private_api.open_api(urllib.request.Request(url)) is marker


def test_internal_authentication_errors_remain_http_errors(monkeypatch):
    monkeypatch.setattr(
        private_api.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=json.dumps(
                {
                    "status": 401,
                    "content_type": "application/json",
                    "body": base64.b64encode(b'{"detail":"unauthorized"}').decode(),
                }
            )
        ),
    )
    with pytest.raises(urllib.error.HTTPError) as error:
        private_api.open_api(
            urllib.request.Request("http://localhost:8000/internal/v1/example")
        )
    assert error.value.code == 401
    assert json.load(error.value) == {"detail": "unauthorized"}
