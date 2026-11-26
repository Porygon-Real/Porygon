"""The local proxy forwards caller identity without adding a shared credential."""

import importlib.util
import io
from pathlib import Path
import sys
from unittest.mock import patch
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "dashboard_server", ROOT / "scripts/serve_dashboard.py"
)
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class Response(io.BytesIO):
    status = 200
    headers = {"Content-Type": "application/json"}


@pytest.mark.parametrize(
    "supplied",
    [
        {"Authorization": "Bearer human-token"},
        {"x-porygon-operator-token": "human-token"},
        {},
    ],
)
def test_proxy_does_not_inject_or_override_authentication(supplied, monkeypatch):
    monkeypatch.setenv(
        "PORYGON_OPERATOR_API_TOKEN", "shared-token-must-not-be-forwarded"
    )
    handler = object.__new__(server.DashboardHandler)
    handler.path = "/api/v1/services"
    handler.command = "GET"
    handler.headers = supplied
    handler.rfile = io.BytesIO()
    handler.wfile = io.BytesIO()
    handler.send_response = lambda *_: None
    handler.send_header = lambda *_: None
    handler.end_headers = lambda: None
    requests = []

    def respond(request, **kwargs):
        requests.append(request)
        return Response(b"{}")

    with patch.object(server.urllib.request, "urlopen", side_effect=respond):
        handler.proxy_api()
    actual = {key.lower(): value for key, value in requests[0].header_items()}
    assert {
        key: value
        for key, value in actual.items()
        if key in {"authorization", "x-porygon-operator-token"}
    } == {key.lower(): value for key, value in supplied.items()}
    assert "shared-token-must-not-be-forwarded" not in actual.values()
