"""Local operator transport for internal API requests over Docker exec.

Browser-facing routes stay on the gateway. A local CLI with Docker access can
address internal routes without a published backend port or a gateway bypass.
Caller-supplied service authentication is still checked by the backend.
"""

from __future__ import annotations

import base64
from email.message import Message
from http import HTTPStatus
from io import BytesIO
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import urllib.response

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = """
import base64, json, sys, urllib.request, urllib.error
request = json.load(sys.stdin)
data = base64.b64decode(request['body']) if request['body'] else None
req = urllib.request.Request('http://127.0.0.1:8000' + request['path'],
    data=data, method=request['method'], headers=request['headers'])
try:
    response = urllib.request.urlopen(req, timeout=request['timeout'])
except urllib.error.HTTPError as exc:
    response = exc
with response:
    body = response.read(64 * 1024 * 1024 + 1)
    if len(body) > 64 * 1024 * 1024:
        raise ValueError('private API response exceeds limit')
    print(json.dumps({'status': response.status,
        'content_type': response.headers.get('Content-Type', 'application/json'),
        'body': base64.b64encode(body).decode('ascii')}))
"""


def open_backend(
    request: urllib.request.Request, timeout: float = 30
) -> urllib.response.addinfourl:
    parsed = urllib.parse.urlsplit(request.full_url)
    path = parsed.path + ("?" + parsed.query if parsed.query else "")
    payload = {
        "path": path,
        "method": request.get_method(),
        "headers": dict(request.header_items()),
        "body": base64.b64encode(request.data or b"").decode("ascii"),
        "timeout": timeout,
    }
    try:
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "backend", "python", "-c", BRIDGE],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=timeout + 10,
            cwd=ROOT,
            check=True,
        )
        value = json.loads(result.stdout)
        body = base64.b64decode(value["body"], validate=True)
        code = int(value["status"])
        headers = Message()
        headers["Content-Type"] = value["content_type"]
        headers["Content-Length"] = str(len(body))
    except (subprocess.SubprocessError, ValueError, KeyError) as exc:
        raise urllib.error.URLError(
            "Private API transport unavailable; check the backend container"
        ) from exc
    response = urllib.response.addinfourl(
        BytesIO(body), headers, request.full_url, code
    )
    if code >= 400:
        raise urllib.error.HTTPError(
            request.full_url, code, HTTPStatus(code).phrase, headers, response
        )
    return response


def open_api(
    request: urllib.request.Request, timeout: float = 30
) -> urllib.response.addinfourl:
    parsed = urllib.parse.urlsplit(request.full_url)
    if parsed.hostname in {"127.0.0.1", "localhost", "::1"} and (
        parsed.path == "/internal" or parsed.path.startswith("/internal/")
    ):
        return open_backend(request, timeout)
    return urllib.request.urlopen(request, timeout=timeout)
