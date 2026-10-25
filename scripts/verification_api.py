"""Run acceptance checks through Docker exec without publishing internal routes.

The temporary listener binds only to loopback and exists for the child command's
lifetime. Each request is executed inside the backend container with the caller's
original credentials. No backend ports or gateway exceptions are introduced.
"""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 64 * 1024 * 1024
BRIDGE = """
import base64, json, sys, urllib.request, urllib.error
request = json.load(sys.stdin)
data = base64.b64decode(request['body']) if request['body'] else None
req = urllib.request.Request('http://127.0.0.1:8000' + request['path'],
    data=data, method=request['method'], headers=request['headers'])
try:
    response = urllib.request.urlopen(req, timeout=180)
except urllib.error.HTTPError as exc:
    response = exc
with response:
    body = response.read(64 * 1024 * 1024 + 1)
    if len(body) > 64 * 1024 * 1024:
        raise ValueError('verification response exceeds limit')
    print(json.dumps({'status': response.status,
        'content_type': response.headers.get('Content-Type', 'application/json'),
        'body': base64.b64encode(body).decode('ascii')}))
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        # Never log URL query strings or service credentials.
        pass

    def forward(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > MAX_BODY:
            self.send_error(413)
            return
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.send_error(400)
            return
        request = {
            "path": self.path,
            "method": self.command,
            "headers": {
                key: value
                for key, value in self.headers.items()
                if key.lower() in {"content-type", "accept"}
                or key.lower().startswith("x-porygon-")
            },
            "body": base64.b64encode(self.rfile.read(length)).decode("ascii"),
        }
        try:
            result = subprocess.run(
                ["docker", "compose", "exec", "-T", "backend", "python", "-c", BRIDGE],
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=190,
                cwd=ROOT,
                check=True,
            )
            response = json.loads(result.stdout)
            body = base64.b64decode(response["body"])
        except (subprocess.SubprocessError, ValueError, KeyError):
            self.send_error(502, "Private verification transport unavailable")
            return
        self.send_response(response["status"])
        self.send_header("Content-Type", response["content_type"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = forward
    do_POST = forward
    do_PATCH = forward
    do_DELETE = forward
    do_PUT = forward


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit(
            "Usage: python3 scripts/verification_api.py command [arguments...]"
        )
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ)
    env["PORYGON_VERIFY_BASE_URL"] = f"http://127.0.0.1:{server.server_port}"
    try:
        return subprocess.run(sys.argv[1:], cwd=ROOT, env=env, check=False).returncode
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
