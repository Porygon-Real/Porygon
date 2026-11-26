#!/usr/bin/env python3
"""Small authenticated CLI for the bounded custom-rule workbench API."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def load_document(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input file must contain one JSON object")
    return value


def request(base_url: str, token: str, path: str, method: str, body: dict[str, Any] | None) -> Any:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail", f"HTTP {exc.code}")
        except (ValueError, AttributeError):
            detail = f"HTTP {exc.code}"
        raise RuntimeError(str(detail)) from None
    return json.loads(raw) if raw else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("PORYGON_API_BASE_URL", "http://127.0.0.1:8000"))
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "draft"):
        command = sub.add_parser(name)
        command.add_argument("rule_json")
    for name in ("preview", "shadow"):
        command = sub.add_parser(name)
        command.add_argument("rule_id")
        command.add_argument("selection_json", help="event_ids or labeled fixtures JSON")
        command.add_argument("--expected-revision-hash", required=True)
    for name in ("activate", "disable"):
        command = sub.add_parser(name)
        command.add_argument("rule_id")
        command.add_argument("--reference", required=True)
        if name == "activate":
            command.add_argument("--expected-revision-hash", required=True)
    rollback = sub.add_parser("rollback")
    rollback.add_argument("rule_id")
    rollback.add_argument("revision_hash")
    rollback.add_argument("--expected-revision-hash", required=True)
    rollback.add_argument("--reference", required=True)
    args = parser.parse_args()

    token = os.environ.get("PORYGON_OPERATOR_API_TOKEN")
    if not token:
        parser.error("set PORYGON_OPERATOR_API_TOKEN in the environment")
    try:
        if args.command in {"validate", "draft"}:
            body = load_document(args.rule_json)
            path = "/operator/v1/rule-workbench/validate" if args.command == "validate" else "/operator/v1/rule-workbench/rules"
            result = request(args.base_url, token, path, "POST", body)
        elif args.command in {"preview", "shadow"}:
            body = load_document(args.selection_json)
            body["expected_revision_hash"] = args.expected_revision_hash
            result = request(args.base_url, token,
                            f"/operator/v1/rule-workbench/rules/{args.rule_id}/{args.command}",
                            "POST", body)
        elif args.command in {"activate", "disable"}:
            body = {"reference": args.reference}
            if args.command == "activate":
                body["expected_revision_hash"] = args.expected_revision_hash
            result = request(args.base_url, token,
                            f"/operator/v1/rule-workbench/rules/{args.rule_id}/{args.command}",
                            "POST", body)
        else:
            result = request(args.base_url, token,
                            f"/operator/v1/rule-workbench/rules/{args.rule_id}/rollback",
                            "POST", {"revision_hash": args.revision_hash, "reference": args.reference,
                                     "expected_revision_hash": args.expected_revision_hash})
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"rule workbench request failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
