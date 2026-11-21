#!/usr/bin/env python3
"""Confirm the running backend judges with the expected detection matcher.

Batches 1 and 2 were judged by porygon.detection.matcher.v5, and batch 3 must be
judged by the same matcher. The check reads the revision from the running
backend container itself (not from the working tree) and records the backend's
image ID, so a rebuilt or replaced backend is caught even if it reports the same
revision. Every check is appended to datasets/runtime/<batch>-matcher-checks.jsonl.

Exit code 0 when the revision and image ID match, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rt_common import RUNTIME_ROOT, docker, utc_now  # noqa: E402

EXPECTED_REVISION = "porygon.detection.matcher.v5"


def observe() -> dict[str, str]:
    revision = docker("compose", "exec", "-T", "backend", "python", "-c",
                      "import porygon_api.detection as d; print(d.MATCHER_REVISION)", timeout=60)
    container = docker("compose", "ps", "-q", "backend").stdout.strip()
    image_id = docker("inspect", "--format", "{{.Image}}", container).stdout.strip() if container else ""
    started = docker("inspect", "--format", "{{.State.StartedAt}}", container).stdout.strip() if container else ""
    return {"revision": revision.stdout.strip(), "revision_error": revision.stderr.strip()[:300],
            "backend_container": container[:12], "backend_image_id": image_id, "backend_started_at": started}


def check(batch: str, when: str, expected_image: str | None = None) -> tuple[bool, dict]:
    seen = observe()
    problems = []
    if seen["revision"] != EXPECTED_REVISION:
        problems.append(f"matcher revision {seen['revision']!r} != {EXPECTED_REVISION!r}")
    if expected_image and seen["backend_image_id"] != expected_image:
        problems.append(f"backend image {seen['backend_image_id']} != {expected_image} recorded at pre-flight")
    record = {"time": utc_now(), "batch": batch, "when": when, "expected_revision": EXPECTED_REVISION,
              "expected_backend_image_id": expected_image, **seen, "ok": not problems, "problems": problems}
    path = RUNTIME_ROOT / f"{batch}-matcher-checks.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    return not problems, record


def preflight_image(batch: str) -> str | None:
    """The backend image ID recorded by the first (pre-flight) check of this batch."""
    path = RUNTIME_ROOT / f"{batch}-matcher-checks.jsonl"
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("when") == "preflight" and row.get("ok"):
            return row.get("backend_image_id")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--batch", default="batch3")
    parser.add_argument("--when", required=True, help="preflight, before:<image>, or end")
    args = parser.parse_args()
    expected = None if args.when == "preflight" else preflight_image(args.batch)
    if args.when != "preflight" and not expected:
        print("no successful pre-flight matcher check recorded")
        return 1
    ok, record = check(args.batch, args.when, expected)
    print(json.dumps(record))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
