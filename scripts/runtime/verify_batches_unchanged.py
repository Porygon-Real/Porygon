#!/usr/bin/env python3
"""Check that adding batch 3 left batches 1 and 2 untouched.

Compares the current dataset with the snapshot taken before batch 3 started
(datasets/runtime/archive/batch1-2-<date>/), whose tables already carry the
batch column:

  - the batch1 and batch2 rows of windows.csv, rule_matches.csv,
    process_events.csv and images.csv are identical, in order, to the snapshot;
  - per_batch.batch1, per_batch.batch2 and every batch 1/2 per_image figure in
    summary.json equal the snapshot's;
  - every raw/ file listed in the snapshot's manifest still has its checksum.

Exit code 1 lists every difference. Nothing here writes to the dataset.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rt_common import RUNTIME_ROOT, read_json, sha256_file  # noqa: E402

TABLES = ("windows.csv", "rule_matches.csv", "process_events.csv", "images.csv")
KEPT = {"batch1", "batch2"}
csv.field_size_limit(10**9)


def rows_of(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.reader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", default=str(RUNTIME_ROOT / "archive" / "batch1-2-2026-11-21"))
    args = parser.parse_args()
    snap = Path(args.snapshot)
    problems: list[str] = []
    if not snap.is_dir():
        print(f"FAIL snapshot {snap} is missing")
        return 1
    for name in TABLES:
        current, snapshot = rows_of(RUNTIME_ROOT / name), rows_of(snap / name)
        if current[0] != snapshot[0]:
            problems.append(f"{name}: header changed")
            continue
        index = current[0].index("batch")
        kept_now = [r for r in current[1:] if r[index] in KEPT]
        if kept_now == snapshot[1:]:
            print(f"OK   {name}: {len(kept_now)} batch 1/2 rows identical to the snapshot")
        else:
            problems.append(f"{name}: {len(kept_now)} batch 1/2 rows vs {len(snapshot) - 1} in the snapshot")
    now, then = read_json(RUNTIME_ROOT / "summary.json", {}) or {}, read_json(snap / "summary.json", {}) or {}
    for batch in sorted(KEPT):
        if (now.get("per_batch") or {}).get(batch) != (then.get("per_batch") or {}).get(batch):
            problems.append(f"summary.json per_batch.{batch} changed")
    for image, figures in (then.get("per_image") or {}).items():
        if (now.get("per_image") or {}).get(image) != figures:
            problems.append(f"summary.json per_image.{image} changed")
    if not any(p.startswith("summary.json") for p in problems):
        print("OK   summary.json: batch 1 and 2 figures equal the snapshot")
    checked = 0
    for name, digest in ((read_json(snap / "manifest.json", {}) or {}).get("files") or {}).items():
        if name.startswith("raw/"):
            path = RUNTIME_ROOT / name
            if not path.is_file():
                problems.append(f"raw file missing: {name}")
            elif sha256_file(path) != digest:
                problems.append(f"raw file changed: {name}")
            else:
                checked += 1
    print(f"OK   raw/: {checked} batch 1/2 files match the snapshot's checksums")
    for problem in problems:
        print("FAIL", problem)
    print("batches 1 and 2 unchanged" if not problems else f"{len(problems)} problem(s)")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
