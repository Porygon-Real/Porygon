#!/usr/bin/env python3
"""Check that adding batch 2 left batch 1's evidence untouched.

Compares the current dataset with the snapshot taken before batch 2 started
(datasets/runtime/archive/batch1-<date>/):

  - with the "batch" column dropped, the batch1 rows of windows.csv,
    rule_matches.csv, process_events.csv and images.csv are identical in content
    to the snapshot, and re-serialise to the same bytes;
  - the batch 1 figures in summary.json equal the snapshot's;
  - batch 1's raw files still have the checksums in the snapshot's manifest.

Exit code 1 lists every difference. Nothing here writes to the dataset.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rt_common import RUNTIME_ROOT, read_json, sha256_file  # noqa: E402

TABLES = ("windows.csv", "rule_matches.csv", "process_events.csv", "images.csv")
csv.field_size_limit(10**9)


def rows_of(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.reader(handle))


def batch1_rows_without_batch_column(path: Path) -> tuple[list[list[str]], list[str]]:
    """The batch1 rows of a two-batch table, with the batch column removed."""
    rows = rows_of(path)
    if not rows:
        return [], ["empty table"]
    header = rows[0]
    problems = []
    if header[-1] != "batch":
        problems.append(f"{path.name}: last column is {header[-1]!r}, expected 'batch'")
        return [], problems
    out = [header[:-1]]
    for row in rows[1:]:
        if row[-1] == "batch1":
            out.append(row[:-1])
    return out, problems


def serialise(rows: list[list[str]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def compare_summary(current: dict, snapshot: dict) -> list[str]:
    problems = []
    batch1 = (current.get("per_batch") or {}).get("batch1")
    if batch1 is None:
        return ["summary.json has no per_batch.batch1 block"]
    pairs = [("per_batch.batch1.incident_verdict", batch1["incident_verdict"], snapshot["overall_incident_verdict"]),
             ("per_batch.batch1.score_verdict", batch1["score_verdict"], snapshot["overall_score_verdict"]),
             ("per_batch.batch1.hard_negative_false_positive_rate",
              batch1["hard_negative_false_positive_rate"], snapshot["hard_negative_false_positive_rate"])]
    for name, now_value, then_value in pairs:
        if now_value != then_value:
            problems.append(f"{name} changed: {json.dumps(now_value, sort_keys=True)} != "
                            f"{json.dumps(then_value, sort_keys=True)}")
    for key in ("per_image", "per_scenario"):
        for image, figures in (snapshot.get(key) or {}).items():
            if key == "per_image" and image not in (current.get(key) or {}):
                problems.append(f"summary.json {key}.{image} is missing")
            elif key == "per_image" and current[key][image] != figures:
                problems.append(f"summary.json {key}.{image} changed")
    for image, state in (snapshot.get("images") or {}).items():
        if (current.get("images") or {}).get(image) != state:
            problems.append(f"summary.json images.{image} changed: "
                            f"{(current.get('images') or {}).get(image)} != {state}")
    if batch1["per_kind"] != snapshot["per_kind"]:
        problems.append("summary.json per_batch.batch1.per_kind differs from batch 1's per_kind")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", default=str(RUNTIME_ROOT / "archive" / "batch1-2026-11-21"))
    parser.add_argument("--current", default=str(RUNTIME_ROOT))
    parser.add_argument("--raw-root", default=str(RUNTIME_ROOT), help="where raw/ lives (export never writes it)")
    args = parser.parse_args()
    snap, cur, raw_root = Path(args.snapshot), Path(args.current), Path(args.raw_root)
    problems: list[str] = []
    if not snap.is_dir():
        print(f"FAIL snapshot {snap} is missing")
        return 1

    for name in TABLES:
        current_rows, found = batch1_rows_without_batch_column(cur / name)
        problems += found
        if found:
            continue
        snapshot_rows = rows_of(snap / name)
        if current_rows == snapshot_rows:
            if serialise(current_rows) != (snap / name).read_bytes():
                problems.append(f"{name}: batch1 rows match but re-serialise to different bytes")
            else:
                print(f"OK   {name}: {len(current_rows) - 1} batch1 rows identical to the snapshot")
            continue
        problems.append(f"{name}: {len(current_rows) - 1} batch1 rows vs {len(snapshot_rows) - 1} in the snapshot")
        shown = 0
        for index, (a, b) in enumerate(zip(current_rows, snapshot_rows)):
            if a != b and shown < 3:
                problems.append(f"  {name} line {index + 1}: {a[:6]} != {b[:6]}")
                shown += 1

    current_summary = read_json(cur / "summary.json", {}) or {}
    snapshot_summary = read_json(snap / "summary.json", {}) or {}
    summary_problems = compare_summary(current_summary, snapshot_summary)
    problems += summary_problems
    if not summary_problems:
        print("OK   summary.json: batch 1 figures equal the snapshot")

    manifest = (read_json(snap / "manifest.json", {}) or {}).get("files", {})
    raw_checked = 0
    for name, digest in manifest.items():
        if not name.startswith("raw/"):
            continue
        path = raw_root / name
        if not path.is_file():
            problems.append(f"batch 1 raw file missing: {name}")
        elif sha256_file(path) != digest:
            problems.append(f"batch 1 raw file changed: {name}")
        else:
            raw_checked += 1
    print(f"OK   raw/: {raw_checked} batch 1 files match the snapshot's checksums"
          if raw_checked else "FAIL no batch 1 raw files checked")

    for problem in problems:
        print("FAIL", problem)
    print("batch 1 unchanged" if not problems else f"{len(problems)} problem(s)")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
