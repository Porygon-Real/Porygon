#!/usr/bin/env python3
"""Check the runtime dataset against its raw records and Porygon's database.

  - ground truth was recorded before each window started
  - stored process-event counts per window still match Porygon's database
  - windows.csv verdicts match the raw detection JSON
  - every abnormal action has a return code and an action_seen_by_falco value
  - the protocol's timing: learning is exactly 30 min (40 where an extension is
    recorded), and there are exactly 30 windows of exactly 60 s, consecutive
  - manifest checksums match
  - no labelled runtime containers are left behind
Exit code 1 lists every failed check. Counts are reported per batch.
"""
from __future__ import annotations

import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rt_common import RAW_ROOT, RUNTIME_ROOT, db_json, check_digest, read_json, runtime_label_containers, sha256_file  # noqa: E402


LEARN_MINUTES = 30
EXTEND_MINUTES = 10
TEST_WINDOWS = 30
WINDOW_SECONDS = 60


def check_timing(rows: list[dict[str, str]]) -> list[str]:
    """The protocol's one hour per image, checked from the recorded timestamps."""
    problems: list[str] = []
    by_image: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_image[row["image_key"]].append(row)
    for key, window_rows in sorted(by_image.items()):
        status = read_json(RAW_ROOT / key / "status.json", {}) or {}
        if status.get("phase") != "complete":
            continue
        attempts = len(status.get("baseline_attempts") or [])
        expected = LEARN_MINUTES + (EXTEND_MINUTES if attempts > 1 else 0)
        start, end = status.get("training_start"), status.get("training_end")
        if not (start and end):
            problems.append(f"{key}: a completed run without a training period")
        else:
            span = datetime.fromisoformat(end) - datetime.fromisoformat(start)
            if span != timedelta(minutes=expected):
                problems.append(f"{key}: learning lasted {span}, expected {expected} min "
                                f"({attempts} baseline attempt(s))")
        ordered = sorted(window_rows, key=lambda r: int(r["window_index"]))
        if len(ordered) != TEST_WINDOWS:
            problems.append(f"{key}: {len(ordered)} test windows, expected {TEST_WINDOWS}")
        for row in ordered:
            if not (row["window_start"] and row["window_end"]):
                problems.append(f"{key} w{row['window_index']}: missing window bounds")
                continue
            length = datetime.fromisoformat(row["window_end"]) - datetime.fromisoformat(row["window_start"])
            if length != timedelta(seconds=WINDOW_SECONDS):
                problems.append(f"{key} w{row['window_index']}: window lasted {length}, expected "
                                f"{WINDOW_SECONDS} s")
        for earlier, later in zip(ordered, ordered[1:]):
            if not (earlier["window_end"] and later["window_start"]):
                continue
            gap = datetime.fromisoformat(later["window_start"]) - datetime.fromisoformat(earlier["window_end"])
            if gap != timedelta(0):
                problems.append(f"{key} w{earlier['window_index']}->w{later['window_index']}: "
                                f"windows are not consecutive ({gap} between them)")
    return problems


def main() -> int:
    problems: list[str] = []
    csv.field_size_limit(10**9)
    rows = list(csv.DictReader((RUNTIME_ROOT / "windows.csv").open(encoding="utf-8")))
    for r in rows:
        tag = f"{r['image_key']} w{r['window_index']}"
        if r["window_start"] and r["ground_truth_recorded_at"]:
            if datetime.fromisoformat(r["ground_truth_recorded_at"]) >= datetime.fromisoformat(r["window_start"]):
                problems.append(f"{tag}: ground truth recorded at/after window start")
        else:
            problems.append(f"{tag}: missing window_start or ground_truth_recorded_at")
        det = read_json(RAW_ROOT / r["image_key"] / "windows" / f"w{int(r['window_index']):02d}-detection.json", None)
        if det is not None and r["window_state"] == "done":
            expected = "abnormal" if det["run"]["incident_created"] else "normal"
            if r["porygon_verdict"] != expected:
                problems.append(f"{tag}: verdict {r['porygon_verdict']} != raw {expected}")
        if r["ground_truth"] == "abnormal":
            if r["action_returncode"] == "":
                problems.append(f"{tag}: abnormal action without return code")
            if r["action_seen_by_falco"] == "":
                problems.append(f"{tag}: abnormal action without action_seen_by_falco")
        if r["window_state"] == "done" and r["process_event_count"] != "":
            digest = check_digest(r["image_digest"])
            count = db_json(f"select count(*) from process_exec_events where image_digest = '{digest}' "
                            f"and occurred_at >= '{r['window_start']}' and occurred_at < '{r['window_end']}'")
            if count != int(r["process_event_count"]):
                problems.append(f"{tag}: score saw {r['process_event_count']} events, database now has {count}")
    problems += check_timing(rows)
    manifest = read_json(RUNTIME_ROOT / "manifest.json", {}) or {}
    for name, digest in manifest.get("files", {}).items():
        path = RUNTIME_ROOT / name
        if not path.is_file() or sha256_file(path) != digest:
            problems.append(f"manifest mismatch: {name}")
    leftovers = runtime_label_containers()
    if leftovers:
        problems.append(f"leftover runtime containers: {[c.get('Names') for c in leftovers]}")
    per_batch = Counter(r.get("batch") or "batch1" for r in rows)
    images = {(r.get("batch") or "batch1", r["image_key"]) for r in rows}
    per_batch_images = Counter(batch for batch, _ in images)
    print(f"{len(rows)} windows checked across {len(images)} images: "
          + ", ".join(f"{b} {per_batch[b]} windows / {per_batch_images[b]} images" for b in sorted(per_batch)))
    for p in problems:
        print("FAIL", p)
    print("OK" if not problems else f"{len(problems)} problem(s)")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
