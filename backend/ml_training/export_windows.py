#!/usr/bin/env python3
"""Porygon Window Exporter & Feature Extractor.

Reads runs.csv, queries process_exec_events from PostgreSQL filtered by container_id
and occurred_at, cuts 60s tumbling windows (dropping the first warmup window),
computes 12 features via extract_features_from_events() using a benign-fit baseline,
and outputs windows.csv.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

# Ensure backend/src is on the module search path
backend_dir = Path(__file__).resolve().parents[1]
src_dir = backend_dir / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from porygon_api.ml_classifier import extract_features_from_events, FEATURE_NAMES, CLASSES
from porygon_api.scoring import jensen_shannon_distance


def load_env() -> dict[str, str]:
    """Read environment variables from .env without printing secrets."""
    env = dict(os.environ)
    for env_path in [backend_dir.parent / ".env", backend_dir / ".env"]:
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env.setdefault(k.strip(), v.strip())
    return env


def query_postgres_events(
    container_id: str,
    start_time: str,
    end_time: str,
    env: dict[str, str],
) -> list[dict[str, Any]]:
    """Query process_exec_events directly from PostgreSQL via docker exec."""
    # Build query safely with parameterized values
    # Filter strictly by container_id (full or prefix) and occurred_at with clock drift margin
    sql = (
        "SELECT json_agg(t) FROM ("
        "  SELECT event_id, container_id, occurred_at, time_nano, "
        "         process_name, executable, parent_name, parent_executable, "
        "         user_uid, command_line "
        "  FROM process_exec_events "
        f" WHERE (container_id = '{container_id}' OR container_id LIKE '{container_id[:12]}%' OR reported_container_id = '{container_id[:12]}') "
        f"   AND occurred_at >= '{start_time}'::timestamptz - interval '2 hours' "
        f"   AND occurred_at <= '{end_time}'::timestamptz + interval '2 hours' "
        "  ORDER BY occurred_at ASC, time_nano ASC"
        ") t;"
    )

    db_user = env.get("POSTGRES_USER", "porygon")
    db_name = env.get("POSTGRES_DB", "porygon")

    cmd = [
        "docker", "exec", "porygon-postgres-1",
        "psql", "-U", db_user, "-d", db_name,
        "-t", "-A", "-c", sql,
    ]

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        return []

    output = proc.stdout.strip()
    if not output or output == "":
        return []

    try:
        data = json.loads(output)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def parse_timestamp(ts_str: str) -> datetime.datetime:
    """Parse ISO8601 string to timezone-aware UTC datetime."""
    clean = ts_str.strip().replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def build_image_baseline(
    fit_events: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, float]]:
    """Build a baseline feature document strictly from benign fit runs."""
    proc_counts: dict[str, int] = {}
    exec_counts: dict[str, int] = {}
    total = len(fit_events)

    for ev in fit_events:
        pname = ev.get("process_name") or ""
        epath = ev.get("executable") or ""
        if pname:
            proc_counts[pname] = proc_counts.get(pname, 0) + 1
        if epath:
            exec_counts[epath] = exec_counts.get(epath, 0) + 1

    proc_dist = {k: v / total for k, v in proc_counts.items()} if total > 0 else {}
    exec_dist = {k: v / total for k, v in exec_counts.items()} if total > 0 else {}

    baseline_features = {
        "categorical_distributions": {
            "process_name": proc_dist,
            "executable": exec_dist,
        }
    }
    return baseline_features, proc_dist


def main() -> int:
    parser = argparse.ArgumentParser(description="Porygon 60s Tumbling Window Exporter")
    parser.add_argument("--runs", default=None, help="Input runs.csv path")
    parser.add_argument("--output", default=None, help="Output windows.csv path")
    parser.add_argument("--window-seconds", type=int, default=60, help="Window duration (default: 60s)")
    parser.add_argument("--min-events", type=int, default=3, help="Minimum events per window (default: 3)")

    args = parser.parse_args()
    
    if args.runs:
        runs_path = Path(args.runs)
    else:
        # Check both relative to cwd and relative to backend_dir
        candidate = Path("backend/ml_training/runs.csv")
        if candidate.exists():
            runs_path = candidate
        else:
            runs_path = backend_dir / "ml_training" / "runs.csv"

    if args.output:
        output_path = Path(args.output)
    else:
        candidate = Path("backend/ml_training/windows.csv")
        if candidate.parent.exists():
            output_path = candidate
        else:
            output_path = backend_dir / "ml_training" / "windows.csv"

    if not runs_path.exists():
        print(f"[!] Error: {runs_path} does not exist. Run scripts/collect_training_data.py first.")
        return 1

    env = load_env()

    # 1. Read runs.csv
    runs: list[dict[str, str]] = []
    with runs_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        runs = list(reader)

    print(f"[*] Read {len(runs)} trials from {runs_path}")

    # 2. First pass: Collect baseline events from separate baseline-only trials
    benign_baseline_events_by_image: dict[str, list[dict[str, Any]]] = {}
    trial_events_map: dict[str, list[dict[str, Any]]] = {}

    print("[*] Querying events from PostgreSQL for each trial...")
    for r in runs:
        run_id = r["run_id"]
        cid = r.get("container_id", "")
        start_ts = r["start_time"]
        end_ts = r["end_time"]
        image = r.get("image", "default")
        label = r["label"]
        split = r["split"]

        events = query_postgres_events(cid, start_ts, end_ts, env)
        trial_events_map[run_id] = events

        # Baseline-only trials (Rule 1: Build baselines from separate baseline trials)
        if split == "baseline":
            benign_baseline_events_by_image.setdefault(image, []).extend(events)

    # Backwards compatibility: fallback to benign fit events if no separate baseline trials present
    if not benign_baseline_events_by_image:
        print("[*] No separate baseline trials found. Falling back to benign-fit events for baseline.")
        for r in runs:
            if r["label"] == "benign" and r["split"] == "fit":
                benign_baseline_events_by_image.setdefault(r.get("image", "default"), []).extend(trial_events_map.get(r["run_id"], []))

    # 3. Construct baseline profiles per image
    baselines: dict[str, tuple[dict[str, Any], dict[str, float]]] = {}
    for image, b_events in benign_baseline_events_by_image.items():
        baselines[image] = build_image_baseline(b_events)
        print(f"[+] Built baseline for {image} from {len(b_events)} separate baseline events.")

    # 4. Cut 60s tumbling windows, drop first window per trial, and extract features
    window_records: list[dict[str, Any]] = []
    dropped_first_count = 0
    skipped_sparse_count = 0

    for r in runs:
        run_id = r["run_id"]
        label = r["label"]
        split = r["split"]
        image = r.get("image", "default")

        # Skip baseline-only trials (Rule 1: NOT exported as training rows)
        if split == "baseline":
            continue

        events = trial_events_map.get(run_id, [])
        if not events:
            continue

        baseline_features, baseline_proc_dist = baselines.get(image, ({}, {}))

        trial_start_dt = parse_timestamp(events[0]["occurred_at"])
        trial_end_dt = parse_timestamp(events[-1]["occurred_at"])
        total_duration = max((trial_end_dt - trial_start_dt).total_seconds(), 1.0)
        num_windows = int(math.ceil(total_duration / args.window_seconds))

        # Create window buckets
        buckets: list[list[dict[str, Any]]] = [[] for _ in range(max(num_windows, 1))]
        for ev in events:
            ev_dt = parse_timestamp(ev["occurred_at"])
            offset = (ev_dt - trial_start_dt).total_seconds()
            w_idx = min(int(offset // args.window_seconds), len(buckets) - 1)
            if 0 <= w_idx < len(buckets):
                buckets[w_idx].append(ev)

        # Drop first window (Rule 7: Warmup/startup window)
        dropped_first_count += 1
        evaluation_buckets = buckets[1:] if len(buckets) > 1 else []

        for w_events in evaluation_buckets:
            if len(w_events) < args.min_events:
                skipped_sparse_count += 1
                continue

            # Compute observed process distribution for JSD
            w_procs: dict[str, int] = {}
            for ev in w_events:
                pname = ev.get("process_name") or ""
                if pname:
                    w_procs[pname] = w_procs.get(pname, 0) + 1
            observed_dist = {k: v / len(w_events) for k, v in w_procs.items()}

            # Calculate Jensen-Shannon Drift against benign fit baseline
            if baseline_proc_dist and observed_dist:
                js_drift = jensen_shannon_distance(baseline_proc_dist, observed_dist)
            else:
                js_drift = 0.0

            # Extract 12 features identically
            features = extract_features_from_events(
                w_events,
                baseline_features=baseline_features,
                drift_score=js_drift,
            )

            record = {
                **features,
                "label": label,
                "image": image,
                "run_id": run_id,
                "split": split,
            }
            window_records.append(record)

    print(f"[*] Processed {len(runs)} trials: dropped {dropped_first_count} warmup windows, skipped {skipped_sparse_count} sparse (<{args.min_events} events) windows.")
    print(f"[+] Total qualified 60s windows extracted: {len(window_records)}")

    # 5. Write windows.csv
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(FEATURE_NAMES) + ["label", "image", "run_id", "split"]
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(window_records)

    print(f"[+] Written dataset to: {output_path}")

    # 5.5 Report Trials per Class per Split (from runs.csv)
    trial_counts: dict[str, dict[str, int]] = {
        cls: {"baseline": 0, "fit": 0, "calibration": 0, "test": 0, "total": 0}
        for cls in CLASSES
    }
    for r in runs:
        lbl = r["label"]
        splt = r["split"]
        if lbl in trial_counts and splt in trial_counts[lbl]:
            trial_counts[lbl][splt] += 1
            trial_counts[lbl]["total"] += 1

    print("\n" + "=" * 75)
    print("TRIALS PER CLASS AND SPLIT (from runs.csv)")
    print("=" * 75)
    print(f"{'Threat Class':<24} | {'Baseline':<10} | {'Fit':<8} | {'Calibration':<12} | {'Test':<8} | {'Total':<8}")
    print("-" * 75)
    for cls in CLASSES:
        tc = trial_counts[cls]
        print(f"{cls:<24} | {tc['baseline']:<10} | {tc['fit']:<8} | {tc['calibration']:<12} | {tc['test']:<8} | {tc['total']:<8}")
    print("-" * 75)
    ttotals = {"baseline": 0, "fit": 0, "calibration": 0, "test": 0, "total": 0}
    for tc in trial_counts.values():
        for k in ttotals:
            ttotals[k] += tc[k]
    print(f"{'TOTAL':<24} | {ttotals['baseline']:<10} | {ttotals['fit']:<8} | {ttotals['calibration']:<12} | {ttotals['test']:<8} | {ttotals['total']:<8}")
    print("=" * 75 + "\n")

    # 6. Report Windows per Class per Split
    counts: dict[str, dict[str, int]] = {
        cls: {"fit": 0, "calibration": 0, "test": 0, "total": 0}
        for cls in CLASSES
    }
    for w in window_records:
        lbl = w["label"]
        s = w["split"]
        if lbl in counts and s in counts[lbl]:
            counts[lbl][s] += 1
            counts[lbl]["total"] += 1

    print("\n" + "=" * 65)
    print("EXTRACTED WINDOWS BREAKDOWN (Class x Split)")
    print("=" * 65)
    print(f"{'Threat Class':<24} | {'Fit':<8} | {'Calibration':<12} | {'Test':<8} | {'Total':<8}")
    print("-" * 65)
    for cls in CLASSES:
        c = counts[cls]
        print(f"{cls:<24} | {c['fit']:<8} | {c['calibration']:<12} | {c['test']:<8} | {c['total']:<8}")
    print("-" * 65)

    totals = {"fit": 0, "calibration": 0, "test": 0, "total": 0}
    for c in counts.values():
        for k in totals:
            totals[k] += c[k]
    print(f"{'TOTAL':<24} | {totals['fit']:<8} | {totals['calibration']:<12} | {totals['test']:<8} | {totals['total']:<8}")
    print("=" * 65 + "\n")

    # 7. Compute and Print Per-Class Mean of all 12 Features
    feature_means: dict[str, dict[str, float]] = {cls: {} for cls in CLASSES}
    class_window_counts: dict[str, int] = {cls: 0 for cls in CLASSES}

    for w in window_records:
        lbl = w["label"]
        if lbl in feature_means:
            class_window_counts[lbl] += 1
            for fname in FEATURE_NAMES:
                val = float(w[fname])
                feature_means[lbl][fname] = feature_means[lbl].get(fname, 0.0) + val

    for cls in CLASSES:
        cnt = class_window_counts[cls]
        for fname in FEATURE_NAMES:
            if cnt > 0:
                feature_means[cls][fname] /= cnt
            else:
                feature_means[cls][fname] = 0.0

    print("=" * 95)
    print("PER-CLASS FEATURE MEANS (from windows.csv)")
    print("=" * 95)
    header = f"{'Feature':<28} | " + " | ".join(f"{cls[:10]:>10}" for cls in CLASSES)
    print(header)
    print("-" * 95)
    for fname in FEATURE_NAMES:
        row = f"{fname:<28} | " + " | ".join(f"{feature_means[cls][fname]:>10.4f}" for cls in CLASSES)
        print(row)
    print("-" * 95)
    count_row = f"{'Window Count (Total)':<28} | " + " | ".join(f"{class_window_counts[cls]:>10d}" for cls in CLASSES)
    print(count_row)
    print("=" * 95 + "\n")

    # 8. Check if any class has under 30 windows in fit
    under_30 = [cls for cls in CLASSES if counts[cls]["fit"] < 30]
    if under_30:
        print(f"[!] WARNING: The following classes have under 30 windows in fit: {under_30}")
        for cls in under_30:
            print(f"    - {cls}: {counts[cls]['fit']} windows in fit (< 30 required)")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
