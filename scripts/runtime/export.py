#!/usr/bin/env python3
"""Export the runtime dataset tables from the untouched raw records.

Reads datasets/runtime/raw/<image>/ (status.json plus Porygon's own score,
detection and event JSON) and writes windows.csv, rule_matches.csv,
process_events.csv, images.csv, summary.json and manifest.json. Every value is
copied or counted from those records; nothing is estimated or filled in. A
window without a score or detection keeps empty Porygon columns and outcome
"failed".

Every table carries a "batch" column as its last column. A raw folder without a
"batch" field in status.json belongs to batch 1, so batch 1's rows are unchanged
apart from that column.
"""
from __future__ import annotations

import argparse
import csv
import json
import platform
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rt_common import RAW_ROOT, RUNTIME_ROOT, docker, read_json, sha256_file, utc_now, write_json  # noqa: E402

ELEVATED = {"elevated", "high", "extreme"}
WINDOW_FIELDS = [
    "image_key", "image_tag", "image_digest", "platform", "run_id", "window_index", "window_start", "window_end",
    "kind", "scenario_id", "scenario_name", "commands", "action_returncode", "ground_truth",
    "ground_truth_recorded_at", "action_seen_by_falco", "process_event_count", "porygon_score", "score_band",
    "rules_fired", "detection_status", "incident_created", "incident_id", "incident_severity", "porygon_verdict",
    "score_verdict", "outcome", "score_outcome", "window_state", "error", "batch",
]
EVENT_FIELDS = ["image_key", "image_digest", "phase", "window_index", "event_id", "occurred_at", "container_name",
                "process_pid", "process_ppid", "process_name", "executable", "command_line", "parent_name",
                "parent_executable", "user_uid", "user_name", "rule_name", "batch"]


def count_multicall(counter: Counter, event: dict[str, Any], names: set[str]) -> None:
    """Count events whose executable is a multicall binary, which hides the applet's own name."""
    executable = event.get("executable") or ""
    base = executable.rsplit("/", 1)[-1]
    if base in names:
        counter[executable] += 1


def monitored_minutes(images_rows: list[dict[str, Any]], window_rows: list[dict[str, Any]]) -> float:
    """Learning span plus test span per image, from the recorded timestamps only."""
    from datetime import datetime
    total = 0.0
    per_image: dict[str, list] = defaultdict(list)
    for r in window_rows:
        if r["window_start"] and r["window_end"]:
            per_image[r["image_key"]].append(r)
    for row in images_rows:
        if row.get("training_start") and row.get("training_end"):
            total += (datetime.fromisoformat(row["training_end"])
                      - datetime.fromisoformat(row["training_start"])).total_seconds() / 60
        rows = sorted(per_image.get(row["image_key"], []), key=lambda r: r["window_start"])
        if rows:
            total += (datetime.fromisoformat(rows[-1]["window_end"])
                      - datetime.fromisoformat(rows[0]["window_start"])).total_seconds() / 60
    return round(total, 1)


def batch_of(status: dict[str, Any]) -> str:
    """A raw folder written before batch 2 has no batch field and belongs to batch 1."""
    return status.get("batch") or "batch1"


def outcome(truth: str, verdict: str | None) -> str:
    if verdict is None:
        return "failed"
    return {("abnormal", "abnormal"): "TP", ("normal", "abnormal"): "FP",
            ("normal", "normal"): "TN", ("abnormal", "normal"): "FN"}[(truth, verdict)]


def confusion(rows: list[dict[str, Any]], key: str = "outcome") -> dict[str, Any]:
    c = Counter(r[key] for r in rows)
    tp, fp, tn, fn = (c.get(k, 0) for k in ("TP", "FP", "TN", "FN"))
    def ratio(a: int, b: int) -> float | None:
        return round(a / b, 4) if b else None
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "failed": c.get("failed", 0), "windows": len(rows),
            "recall": ratio(tp, tp + fn), "precision": ratio(tp, tp + fp), "fpr": ratio(fp, fp + tn),
            "accuracy": ratio(tp + tn, tp + tn + fp + fn)}


def window_row(st: dict[str, Any], idx: int, wdir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    w = st["windows"][str(idx)]
    score = read_json(wdir / f"w{idx:02d}-score.json", None)
    det = read_json(wdir / f"w{idx:02d}-detection.json", None)
    events = read_json(wdir / f"w{idx:02d}-events.json", None)
    run = (det or {}).get("run") or {}
    incident = (det or {}).get("incident") or {}
    matches = (run.get("result") or {}).get("matches") or []
    rules = sorted({m["rule_id"] for m in matches})
    verdict = None
    if det is not None and w.get("state") == "done":
        verdict = "abnormal" if run.get("incident_created") else "normal"
    score_verdict = None
    if score is not None and w.get("state") == "done":
        score_verdict = "abnormal" if score.get("score_band") in ELEVATED else "normal"
    action = w.get("action") or {}
    row = {
        "image_key": st["image_key"], "image_tag": st["tag"], "image_digest": st.get("image_digest"),
        "platform": st["platform"], "run_id": st["run_id"], "window_index": idx,
        "window_start": w.get("window_start"), "window_end": w.get("window_end"), "kind": w["kind"],
        "scenario_id": w["scenario_id"], "scenario_name": w["scenario_name"], "commands": w.get("commands", ""),
        "action_returncode": action.get("returncode"), "ground_truth": w["ground_truth"],
        "ground_truth_recorded_at": w.get("ground_truth_recorded_at"),
        "action_seen_by_falco": w.get("action_seen_by_falco"),
        "process_event_count": score.get("process_event_count") if score else None,
        "porygon_score": score.get("total_score") if score else None,
        "score_band": score.get("score_band") if score else None, "rules_fired": ";".join(rules),
        "detection_status": run.get("status"), "incident_created": run.get("incident_created") if det else None,
        "incident_id": incident.get("incident_id"), "incident_severity": incident.get("severity_level"),
        "porygon_verdict": verdict, "score_verdict": score_verdict,
        "outcome": outcome(w["ground_truth"], verdict), "score_outcome": outcome(w["ground_truth"], score_verdict),
        "window_state": w.get("state"), "error": w.get("error", ""), "batch": batch_of(st),
    }
    match_rows = [{"image_key": st["image_key"], "image_digest": st.get("image_digest"), "window_index": idx,
                   "scenario_id": w["scenario_id"], "ground_truth": w["ground_truth"], "rule_id": m.get("rule_id"),
                   "rule_name": m.get("name") or m.get("rule_name"), "incident_eligible": m.get("incident_eligible"),
                   "occurred_at": m.get("occurred_at"), "source_type": m.get("source_type"),
                   "summary": m.get("summary"), "batch": batch_of(st)} for m in matches]
    for e in events or []:
        e["_window"] = idx
    return row, match_rows, events or []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(RUNTIME_ROOT))
    args = parser.parse_args()
    out = Path(args.out)
    windows: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    images: list[dict[str, Any]] = []
    # Which images Falco reports through a multicall binary, counted from the stored events.
    multicall: dict[str, Counter] = defaultdict(Counter)
    multicall_names = {"coreutils", "busybox", "toybox"}
    with (out / "process_events.csv").open("w", newline="", encoding="utf-8") as ev_handle:
        ev = csv.DictWriter(ev_handle, EVENT_FIELDS, extrasaction="ignore")
        ev.writeheader()
        for status_path in sorted(RAW_ROOT.glob("*/status.json")):
            st = read_json(status_path)
            base = status_path.parent
            baseline = read_json(base / "baseline.json", {}) or {}
            images.append({
                "image_key": st["image_key"], "tag": st["tag"], "image_digest": st.get("image_digest"),
                "platform": st["platform"], "run_id": st["run_id"], "status": st.get("phase"),
                "error": st.get("error", ""), "recipe": json.dumps(st.get("recipe"), sort_keys=True),
                "start_command": " ".join(st.get("recipe", {}).get("cmd", [])) or "(image default)",
                "seed": st.get("seed"), "training_start": st.get("training_start"), "training_end": st.get("training_end"),
                "baseline_id": st.get("baseline_id"),
                "baseline_quality_passed": (baseline.get("quality") or {}).get("passed"),
                "baseline_stats": json.dumps((baseline.get("quality") or {}).get("checks"), sort_keys=True),
                "learning_restarts": len(st.get("learning_restarts", [])),
                "windows_done": sum(1 for w in st.get("windows", {}).values() if w.get("state") == "done"),
                "batch": batch_of(st),
            })
            for e in read_json(base / "learning-events.json", []) or []:
                count_multicall(multicall[st["image_key"]], e, multicall_names)
                ev.writerow(e | {"image_key": st["image_key"], "phase": "learning", "window_index": "",
                                 "batch": batch_of(st)})
            for idx in sorted(int(i) for i in st.get("windows", {})):
                if st["windows"][str(idx)].get("action") is None:
                    continue
                row, mrows, events = window_row(st, idx, base / "windows")
                windows.append(row)
                matches.extend(mrows)
                for e in events:
                    count_multicall(multicall[st["image_key"]], e, multicall_names)
                    ev.writerow(e | {"image_key": st["image_key"], "phase": "test", "window_index": idx,
                                     "batch": batch_of(st)})
    for name, fields, rows in (("windows.csv", WINDOW_FIELDS, windows),
                               ("rule_matches.csv", list(matches[0]) if matches else ["image_key"], matches),
                               ("images.csv", list(images[0]) if images else ["image_key"], images)):
        with (out / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fields)
            writer.writeheader()
            writer.writerows(rows)

    by: dict[str, dict[str, list]] = {"image": defaultdict(list), "scenario": defaultdict(list), "kind": defaultdict(list)}
    for r in windows:
        by["image"][r["image_key"]].append(r)
        by["scenario"][r["scenario_id"]].append(r)
        by["kind"][r["kind"]].append(r)
    rule_windows: dict[str, Counter] = defaultdict(Counter)
    for r in windows:
        for rule in filter(None, r["rules_fired"].split(";")):
            rule_windows[rule][r["ground_truth"]] += 1
    hn = by["kind"].get("hard_negative", [])
    by_batch: dict[str, list] = defaultdict(list)
    for r in windows:
        by_batch[r["batch"]].append(r)
    images_by_batch: dict[str, list] = defaultdict(list)
    for i in images:
        images_by_batch[i["batch"]].append(i)

    def batch_block(name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        kinds: dict[str, list] = defaultdict(list)
        for r in rows:
            kinds[r["kind"]].append(r)
        bhn = kinds.get("hard_negative", [])
        imgs = images_by_batch.get(name, [])
        return {
            "incident_verdict": confusion(rows), "score_verdict": confusion(rows, "score_outcome"),
            "per_kind": {k: confusion(v) for k, v in sorted(kinds.items())},
            "per_kind_score_verdict": {k: confusion(v, "score_outcome") for k, v in sorted(kinds.items())},
            "hard_negative_false_positive_rate": confusion(bhn)["fpr"] if bhn else None,
            "hard_negative_score_false_positive_rate": confusion(bhn, "score_outcome")["fpr"] if bhn else None,
            "images": sorted({r["image_key"] for r in rows}), "image_count": len(imgs),
            "images_complete": sum(1 for i in imgs if i["status"] == "complete"),
            "images_failed": sorted(i["image_key"] for i in imgs if i["status"] != "complete"),
            "windows": len(rows), "monitored_minutes": monitored_minutes(imgs, rows),
        }

    info = docker("info", "--format", "{{json .}}").stdout
    docker_info = json.loads(info) if info.strip() else {}
    summary = {
        "generated_at": utc_now(),
        "overall_incident_verdict": confusion(windows), "overall_score_verdict": confusion(windows, "score_outcome"),
        "per_image": {k: confusion(v) for k, v in sorted(by["image"].items())},
        "per_scenario": {k: confusion(v) for k, v in sorted(by["scenario"].items())},
        "per_kind": {k: confusion(v) for k, v in sorted(by["kind"].items())},
        "per_rule_windows_fired_by_ground_truth": {k: dict(v) for k, v in sorted(rule_windows.items())},
        "per_batch": {b: batch_block(b, rows) for b, rows in sorted(by_batch.items())},
        "multicall_executables_by_image": {k: dict(v) for k, v in sorted(multicall.items()) if v},
        "hard_negative_false_positive_rate": confusion(hn)["fpr"] if hn else None,
        "images": {i["image_key"]: i["status"] for i in images},
        "host": {"os": platform.platform(), "machine": platform.machine(),
                 "docker_server_version": docker_info.get("ServerVersion"), "kernel": docker_info.get("KernelVersion"),
                 "docker_cpus": docker_info.get("NCPU"), "docker_memory_bytes": docker_info.get("MemTotal"),
                 "docker_os": docker_info.get("OperatingSystem")},
    }
    write_json(out / "summary.json", summary)
    files = sorted(p for p in out.rglob("*") if p.is_file() and p.name not in ("manifest.json",) and not p.name.startswith("."))
    write_json(out / "manifest.json", {"generated_at": utc_now(),
                                       "files": {str(p.relative_to(out)): sha256_file(p) for p in files}})
    print(json.dumps({k: summary[k] for k in ("overall_incident_verdict", "overall_score_verdict", "per_batch",
                                             "images")}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
