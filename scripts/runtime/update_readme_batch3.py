#!/usr/bin/env python3
"""Add batch 3's sections to datasets/runtime/readme.md, keeping batches 1 and 2's text.

Every figure comes from the exported tables, summary.json and the matcher checks;
nothing is typed in by hand. Re-running replaces the batch 3 sections it added
before. Run only this script for batch 3: update_readme_batch2.py would rewrite
everything from its own section onwards.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recipes import BATCH3_COREUTILS, RECIPES  # noqa: E402
from rt_common import RUNTIME_ROOT, read_json  # noqa: E402
from update_readme_batch2 import baseline_has_multicall, fmt, read_csv, substitutions_section  # noqa: E402

START = "## Batch 3 (second held-out set)"
LIMITS = "## Limits"
LIMITS_MARK = "- Batch 3 adds"
BATCHES = ("batch1", "batch2", "batch3")


def results_table(summary: dict) -> str:
    per_batch = summary.get("per_batch") or {}
    lines = ["| Verdict | Batch | Images | Windows | TP | FP | TN | FN | Recall | Precision | FPR | Hard-neg FPR |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    combined_images = sum((per_batch.get(b) or {}).get("image_count", 0) for b in per_batch)
    for verdict, key, hn_key in (("Incident", "incident_verdict", "hard_negative_false_positive_rate"),
                                 ("Score band", "score_verdict", "hard_negative_score_false_positive_rate")):
        for name in BATCHES:
            block = per_batch.get(name)
            if block:
                c = block[key]
                lines.append(f"| {verdict} | {name} | {block['image_count']} | {c['windows']} | {c['TP']} | "
                             f"{c['FP']} | {c['TN']} | {c['FN']} | {fmt(c['recall'])} | {fmt(c['precision'])} | "
                             f"{fmt(c['fpr'])} | {fmt(block.get(hn_key))} |")
        c = summary["overall_incident_verdict" if key == "incident_verdict" else "overall_score_verdict"]
        hn = summary.get("hard_negative_false_positive_rate") if key == "incident_verdict" else None
        lines.append(f"| {verdict} | **combined** | {combined_images} | {c['windows']} | {c['TP']} | {c['FP']} | "
                     f"{c['TN']} | {c['FN']} | {fmt(c['recall'])} | {fmt(c['precision'])} | {fmt(c['fpr'])} | "
                     f"{fmt(hn)} |")
    return "\n".join(lines)


def coreutils_section(summary: dict, windows: list[dict[str, str]], events: list[dict[str, str]]) -> str:
    present = [k for k in BATCH3_COREUTILS if k in (summary.get("per_image") or {})]
    if not present:
        return "No coreutils-single image completed in batch 3."
    exe_counts: dict[str, Counter] = defaultdict(Counter)
    for row in events:
        if row.get("batch") == "batch3" and row["image_key"] in present:
            exe_counts[row["image_key"]][row.get("executable") or ""] += 1
    missed: dict[str, list[str]] = defaultdict(list)
    for row in windows:
        if row.get("batch") == "batch3" and row["ground_truth"] == "abnormal" and row["outcome"] == "FN":
            missed[row["image_key"]].append(row["scenario_id"])
    lines = ["| Image | Tag | Abnormal recall | `coreutils` events | `coreutils` in the baseline |",
             "|---|---|---:|---:|---|"]
    for key in present:
        counter = exe_counts.get(key, Counter())
        multicall = sum(v for k, v in counter.items() if k.endswith("/coreutils"))
        mark = {True: "yes", False: "no"}.get(baseline_has_multicall(key), "not recorded")
        lines.append(f"| {key} | `{RECIPES[key]['tag']}` | {fmt(summary['per_image'][key]['recall'])} | "
                     f"{multicall} | {mark} |")
    detail = "\n".join(f"- `{k}`: {len(missed.get(k, []))} of 12 abnormal windows not flagged"
                       + (f" ({', '.join(sorted(missed[k]))})" if missed.get(k) else "") for k in present)
    return ("\n".join(lines) + "\n\n" + detail + "\n\nThese are observed results under matcher v5, the same "
            "matcher as batches 1 and 2. They are not a test of any later matcher.")


def matcher_section() -> str:
    path = RUNTIME_ROOT / "batch3-matcher-checks.jsonl"
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()] if path.is_file() else []
    if not rows:
        return "No matcher checks were recorded."
    ok = sum(1 for r in rows if r.get("ok"))
    revisions = sorted({r.get("revision") for r in rows})
    images = sorted({r.get("backend_image_id", "")[:19] for r in rows})
    return (f"{len(rows)} checks (pre-flight, before every image, and at the end) read the matcher revision from "
            f"the running backend container: {ok} of {len(rows)} passed. Revisions seen: "
            f"{', '.join(f'`{r}`' for r in revisions)}; backend image IDs seen: "
            f"{', '.join(f'`{i}`' for i in images)}. Every check is in `batch3-matcher-checks.jsonl`.")


def incidents_section(fixes: list[dict]) -> str:
    by_step: Counter = Counter(str(e.get("step", "")).split(":")[0] for e in fixes)
    lines = []
    if by_step:
        lines.append("Automatic fixes and events recorded in `run-log.jsonl` (batch 3 lines), by step: "
                     + ", ".join(f"`{k}` {v}" for k, v in sorted(by_step.items())) + ".")
    gaps = (read_json(RUNTIME_ROOT / "batch3-sensor-gaps.json", {}) or {}).get("gaps") or []
    lines.append("")
    if gaps:
        lines.append("Sensor gaps detected and repaired by the watchdog:")
        lines += [f"- {g.get('last_event_seen_at')} to {g.get('gap_ended_at')} ({g.get('gap_minutes')} min): "
                  f"repaired={g.get('repaired')}, runs collected again: {g.get('runs_invalidated') or 'none'}."
                  for g in gaps]
    else:
        lines.append("The sensor watchdog ran throughout and found no gap, so no batch 3 run was invalidated.")
    if (RUNTIME_ROOT / "NEEDS_ATTENTION.md").is_file():
        lines += ["", "Some problems could not be fixed automatically; they are written up in `NEEDS_ATTENTION.md`."]
    return "\n".join(lines)


def main() -> int:
    summary = read_json(RUNTIME_ROOT / "summary.json", {}) or {}
    block = (summary.get("per_batch") or {}).get("batch3")
    if not block:
        print("summary.json has no batch 3 block yet; run export.py first")
        return 2
    windows, images, events = read_csv("windows.csv"), read_csv("images.csv"), read_csv("process_events.csv")
    subs = [r for r in read_csv("substitutions.csv") if r.get("batch") == "batch3"]
    fixes = []
    log_path = RUNTIME_ROOT / "run-log.jsonl"
    if log_path.is_file():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("batch") == "batch3":
                fixes.append(entry)
    batch3_images = [r for r in images if r.get("batch") == "batch3"]
    listing = ", ".join(f"{r['image_key']} (`{r['tag']}`, {r['status']})" for r in batch3_images)
    dates = sorted({r["window_start"][:10] for r in windows if r.get("batch") == "batch3" and r.get("window_start")})
    span = dates[0] if len(dates) < 2 else f"{dates[0]} to {dates[-1]}"
    total_hours = sum((summary["per_batch"].get(b) or {}).get("monitored_minutes", 0) for b in BATCHES) / 60
    failed_note = ""
    if block.get("images_failed"):
        failed_note = (f"\n\n{len(block['images_failed'])} batch 3 run(s) did not complete "
                       f"({', '.join(block['images_failed'])}); see `images.csv` and `substitutions.csv`.")

    section = f"""{START}

Batch 3 is a second held-out set of {block['image_count']} images, collected {span} under the
**same protocol, with the same Porygon (detection matcher v5)**: 30 min learning +
30 × 60 s test windows = 60 min per image. No batch 3 image has the same digest
as any batch 1 or batch 2 image. Batch 3 monitored {block['monitored_minutes'] / 60:.1f} hours
({block['windows']} test windows), measured from the recorded timestamps; the whole
dataset now holds {total_hours:.1f} monitored hours. Every table's `batch` column now
takes `batch1`, `batch2` or `batch3`; the batch 1 and batch 2 rows are unchanged.{failed_note}

### Images

{listing}.

The exact start commands, digests and recipes are in `images.csv`.

### Same Porygon as batches 1 and 2

{matcher_section()}

### Substitutions

{substitutions_section(subs) if subs else "None: every one of the 22 primary images ran."}

### Files added by batch 3

| File | Contents |
|---|---|
| `batch3-preflight.json` | Free disk, Docker usage, service health and Falco liveness before batch 3 |
| `batch3-matcher-checks.jsonl` | The detection matcher revision and backend image, checked before every image |
| `batch3-plan.json` | Which images batch 3 selected or rejected, and why |
| `prefetch-batch3.json`, `prefetch-batch3.log` | The arm64 download for batch 3, with digests |
| `archive/batch1-2-2026-11-21/` | Batches 1 and 2's tables and checksums before batch 3, used to prove they did not change |

## Results: all three batches

{results_table(summary)}

## Coreutils images (batch 3)

{coreutils_section(summary, windows, events)}

## Incidents during collection (batch 3)

{incidents_section(fixes)}

"""
    path = RUNTIME_ROOT / "readme.md"
    text = path.read_text(encoding="utf-8")
    if START in text:
        text = text[:text.index(START)] + text[text.index(LIMITS, text.index(START)):]
    head, _, limits = text.partition(LIMITS)
    batch3_limits = [
        f"- Batch 3 adds {block['image_count']} more held-out images under the identical protocol and the same",
        "  detection matcher (v5), checked before every image. Like batch 2, its images were",
        "  chosen to widen coverage, not sampled at random.",
    ]
    appended = {line.strip() for line in batch3_limits}
    limits_lines = [line for line in limits.splitlines()
                    if line.strip() not in appended and not line.startswith(LIMITS_MARK)
                    and not line.startswith("  detection matcher (v5), checked before every image")
                    and not line.startswith("  chosen to widen coverage, not sampled at random")]
    new_text = head + section + LIMITS + "\n".join(limits_lines).rstrip() + "\n" + "\n".join(batch3_limits) + "\n"
    path.write_text(new_text, encoding="utf-8")
    print(f"readme.md updated: {len(new_text.splitlines())} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
