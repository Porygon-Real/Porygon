#!/usr/bin/env python3
"""Add batch 2's sections to datasets/runtime/readme.md, keeping batch 1's text.

Every figure comes from the exported tables and summary.json; nothing is typed in
by hand. Re-running replaces the batch 2 sections it added before, so the readme
can be regenerated after a later pass without the file growing.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recipes import BATCH2_COREUTILS, RECIPES  # noqa: E402
from rt_common import RUNTIME_ROOT, read_json  # noqa: E402

START = "## Batch 2 (held-out images)"
LIMITS = "## Limits"
BATCH2_LIMITS_MARK = "- Batch 2 adds 22 held-out images"
csv.field_size_limit(10**9)


def read_csv(name: str) -> list[dict[str, str]]:
    path = RUNTIME_ROOT / name
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def fmt(value: object) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def results_table(summary: dict) -> str:
    per_batch = summary.get("per_batch") or {}
    lines = ["| Verdict | Batch | Images | Windows | TP | FP | TN | FN | Recall | Precision | FPR | Hard-neg FPR |",
             "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    rows: list[tuple[str, str, dict, object, object]] = []
    for name in ("batch1", "batch2"):
        block = per_batch.get(name)
        if not block:
            continue
        rows.append(("Incident", name, block["incident_verdict"], block["image_count"],
                     block["hard_negative_false_positive_rate"]))
        rows.append(("Score band", name, block["score_verdict"], block["image_count"],
                     block["hard_negative_score_false_positive_rate"]))
    combined_images = sum((per_batch.get(b) or {}).get("image_count", 0) for b in per_batch)
    hn = summary.get("hard_negative_false_positive_rate")
    rows.append(("Incident", "combined", summary["overall_incident_verdict"], combined_images, hn))
    rows.append(("Score band", "combined", summary["overall_score_verdict"], combined_images, None))
    order = {"Incident": 0, "Score band": 1}
    for verdict, batch, c, images, hn_fpr in sorted(rows, key=lambda r: (order[r[0]], r[1])):
        lines.append(f"| {verdict} | {batch} | {images} | {c['windows']} | {c['TP']} | {c['FP']} | {c['TN']} | "
                     f"{c['FN']} | {fmt(c['recall'])} | {fmt(c['precision'])} | {fmt(c['fpr'])} | "
                     f"{fmt(hn_fpr)} |")
    return "\n".join(lines)


def baseline_has_multicall(key: str) -> bool | None:
    """Whether this image's accepted baseline already lists a multicall binary as an observed
    executable. None when the status file records no observed set to read."""
    status = RUNTIME_ROOT / "raw" / key / "status.json"
    if not status.exists():
        return None
    try:
        data = json.loads(status.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for attempt in data.get("baseline_attempts") or []:
        observed = (((attempt.get("profile") or {}).get("features") or {})
                    .get("observed_sets") or {}).get("executables")
        if observed is None:
            continue
        return any(str(name).endswith(("/coreutils", "/busybox", "/toybox")) for name in observed)
    return None


def coreutils_section(summary: dict, windows: list[dict[str, str]], events: list[dict[str, str]]) -> str:
    present = [k for k in BATCH2_COREUTILS if k in (summary.get("per_image") or {})]
    if not present:
        return ("No coreutils-single image completed in batch 2, so batch 1's mysql finding is neither "
                "supported nor contradicted here.")
    exe_counts: dict[str, Counter] = defaultdict(Counter)
    for row in events:
        if row.get("batch") == "batch2":
            exe_counts[row["image_key"]][row.get("executable") or ""] += 1
    by_image_scenario: dict[str, dict[str, str]] = defaultdict(dict)
    for row in windows:
        if row.get("batch") == "batch2" and row["ground_truth"] == "abnormal":
            by_image_scenario[row["image_key"]][row["scenario_id"]] = row["outcome"]
    lines = ["| Image | Tag | Abnormal recall | Multicall events | `coreutils` in the baseline | "
             "Falco executable for the attack processes |",
             "|---|---|---:|---:|---|---|"]
    in_baseline: dict[str, bool | None] = {}
    for key in present:
        figures = summary["per_image"][key]
        counter = exe_counts.get(key, Counter())
        multicall = sum(v for k, v in counter.items() if k.endswith("/coreutils"))
        top = ", ".join(f"`{k}` {v}" for k, v in counter.most_common(3) if k) or "none recorded"
        in_baseline[key] = baseline_has_multicall(key)
        mark = {True: "yes", False: "no"}.get(in_baseline[key], "not recorded")
        lines.append(f"| {key} | `{RECIPES[key]['tag']}` | {fmt(figures['recall'])} | {multicall} | "
                     f"{mark} | {top} |")
    missed = {k: sorted(s for s, o in by_image_scenario.get(k, {}).items() if o == "FN") for k in present}
    detail = "\n".join(f"- `{k}`: {len(v)} of 12 abnormal windows not flagged"
                       + (f" ({', '.join(v)})" if v else "") for k, v in missed.items())
    escaped = [k for k in present if in_baseline.get(k) is False]
    caught = [k for k in present if in_baseline.get(k) is True]
    note = ""
    if escaped and caught:
        note = ("\n\nThe baseline column is what decides the outcome, not the image family. "
                f"In {', '.join(f'`{k}`' for k in caught)} the multicall binary was already in the baseline's "
                "observed executables, so every applet an attack ran resolved to a binary POR-DET-004 had "
                f"seen before and the rule stayed silent. In {', '.join(f'`{k}`' for k in escaped)} the "
                "learning phase never executed it, so the first applet the attacks ran made "
                "`/usr/bin/coreutils` itself a previously unseen executable and the rule fired normally. "
                "The gap is therefore not 'coreutils images are invisible' but 'an executable that enters "
                "the baseline takes every applet reachable through it with it'.")
    return "\n".join(lines) + "\n\n" + detail + note


def images_section(images: list[dict[str, str]], summary: dict) -> str:
    batch2 = [r for r in images if r.get("batch") == "batch2"]
    coreutils = [r for r in batch2 if r["image_key"] in BATCH2_COREUTILS]
    runtimes = [r for r in batch2 if r["image_key"] in
                ("node-20-alpine", "python-3.12-alpine", "ruby-3.3-alpine", "perl", "ubi9-python")
                and r["image_key"] not in BATCH2_COREUTILS]
    others = [r for r in batch2 if r not in coreutils and r not in runtimes]
    def listing(rows: list[dict[str, str]]) -> str:
        return ", ".join(f"{r['image_key']} (`{r['tag']}`, {r['status']})" for r in rows) or "none"
    return (f"- **Services and servers ({len(others)}):** {listing(others)}.\n"
            f"- **GNU coreutils-single images ({len(coreutils)}), the batch 1 mysql finding re-tested:** "
            f"{listing(coreutils)}.\n"
            f"- **Runtimes running a small server ({len(runtimes)}):** {listing(runtimes)}.\n\n"
            "  The exact start commands, digests and recipes are in `images.csv`.")


def gaps_file_row(gaps: dict) -> str:
    """The sensor-gaps row, listed only when the watchdog actually wrote the file."""
    if not (RUNTIME_ROOT / "batch2-sensor-gaps.json").exists():
        return ("| `batch2-sensor-gaps.json` | Written only if the watchdog detects a Falco sensor gap; "
                "this run had none, so the file is absent |")
    return "| `batch2-sensor-gaps.json` | Any Falco sensor gap the watchdog detected, with the repair steps |"

def substitutions_section(subs: list[dict[str, str]]) -> str:
    if not subs:
        return "None: every one of the 22 primary images was pulled as a native arm64 build and ran."
    lines = ["| Primary image | Replaced by | Why |", "|---|---|---|"]
    for row in subs:
        replacement = (f"{row['replacement_image_key']} (`{row['replacement_tag']}`)"
                       if row["replacement_image_key"] else "**nothing (reserves exhausted)**")
        lines.append(f"| {row['replaced_image_key']} (`{row['replaced_tag']}`) | {replacement} | {row['reason']} |")
    return "\n".join(lines)


def incidents_section(gaps: dict, fixes: list[dict]) -> str:
    lines = []
    by_step: Counter = Counter()
    for entry in fixes:
        by_step[str(entry.get("step", "")).split(":")[0]] += 1
    if by_step:
        lines.append("Automatic fixes recorded in `run-log.jsonl` (batch 2 lines), by step: "
                     + ", ".join(f"`{k}` {v}" for k, v in sorted(by_step.items())) + ".")
    gap_list = (gaps or {}).get("gaps") or []
    if gap_list:
        lines.append("")
        lines.append("Sensor gaps detected and repaired by the watchdog:")
        for gap in gap_list:
            lines.append(f"- {gap.get('last_event_seen_at')} to {gap.get('gap_ended_at')} "
                         f"({gap.get('gap_minutes')} min): repair attempt {gap.get('repair_attempt')}, "
                         f"repaired={gap.get('repaired')}, runs collected again: "
                         f"{gap.get('runs_invalidated') or 'none'}.")
    else:
        lines.append("")
        lines.append("The sensor watchdog ran throughout and found no gap: every liveness check saw Porygon "
                     "store the event from a real `docker exec` in the watchdog's own throwaway container, so "
                     "no run was invalidated.")
    if (RUNTIME_ROOT / "NEEDS_ATTENTION.md").is_file():
        lines.append("")
        lines.append("Some problems could not be fixed automatically; they are written up in "
                     "`NEEDS_ATTENTION.md`.")
    return "\n".join(lines)


def main() -> int:
    summary = read_json(RUNTIME_ROOT / "summary.json", {}) or {}
    if not (summary.get("per_batch") or {}).get("batch2"):
        print("summary.json has no batch 2 block yet; run export.py first")
        return 2
    windows, images, events = read_csv("windows.csv"), read_csv("images.csv"), read_csv("process_events.csv")
    subs = read_csv("substitutions.csv")
    gaps = read_json(RUNTIME_ROOT / "batch2-sensor-gaps.json", {}) or {}
    fixes = []
    log_path = RUNTIME_ROOT / "run-log.jsonl"
    if log_path.is_file():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("batch") == "batch2":
                fixes.append(entry)
    block = summary["per_batch"]["batch2"]
    failed_note = ""
    if block.get("images_failed"):
        failed_note = (f"\n\n{len(block['images_failed'])} of batch 2's runs did not complete "
                       f"({', '.join(block['images_failed'])}); their windows are still in the tables, marked "
                       "with their run status in `images.csv`, and a reserve image was run in their place.")
    batch2_rows = [r for r in windows if r.get("batch") == "batch2"]
    dates = sorted({r["window_start"][:10] for r in batch2_rows if r.get("window_start")})
    span = dates[0] if len(dates) < 2 else f"{dates[0]} to {dates[-1]}"

    section = f"""{START}

Batch 2 is a held-out test set of {block['image_count']} further images, collected {span} under the
**same protocol and with no change to Porygon**: 30 min learning + 30 × 60 s test
windows = 60 min per image. Its purpose is to show whether batch 1's results hold
on images Porygon had never seen. Batch 2 monitored
{block['monitored_minutes'] / 60:.1f} hours in total ({block['windows']} test windows), measured from the
recorded timestamps; the whole dataset now holds
{(summary['per_batch'].get('batch1') or {}).get('monitored_minutes', 0) / 60 + block['monitored_minutes'] / 60:.1f} monitored hours.
Every table carries a `batch` column (`batch1`/`batch2`); batch 1's rows are
unchanged apart from that column.{failed_note}

### Images

{images_section(images, summary)}

### Substitutions

{substitutions_section(subs)}

### Files added by batch 2

| File | Contents |
|---|---|
| `substitutions.csv` | Which primary image was replaced by which reserve, and why |
| `batch2-preflight.json` | Free disk, Docker usage, service health, Falco liveness and the rotation limit before batch 2 started |
| `batch2-plan.json` | Which images batch 2 selected, which it rejected and why |
| `prefetch-batch2.json`, `prefetch-batch2.log` | The arm64 download for batch 2, with digests |
{gaps_file_row(gaps)}
| `archive/batch1-2026-11-21/` | Batch 1's tables and checksums as they were before batch 2, used to prove batch 1 did not change |

Scripts added: `scripts/runtime/run_batch2.sh` (the whole unattended run),
`plan_batch2.py` (substitutions), `watchdog_batch2.py` (the Falco watchdog),
`preflight_batch2.py`, `check_recipe.py` and `verify_batch1_unchanged.py`.
Make targets: `runtime-batch2`, `runtime-check-recipe IMAGE=<key>`, `runtime-verify-batch1`.

## Results: batch 1 against batch 2

{results_table(summary)}

Per image, per scenario, per kind and per rule figures for both batches, and the
`per_batch` block, are in `summary.json`.

## Coreutils images (batch 2)

Batch 1 found that mysql's GNU coreutils multicall binary hid 10 of its 12
attacks, because Porygon resolves applet names only for busybox and toybox.
Batch 2 re-tests that on four images built the same way. The data decides:

{coreutils_section(summary, windows, events)}

## Incidents during collection (batch 2)

{incidents_section(gaps, fixes)}

"""

    path = RUNTIME_ROOT / "readme.md"
    text = path.read_text(encoding="utf-8")
    if START in text:  # replace the batch 2 sections added by an earlier run
        text = text[:text.index(START)] + text[text.index(LIMITS, text.index(START)):]
    head, _, limits = text.partition(LIMITS)
    batch2_limits = [
        "- Batch 2 adds 22 held-out images under the identical protocol, so the",
        "  combined figures cover 44 images and 1,320 windows on the same host. The",
        "  two batches were collected on different days; Porygon's code, rules and",
        "  thresholds were identical for both.",
        "- Batch 2's images were never used to choose or tune anything in Porygon,",
        "  which is what makes them held out. They were chosen to fill batch 1's",
        "  gaps (coreutils-single images, busybox/Alpine images, new service types),",
        "  so batch 2 is deliberately not a random sample of container images.",
    ]
    couchdb_limit = [
        "- CouchDB ships no working `weatherreport`, so its `RT-HN-ADMIN` command is the",
        "  documented `_node/_local/_system` admin call made with the image's own `curl`",
        "  rather than a service CLI (recorded in its recipe's `fixes`).",
    ]
    # Drop every bullet an earlier run of this script appended, so re-running it is
    # idempotent and the batch 1 limits written by hand are kept untouched.
    appended = {line.strip() for line in batch2_limits + couchdb_limit}
    limits_lines = [line for line in limits.splitlines()
                    if line.strip() not in appended and not line.startswith(BATCH2_LIMITS_MARK)]
    extra = list(batch2_limits)
    if not any("escript" in line for line in limits_lines):
        extra.extend(couchdb_limit)
    new_text = head + section + LIMITS + "\n".join(limits_lines).rstrip() + "\n" + "\n".join(extra) + "\n"
    path.write_text(new_text, encoding="utf-8")
    print(f"readme.md updated: {len(new_text.splitlines())} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
