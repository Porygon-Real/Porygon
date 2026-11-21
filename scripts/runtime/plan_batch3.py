#!/usr/bin/env python3
"""Decide which batch 3 images to run, and record every substitution.

A primary image is run unless the evidence says it cannot be:
  - its arm64 pull failed after all retries;
  - the pulled image is not arm64;
  - its digest is already in batch 1 or batch 2, so it would repeat an earlier image;
  - a completed run of it failed.
Each rejected primary is replaced by the next reserve that is itself usable and
not already in use, and the pairing is written to datasets/runtime/substitutions.csv.

Idempotent: it reads the current prefetch record, batch 1's digests and each
raw/<key>/status.json, and can be re-run after every pass of the batch.
Writes datasets/runtime/batch3-plan.json; --print-queue lists the keys to run.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recipes import BATCH3_ORDER, BATCH3_RESERVES, RECIPES  # noqa: E402
from rt_common import RAW_ROOT, RUNTIME_ROOT, log_event, read_json, utc_now  # noqa: E402

TARGET = len(BATCH3_ORDER)
SUBS_FIELDS = ["replaced_image_key", "replaced_tag", "reason", "replacement_image_key", "replacement_tag",
               "decided_at", "batch"]


def earlier_digests() -> dict[str, str]:
    """Every image digest batches 1 and 2 recorded, from images.csv and the pre-batch-3 snapshot."""
    digests: dict[str, str] = {}
    sources = [RUNTIME_ROOT / "images.csv"]
    sources += sorted((RUNTIME_ROOT / "archive").glob("batch1-*/images.csv"))
    for path in sources:
        if not path.is_file():
            continue
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if (row.get("batch") or "batch1") in ("batch1", "batch2") and row.get("image_digest"):
                    digests[row["image_digest"]] = f"{row.get('batch') or 'batch1'}:{row['image_key']}"
    return digests


def status_of(key: str) -> dict:
    return read_json(RAW_ROOT / key / "status.json", {}) or {}


def usable(key: str, prefetch: dict, digests: dict[str, str]) -> tuple[bool, str]:
    tag = RECIPES[key]["tag"]
    entry = (prefetch.get("images") or {}).get(tag)
    if entry is None:
        return False, "not pulled: no prefetch record for the tag"
    if entry.get("status") != "ok":
        return False, f"pull failed after all retries: {str(entry.get('error'))[:200]}"
    if entry.get("architecture") != "arm64":
        return False, f"no arm64 build (architecture {entry.get('architecture')})"
    digest = entry.get("repo_digest")
    if digest and digest in digests:
        return False, f"same digest as an earlier batch ({digests[digest]}, {digest})"
    status = status_of(key)
    if status.get("phase") == "failed":
        return False, f"run failed: {str(status.get('error'))[:300]}"
    return True, ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--print-queue", action="store_true", help="print the keys to run, one per line")
    args = parser.parse_args()
    prefetch = read_json(RUNTIME_ROOT / "prefetch-batch3.json", {}) or {}
    if not prefetch.get("finished_at"):
        # Without a finished prefetch, a tag with no record only means "not downloaded yet",
        # which is not a reason to substitute anything.
        print("prefetch-batch3.json has no finished_at: the prefetch is still running, so no plan is written",
              file=sys.stderr)
        return 2
    digests = earlier_digests()

    selected: list[str] = []
    rejected: dict[str, str] = {}
    for key in BATCH3_ORDER:
        ok, reason = usable(key, prefetch, digests)
        (selected.append(key) if ok else rejected.update({key: reason}))

    substitutions: list[dict[str, str]] = []
    reserve_pool = [k for k in BATCH3_RESERVES]
    for key in BATCH3_ORDER:
        if key not in rejected or len(selected) >= TARGET:
            continue
        replacement, replacement_reason = "", ""
        while reserve_pool:
            candidate = reserve_pool.pop(0)
            ok, reason = usable(candidate, prefetch, digests)
            if ok:
                replacement = candidate
                selected.append(candidate)
                break
            rejected.setdefault(candidate, reason)
            replacement_reason = reason
        substitutions.append({
            "replaced_image_key": key, "replaced_tag": RECIPES[key]["tag"], "reason": rejected[key],
            "replacement_image_key": replacement,
            "replacement_tag": RECIPES[replacement]["tag"] if replacement else "",
            "decided_at": utc_now(), "batch": "batch3",
        })
        if not replacement:
            substitutions[-1]["reason"] = (f"{rejected[key]}; no reserve left"
                                           + (f" (last reserve: {replacement_reason})" if replacement_reason else ""))

    # substitutions.csv keeps the whole decision history: earlier rows are preserved.
    subs_path = RUNTIME_ROOT / "substitutions.csv"
    existing: list[dict[str, str]] = []
    if subs_path.is_file():
        with subs_path.open(encoding="utf-8", newline="") as handle:
            existing = [r for r in csv.DictReader(handle)]
    by_pair = {(r["replaced_image_key"], r["replacement_image_key"]): r for r in existing}
    for row in substitutions:
        by_pair.setdefault((row["replaced_image_key"], row["replacement_image_key"]), row)
    with subs_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, SUBS_FIELDS)
        writer.writeheader()
        writer.writerows([by_pair[k] for k in sorted(by_pair, key=lambda k: (BATCH3_ORDER.index(k[0])
                                                                            if k[0] in BATCH3_ORDER else 99, k[1]))])

    plan = {"generated_at": utc_now(), "batch": "batch3", "target_images": TARGET,
            "selected": selected, "rejected": rejected, "substitutions": substitutions,
            "reserves_unused": reserve_pool,
            "phases": {k: status_of(k).get("phase") for k in selected}}
    (RUNTIME_ROOT / "batch3-plan.json").write_text(__import__("json").dumps(plan, indent=2) + "\n",
                                                   encoding="utf-8")
    for row in substitutions:
        log_event("plan", f"{row['replaced_image_key']} ({row['replaced_tag']}): {row['reason']}",
                  f"substituted with {row['replacement_image_key'] or '(no reserve left)'}",
                  "recorded in substitutions.csv", batch="batch3")
    if args.print_queue:
        print("\n".join(selected))
        return 0
    print(f"selected {len(selected)}/{TARGET}: {selected}")
    print(f"rejected: {rejected}")
    print(f"substitutions: {[(r['replaced_image_key'], r['replacement_image_key']) for r in substitutions]}")
    print(f"reserves unused: {reserve_pool}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
