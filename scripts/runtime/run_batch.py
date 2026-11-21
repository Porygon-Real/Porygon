#!/usr/bin/env python3
"""Run a queue of images through run_image.py, up to 4 at a time.

Resumable: images already complete or failed are skipped by run_image.py, and an
interrupted image resumes from its status.json. Images whose sidecar shares a
monitored digest never run at the same time.

Free disk below 30 GB stops new images from starting and writes NEEDS_ATTENTION.md.
Failed images are recorded the same way: in batch 1 three of them stopped the
queue, while a later batch (--batch) records them and keeps going, because a
failed image is substituted from the reserve list instead of blocking the rest.
A later batch also stops starting new images while a stop file is present, which
is how the sensor watchdog halts collection it cannot repair.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recipes import BATCH_ORDER, CONFLICTS  # noqa: E402
from rt_common import RAW_ROOT, RUNTIME_ROOT, log_event, read_json, utc_now  # noqa: E402

HERE = Path(__file__).resolve().parent
MIN_FREE_GB = 30
STOP_FILE = RUNTIME_ROOT / "batch2-stop"  # replaced by "<batch>-stop" for the running batch in main()
# Set PORYGON_RT_REQUIRE_MATCHER=1 to check the backend's detection matcher before every image
# (matcher_guard.py); a failed check stops the queue from starting further images.
REQUIRE_MATCHER = os.environ.get("PORYGON_RT_REQUIRE_MATCHER") == "1"


def phase(key: str) -> str | None:
    return (read_json(RAW_ROOT / key / "status.json", {}) or {}).get("phase")


def escalate(reason: str, proposal: str) -> None:
    note = (f"\n## Batch queue stopped ({utc_now()})\n\n### What happened\n\n{reason}\n\n### State\n\n"
            "The batch stopped starting new images. Images already running finished their current run; "
            "runtime containers were removed by run_image.py. The Porygon stack was left running.\n\n"
            f"### Proposed command(s)\n\n```bash\n{proposal}\n```\n")
    path = RUNTIME_ROOT / "NEEDS_ATTENTION.md"
    header = "" if path.is_file() else "# Needs attention\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(header + note)
    log_event("batch", reason, "stopped the queue and wrote NEEDS_ATTENTION.md", "recorded")


def record_failures(failed: list[str], batch: str) -> None:
    """A later batch records failed images and keeps going; they are substituted instead."""
    note = (f"\n## Failed images ({utc_now()}, {batch})\n\n"
            f"{len(failed)} image(s) failed and will be substituted from the reserve list: {failed}\n\n"
            "The queue was not stopped: each failed image is recorded in its own raw/<key>/status.json "
            "with the error, and the reserve run takes its place.\n")
    path = RUNTIME_ROOT / "NEEDS_ATTENTION.md"
    header = "" if path.is_file() else "# Needs attention\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(header + note)
    log_event("batch", f"{len(failed)} images failed: {failed}", "recorded; the queue kept running", "recorded")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="*", default=BATCH_ORDER)
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--batch", default="batch1", help="collection batch recorded with every run")
    args = parser.parse_args()
    if not args.images:
        args.images = BATCH_ORDER
    env = {**os.environ, "PORYGON_RT_BATCH": args.batch}
    global STOP_FILE
    STOP_FILE = RUNTIME_ROOT / f"{args.batch}-stop"
    reported_failures: set[str] = set()
    queue = [k for k in args.images if phase(k) not in ("complete", "failed")]
    running: dict[str, subprocess.Popen] = {}
    logs_dir = RUNTIME_ROOT / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    stopped = False
    while queue or running:
        for key, proc in list(running.items()):
            if proc.poll() is not None:
                print(f"{utc_now()} finished {key} rc={proc.returncode} phase={phase(key)}", flush=True)
                del running[key]
        failed = [k for k in args.images if phase(k) == "failed"]
        free_gb = shutil.disk_usage("/").free / 1e9
        if args.batch == "batch1":
            if not stopped and len(failed) >= 3:
                escalate(f"{len(failed)} images failed: {failed}",
                         "python3 scripts/runtime/run_batch.py  # after review")
                stopped = True
        else:
            if new_failures := [k for k in failed if k not in reported_failures]:
                reported_failures.update(new_failures)
                record_failures(sorted(reported_failures), args.batch)
            if not stopped and STOP_FILE.is_file():
                escalate(f"{STOP_FILE.name} is present: {STOP_FILE.read_text(encoding='utf-8')[:500]}",
                         f"rm {STOP_FILE}  # after the sensor is working again")
                stopped = True
        if not stopped and free_gb < MIN_FREE_GB:
            escalate(f"free disk {free_gb:.1f} GB < {MIN_FREE_GB} GB", "docker system df  # review before freeing space")
            stopped = True
        if not stopped:
            for key in list(queue):
                if len(running) >= args.parallel:
                    break
                if CONFLICTS.get(key, set()) & set(running):
                    continue
                if REQUIRE_MATCHER:
                    guard = subprocess.run([sys.executable, str(HERE / "matcher_guard.py"), "--batch", args.batch,
                                            "--when", f"before:{key}"], capture_output=True, text=True)
                    if guard.returncode != 0:
                        STOP_FILE.write_text(f"{utc_now()} matcher check failed before {key}: "
                                             f"{guard.stdout.strip()[-800:]}\n", encoding="utf-8")
                        escalate(f"detection matcher check failed before {key}: {guard.stdout.strip()[-800:]}",
                                 "docker compose exec -T backend python -c "
                                 "\"import porygon_api.detection as d; print(d.MATCHER_REVISION)\"")
                        stopped = True
                        break
                queue.remove(key)
                handle = (logs_dir / f"{key}.log").open("a", encoding="utf-8")
                running[key] = subprocess.Popen([sys.executable, "-u", str(HERE / "run_image.py"), key,
                                                 "--batch", args.batch],
                                                stdout=handle, stderr=subprocess.STDOUT, env=env)
                print(f"{utc_now()} started {key}", flush=True)
                time.sleep(20)  # stagger start-ups
        elif not running:
            break
        time.sleep(10)
    print(f"{utc_now()} batch done; " + ", ".join(f"{k}={phase(k)}" for k in args.images), flush=True)
    return 1 if stopped else 0


if __name__ == "__main__":
    raise SystemExit(main())
