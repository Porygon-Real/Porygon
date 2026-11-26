#!/usr/bin/env python3
"""Porygon Training Data Collector.

Executes controlled trials in disposable Docker containers and writes
trial intervals and ground-truth labels to runs.csv.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import threading
import time
from uuid import uuid4

_CSV_LOCK = threading.Lock()

CLASSES = (
    "benign",
    "reconnaissance",
    "privilege_escalation",
    "shell_escape",
    "suspicious_tooling",
)

SPLITS = ("fit", "calibration", "test")


def assign_split(run_id: str, splits: tuple[str, ...] = SPLITS) -> str:
    """Deterministically assign a run to a split using SHA-256."""
    digest = hashlib.sha256(run_id.encode("utf-8")).digest()
    return splits[int.from_bytes(digest[:8], "big") % len(splits)]


def now_utc_iso() -> str:
    """Current UTC timestamp in ISO format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run_cmd(args: list[str], timeout: float = 30) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess command."""
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def docker_exec(container: str, binary: str, *args: str) -> None:
    """Run a binary directly via docker exec with NO shell wrapper."""
    cmd = ["docker", "exec", container, binary] + list(args)
    try:
        run_cmd(cmd, timeout=15)
    except Exception:
        pass


def docker_exec_shell(container: str, shell_bin: str, command: str) -> None:
    """Run a shell command via docker exec (allowed ONLY for shell_escape)."""
    cmd = ["docker", "exec", container, shell_bin, "-c", command]
    try:
        run_cmd(cmd, timeout=15)
    except Exception:
        pass


def check_pipeline_health_probe(timeout_seconds: float = 12.0) -> bool:
    """Verify that process execution events are actively reaching PostgreSQL.

    Spawns a temporary probe container, executes an execve command, and polls
    process_exec_events in PostgreSQL. If the event is not recorded within timeout,
    returns False so the run aborts immediately before wasting trial containers.
    """
    token = f"probe_{uuid4().hex[:6]}"
    probe_id = f"porygon-probe-{uuid4().hex[:8]}"
    print(f"[*] Running pre-batch pipeline health probe ({probe_id}, token={token})...")

    start_cmd = [
        "docker", "run", "--rm",
        "--name", probe_id,
        "alpine:latest",
        "echo", token,
    ]
    proc = run_cmd(start_cmd, timeout=10)
    if proc.returncode != 0:
        print(f"[!] Health probe container execution failed: {proc.stderr}")
        return False

    env: dict[str, str] = {}
    for env_path in [Path(".env"), Path("../.env"), Path("backend/.env")]:
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()

    db_user = env.get("POSTGRES_USER", "porygon")
    db_name = env.get("POSTGRES_DB", "porygon")
    sql = f"SELECT count(*) FROM process_exec_events WHERE command_line LIKE '%{token}%';"

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        time.sleep(1.5)
        res = run_cmd([
            "docker", "exec", "porygon-postgres-1",
            "psql", "-U", db_user, "-d", db_name, "-t", "-A", "-c", sql,
        ], timeout=5)
        cnt = int(res.stdout.strip() or 0)
        if cnt > 0:
            print(f"[+] Health probe passed: {cnt} events verified live in PostgreSQL.")
            return True

    print(f"[!] FATAL: Pre-batch health probe timed out after {timeout_seconds}s! Event '{token}' not found in process_exec_events.")
    return False


def verify_image_binaries(image: str) -> bool:
    """Verify that image contains sudo, nsenter, capsh, gcc, nc."""
    required = ["sudo", "nsenter", "capsh", "gcc", "nc"]
    proc = run_cmd(["docker", "run", "--rm", image, "which"] + required)
    found = [line.strip().split("/")[-1] for line in proc.stdout.splitlines() if line.strip()]
    missing = [b for b in required if b not in found and not any(line.endswith(b) for line in proc.stdout.splitlines())]
    if missing:
        print(f"[!] Warning: Image {image} missing required binaries: {missing}")
        return False
    print(f"[+] Verified all required binaries exist in {image}: {required}")
    return True


def execute_benign_web_api(container: str, stop_event: float) -> None:
    """Simulate web service API traffic, health probes, and metrics scraping."""
    web_cmds = [
        ("curl", ["-s", "http://127.0.0.1:8000/healthz"]),
        ("curl", ["-s", "http://127.0.0.1:8000/api/v1/status"]),
        ("curl", ["-s", "-o", "/dev/null", "http://127.0.0.1:8000/metrics"]),
        ("wget", ["-q", "-O-", "http://127.0.0.1:8000/ready"]),
        ("curl", ["-s", "-I", "http://127.0.0.1:8000/"]),
    ]
    diag_cmds = [
        ("uptime", []),
        ("date", []),
        ("df", ["-h"]),
    ]
    while time.time() < stop_event:
        if random.random() < 0.75:
            bin_name, args = random.choice(web_cmds)
        else:
            bin_name, args = random.choice(diag_cmds)
        docker_exec(container, bin_name, *args)
        time.sleep(random.uniform(1.0, 3.5))


def execute_benign_sysadmin(container: str, stop_event: float) -> None:
    """Simulate DevOps and system administrative auditing (hard benign)."""
    admin_cmds = [
        ("uname", ["-a"]),
        ("id", []),
        ("whoami", []),
        ("hostname", []),
        ("uptime", []),
        ("df", ["-h"]),
        ("free", ["-m"]),
        ("ps", ["aux"]),
        ("cat", ["/etc/os-release"]),
        ("cat", ["/proc/version"]),
        ("cat", ["/etc/hosts"]),
        ("cat", ["/etc/resolv.conf"]),
        ("head", ["-n", "10", "/etc/passwd"]),
        ("cat", ["/proc/meminfo"]),
        ("cat", ["/proc/loadavg"]),
    ]
    while time.time() < stop_event:
        bin_name, args = random.choice(admin_cmds)
        docker_exec(container, bin_name, *args)
        time.sleep(random.uniform(2.0, 5.0))


def execute_benign_batch_worker(container: str, stop_event: float) -> None:
    """Simulate batch worker processing, file management, and integrity checks."""
    worker_cmds = [
        ("du", ["-sh", "/tmp"]),
        ("find", ["/var", "-maxdepth", "2"]),
        ("sha256sum", ["/etc/os-release"]),
        ("sha256sum", ["/etc/hosts"]),
        ("md5sum", ["/etc/resolv.conf"]),
        ("head", ["-n", "20", "/etc/services"]),
        ("tar", ["-cf", "/tmp/backup.tar", "/etc/resolv.conf"]),
        ("gzip", ["-f", "/tmp/backup.tar"]),
        ("rm", ["-f", "/tmp/backup.tar.gz"]),
        ("date", ["+%Y-%m-%d %H:%M:%S"]),
        ("uptime", []),
    ]
    while time.time() < stop_event:
        bin_name, args = random.choice(worker_cmds)
        docker_exec(container, bin_name, *args)
        time.sleep(random.uniform(1.5, 4.5))


def execute_benign_workload(container: str, stop_event: float) -> None:
    """Execute randomized, varied benign workloads across trials."""
    sub_workloads = [
        execute_benign_web_api,
        execute_benign_sysadmin,
        execute_benign_batch_worker,
    ]
    # Pick a persona for this trial to ensure high cross-trial variance
    persona = random.choice(sub_workloads)
    persona(container, stop_event)


def execute_recon_workload(container: str, stop_event: float) -> None:
    """Execute reconnaissance commands directly without shell wrapper."""
    recon_cmds = [
        ("whoami", []),
        ("uname", ["-a"]),
        ("id", []),
        ("hostname", []),
        ("ps", ["aux"]),
        ("netstat", ["-tlpn"]),
        ("ip", ["addr"]),
        ("cat", ["/proc/cpuinfo"]),
        ("cat", ["/etc/passwd"]),
        ("find", ["/etc", "-maxdepth", "2"]),
    ]
    benign_noise = [
        ("date", []),
        ("uptime", []),
        ("df", ["-h"]),
    ]

    while time.time() < stop_event:
        if random.random() < 0.8:
            bin_name, args = random.choice(recon_cmds)
        else:
            bin_name, args = random.choice(benign_noise)
        docker_exec(container, bin_name, *args)
        time.sleep(random.uniform(1.5, 4.0))


def execute_privesc_workload(container: str, stop_event: float) -> None:
    """Execute privilege escalation commands directly without shell wrapper."""
    priv_cmds = [
        ("sudo", ["-l"]),
        ("sudo", ["-V"]),
        ("su", ["-c", "id"]),
        ("nsenter", ["--help"]),
        ("capsh", ["--print"]),
        ("chmod", ["+s", "/tmp"]),
        ("cat", ["/etc/shadow"]),
        ("find", ["/usr/bin", "-perm", "-4000"]),
    ]
    benign_noise = [
        ("whoami", []),
        ("id", []),
        ("date", []),
    ]

    while time.time() < stop_event:
        if random.random() < 0.8:
            bin_name, args = random.choice(priv_cmds)
        else:
            bin_name, args = random.choice(benign_noise)
        docker_exec(container, bin_name, *args)
        time.sleep(random.uniform(1.5, 4.0))


def execute_tooling_workload(container: str, stop_event: float) -> None:
    """Execute suspicious tooling commands directly without shell wrapper."""
    tooling_cmds = [
        ("curl", ["-s", "http://127.0.0.1:9999/stage2"]),
        ("wget", ["-q", "-O-", "http://127.0.0.1:9999/miner"]),
        ("nc", ["-zv", "127.0.0.1", "4444"]),
        ("gcc", ["--version"]),
        ("wget", ["--help"]),
        ("curl", ["--version"]),
    ]
    benign_noise = [
        ("uptime", []),
        ("cat", ["/etc/hosts"]),
        ("date", []),
    ]

    while time.time() < stop_event:
        if random.random() < 0.8:
            bin_name, args = random.choice(tooling_cmds)
        else:
            bin_name, args = random.choice(benign_noise)
        docker_exec(container, bin_name, *args)
        time.sleep(random.uniform(1.5, 4.0))


def execute_shell_escape_workload(container: str, stop_event: float) -> None:
    """Execute shell escape commands (shell wrappers explicitly permitted here)."""
    shell_cmds = [
        ("/bin/sh", "echo 'interactive shell session'; id; whoami"),
        ("/bin/bash", "sh -c 'uname -a; cat /proc/1/cgroup'"),
        ("/bin/sh", "cat /proc/self/status | head -n 10"),
        ("/bin/bash", "echo 'subshell probe'; ps aux"),
        ("/bin/sh", "cd /tmp && pwd"),
    ]
    benign_noise = [
        ("date", []),
        ("uptime", []),
    ]

    while time.time() < stop_event:
        if random.random() < 0.85:
            shell_bin, script = random.choice(shell_cmds)
            docker_exec_shell(container, shell_bin, script)
        else:
            bin_name, args = random.choice(benign_noise)
            docker_exec(container, bin_name, *args)
        time.sleep(random.uniform(1.5, 4.0))


WORKLOAD_EXECUTORS = {
    "benign": execute_benign_workload,
    "reconnaissance": execute_recon_workload,
    "privilege_escalation": execute_privesc_workload,
    "suspicious_tooling": execute_tooling_workload,
    "shell_escape": execute_shell_escape_workload,
}


def generate_run_id_for_split(target_split: str) -> str:
    """Generate a run_id that deterministically produces target_split via assign_split."""
    if target_split == "baseline":
        return f"run-base-{uuid4().hex[:10]}"
    while True:
        rid = f"run-{uuid4().hex[:12]}"
        if assign_split(rid) == target_split:
            return rid


def run_single_trial(
    label: str,
    target_split: str,
    image: str,
    duration_seconds: int,
    output_csv: Path,
) -> dict[str, str]:
    """Execute a single trial in an isolated disposable container."""
    run_id = generate_run_id_for_split(target_split)
    split = target_split
    container_name = f"porygon-train-{label[:4]}-{uuid4().hex[:8]}"

    # Start disposable container with no host mounts and no privileged flag
    start_cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--rm",
        "--label", "com.porygon.training=true",
        image,
        "sleep", str(duration_seconds + 120),
    ]
    proc = run_cmd(start_cmd)
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to start container {container_name}: {proc.stderr}")
    container_id = proc.stdout.strip()

    start_time = now_utc_iso()
    print(f"[*] Started trial {run_id} ({label}) on {container_name} [{split}] for {duration_seconds}s...")

    try:
        # Give container 2s to initialize
        time.sleep(2.0)
        stop_at = time.time() + duration_seconds
        executor = WORKLOAD_EXECUTORS[label]
        executor(container_name, stop_at)
    finally:
        end_time = now_utc_iso()
        # Cleanly stop/remove container
        run_cmd(["docker", "rm", "-f", container_name])
        print(f"[+] Completed trial {run_id} ({label}) [{split}]. Container removed.")

    record = {
        "container_name": container_name,
        "container_id": container_id,
        "label": label,
        "run_id": run_id,
        "split": split,
        "start_time": start_time,
        "end_time": end_time,
        "image": image,
    }

    # Write record to runs.csv (thread-safe)
    with _CSV_LOCK:
        write_header = not output_csv.exists()
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        with output_csv.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "container_name", "container_id", "label", "run_id", "split",
                    "start_time", "end_time", "image",
                ],
            )
            if write_header:
                writer.writeheader()
            writer.writerow(record)

    return record


def main() -> int:
    parser = argparse.ArgumentParser(description="Porygon Training Data Collector")
    parser.add_argument("--pilot", action="store_true", help="Run in pilot mode (2 trials per class)")
    parser.add_argument("--top-up", action="store_true", help="Run top-up trials: 8 shell_escape (fit) + 2 suspicious_tooling (fit)")
    parser.add_argument("--rerun-zeros", action="store_true", help="Rerun all trials that have zero events in PostgreSQL")
    parser.add_argument("--concurrency", type=int, default=1, help="Max parallel trials (default: 1)")
    parser.add_argument("--attack-trials-per-class", type=int, default=40, help="Attack trials per class (default: 40)")
    parser.add_argument("--benign-trials", type=int, default=45, help="Total benign training trials (default: 45)")
    parser.add_argument("--baseline-trials", type=int, default=15, help="Separate benign baseline trials (default: 15)")
    parser.add_argument("--trial-duration", type=int, default=240, help="Trial duration in seconds (default: 240 = 4 min)")
    parser.add_argument("--image", default="porygon-training-workload:latest", help="Container image to use")
    parser.add_argument("--output", default="backend/ml_training/runs.csv", help="Output path for runs.csv")

    args = parser.parse_args()
    output_csv = Path(args.output)

    print("=" * 60)
    print("PORYGON TRAINING DATA COLLECTION TOOL")
    print("=" * 60)

    # 1. Verify image binaries
    if not verify_image_binaries(args.image):
        print(f"[!] Warning: proceeding with available binaries in {args.image}")

    # Determine trial plan with structured split distribution
    if args.rerun_zeros:
        print("[*] RERUN-ZEROS MODE ACTIVATED: Identifying zero-event trials...")
        if not output_csv.exists():
            print(f"[!] Error: {output_csv} does not exist.")
            return 1
        with output_csv.open("r", encoding="utf-8") as f:
            existing_runs = list(csv.DictReader(f))

        # Discard the 10 extra fit-only top-up trials if present (keeping original 220 planned trials)
        if len(existing_runs) > 220:
            print(f"[*] Trimming {len(existing_runs) - 220} extra top-up trials back to 220 base trials.")
            existing_runs = existing_runs[:220]

        env: dict[str, str] = {}
        for env_path in [Path(".env"), Path("../.env"), Path("backend/.env")]:
            if env_path.exists():
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        env[k.strip()] = v.strip()
        db_user = env.get("POSTGRES_USER", "porygon")
        db_name = env.get("POSTGRES_DB", "porygon")

        valid_runs = []
        zero_runs = []
        print("[*] Scanning database for zero-event trials...")
        for r in existing_runs:
            cid = r["container_id"]
            sql = f"SELECT count(*) FROM process_exec_events WHERE container_id = '{cid}' OR container_id LIKE '{cid[:12]}%';"
            res = run_cmd([
                "docker", "exec", "porygon-postgres-1",
                "psql", "-U", db_user, "-d", db_name, "-t", "-A", "-c", sql,
            ], timeout=5)
            cnt = int(res.stdout.strip() or 0)
            if cnt > 0:
                valid_runs.append(r)
            else:
                zero_runs.append(r)

        print(f"[+] Found {len(valid_runs)} valid trials with events, and {len(zero_runs)} zero-event trials to rerun.")
        # Rewrite runs.csv with only the valid runs
        with output_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "container_name", "container_id", "label", "run_id", "split",
                    "start_time", "end_time", "image",
                ],
            )
            writer.writeheader()
            writer.writerows(valid_runs)

        # Plan the rerun with exact original class and split
        trial_plan = [(r["label"], r["split"]) for r in zero_runs]
    elif args.top_up:
        print("[*] TOP-UP MODE ACTIVATED: 8 shell_escape (fit) + 2 suspicious_tooling (fit).")
        trial_plan: list[tuple[str, str]] = [("shell_escape", "fit")] * 8 + [("suspicious_tooling", "fit")] * 2
    elif args.pilot:
        print("[*] PILOT MODE ACTIVATED: 2 trials per class + 2 baseline trials.")
        trial_plan: list[tuple[str, str]] = [("benign", "baseline"), ("benign", "baseline")]
        for cls in CLASSES:
            trial_plan.append((cls, "fit"))
            trial_plan.append((cls, "test"))
    else:
        trial_plan: list[tuple[str, str]] = []
        # Separate baseline-only trials (Rule 1: NOT exported as training rows)
        trial_plan.extend([("benign", "baseline")] * args.baseline_trials)

        # Benign training trials (split: fit, calibration, test)
        benign_fit = int(round(args.benign_trials * 0.40))
        benign_cal = int(round(args.benign_trials * 0.30))
        benign_test = args.benign_trials - benign_fit - benign_cal
        trial_plan.extend([("benign", "fit")] * benign_fit)
        trial_plan.extend([("benign", "calibration")] * benign_cal)
        trial_plan.extend([("benign", "test")] * benign_test)

        # Attack trials (40 per class: 16 fit, 12 calibration, 12 test)
        for cls in CLASSES:
            if cls != "benign":
                att_fit = int(round(args.attack_trials_per_class * 0.40))
                att_cal = int(round(args.attack_trials_per_class * 0.30))
                att_test = args.attack_trials_per_class - att_fit - att_cal
                trial_plan.extend([(cls, "fit")] * att_fit)
                trial_plan.extend([(cls, "calibration")] * att_cal)
                trial_plan.extend([(cls, "test")] * att_test)

    random.shuffle(trial_plan)
    print(f"[*] Total planned trials: {len(trial_plan)} (Duration per trial: {args.trial_duration}s)")
    print(f"[*] Concurrency level: {args.concurrency}")
    print(f"[*] Output path: {output_csv}")

    results = []
    if args.concurrency > 1:
        import concurrent.futures
        batch_size = args.concurrency
        batches = [trial_plan[i:i + batch_size] for i in range(0, len(trial_plan), batch_size)]
        print(f"[*] Executing {len(trial_plan)} trials in {len(batches)} batches of up to {batch_size} parallel workers...")

        for b_idx, batch in enumerate(batches, start=1):
            print(f"\n=== Starting Batch {b_idx}/{len(batches)} ({len(batch)} parallel trials) ===")
            # Pre-batch pipeline health probe (Rule 4)
            if not check_pipeline_health_probe():
                print(f"[!] FATAL: Pre-batch health probe failed before batch {b_idx}! Aborting run.")
                return 1

            with concurrent.futures.ThreadPoolExecutor(max_workers=len(batch)) as pool:
                futures = [
                    pool.submit(
                        run_single_trial,
                        label=lbl,
                        target_split=splt,
                        image=args.image,
                        duration_seconds=args.trial_duration,
                        output_csv=output_csv,
                    )
                    for lbl, splt in batch
                ]
                for f in concurrent.futures.as_completed(futures):
                    try:
                        results.append(f.result())
                    except Exception as exc:
                        print(f"[!] Trial error: {exc}")
    else:
        for idx, (label, splt) in enumerate(trial_plan, start=1):
            print(f"\n--- Progress: Trial {idx}/{len(trial_plan)} [{label} | {splt}] ---")
            if not check_pipeline_health_probe():
                print("[!] FATAL: Pre-batch health probe failed! Aborting run.")
                return 1
            rec = run_single_trial(
                label=label,
                target_split=splt,
                image=args.image,
                duration_seconds=args.trial_duration,
                output_csv=output_csv,
            )
            results.append(rec)
            time.sleep(2.0)

    print("\n" + "=" * 60)
    print("[+] ALL PLANNED TRIALS COMPLETED SUCCESSFULLY!")
    print(f"[+] Runs registry saved to: {output_csv}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
