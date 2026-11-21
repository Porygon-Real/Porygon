#!/usr/bin/env python3
"""Download the native linux/arm64 builds of the monitored images.

Smallest and pilot images first. Each pull is retried with increasing waits;
a tag that still fails is moved to the end of the queue and tried once more.
Every pulled image is checked to be arm64, and its digest is logged to
datasets/runtime/prefetch.json (rewritten after every tag, so progress survives
an interruption). Already-present arm64 images are recorded without re-pulling.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dataset"))
from common import ROOT, read_json, run, utc_now, write_json  # noqa: E402

RUNTIME_ROOT = ROOT / "datasets" / "runtime"
OUT = RUNTIME_ROOT / "prefetch.json"
OUT_BATCH2 = RUNTIME_ROOT / "prefetch-batch2.json"
LOG = ROOT / "datasets" / "runtime" / "run-log.jsonl"
PLATFORM = "linux/arm64"

TAGS = [
    "redis:latest", "memcached:latest", "httpd:latest", "traefik:latest", "rabbitmq:latest",
    "mariadb:latest", "php:7.4-apache", "tomcat:latest", "eclipse-temurin:21", "mysql:8.4",
    "ghost:latest", "wordpress:latest", "drupal:latest", "mongo:latest", "nextcloud:latest",
    "node:16", "node:22", "python:3.6", "python:3.8", "python:latest", "ruby:latest", "golang:latest",
]
# Batch 2 (held-out test set): 22 primary tags, then the reserves in substitution order.
BATCH2_TAGS = [
    "nginx:1.27", "caddy:2", "postgres:16", "valkey/valkey:8", "influxdb:2", "couchdb:3",
    "prom/prometheus:latest", "grafana/grafana:latest", "hashicorp/consul:latest",
    "eclipse-mosquitto:2", "registry:2", "gitea/gitea:latest", "nats:alpine", "php:8.3-apache",
    "mysql:9", "registry.access.redhat.com/ubi9/httpd-24", "registry.access.redhat.com/ubi9/nginx-124",
    "registry.access.redhat.com/ubi9/python-312", "node:20-alpine", "python:3.12-alpine",
    "ruby:3.3-alpine", "perl:5.40",
]
BATCH2_RESERVE_TAGS = [
    "varnish:7", "memcached:1.6-alpine", "httpd:2.4-alpine", "redis:7.4-alpine",
    "hashicorp/vault:latest", "rabbitmq:3-management-alpine", "adminer:latest", "mariadb:11",
]

# Batch 3 (second held-out set): 22 primary tags, then its reserves. The first eight
# primaries were batch 2's unused reserves and may already be present locally.
BATCH3_TAGS = [
    "varnish:7", "memcached:1.6-alpine", "httpd:2.4-alpine", "redis:7.4-alpine",
    "hashicorp/vault:latest", "rabbitmq:3-management-alpine", "adminer:latest", "mariadb:11",
    "mongo:7", "postgres:15-alpine", "nginx:alpine", "tomcat:9-jdk17", "traefik:v2.11",
    "influxdb:1.11", "eclipse-temurin:21-alpine", "golang:1.22-alpine", "php:8.2-cli",
    "python:3.11-slim", "node:18-bookworm-slim", "ghost:5-alpine",
    "registry.access.redhat.com/ubi9/nodejs-20", "registry.access.redhat.com/ubi9/php-82",
]
BATCH3_RESERVE_TAGS = [
    "solr:9", "registry.access.redhat.com/ubi9/ruby-33", "phpmyadmin:latest", "matomo:5",
]

WAITS = [30, 60, 120, 240, 300]  # seconds before attempts 2..5


BATCH = "batch1"  # set from --batch; every run-log line records which batch it belongs to


def log_fix(what_failed: str, action: str, result: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"time": utc_now(), "step": "prefetch", "failed": what_failed,
                                 "action": action, "result": result, "batch": BATCH}) + "\n")


def inspect(tag: str) -> dict | None:
    result = run(["docker", "image", "inspect", tag])
    return json.loads(result.stdout)[0] if result.returncode == 0 else None


def entry_for(tag: str, info: dict, attempts: int) -> dict:
    repo = tag.split(":", 1)[0]
    digests = info.get("RepoDigests") or []
    match = [d for d in digests if d.split("@", 1)[0] in (repo, f"docker.io/library/{repo}")]
    return {"status": "ok" if info.get("Architecture") == "arm64" else "wrong_architecture",
            "architecture": info.get("Architecture"), "os": info.get("Os"), "image_id": info.get("Id"),
            "repo_digest": (match or digests or [None])[0], "size_bytes": info.get("Size"),
            "attempts": attempts, "finished_at": utc_now()}


def pull(tag: str, attempts_allowed: int) -> dict:
    last_error = ""
    for attempt in range(1, attempts_allowed + 1):
        print(f"  pull {tag:22} attempt {attempt}", flush=True)
        result = run(["docker", "pull", "--platform", PLATFORM, tag], timeout=5400)
        if result.returncode == 0:
            info = inspect(tag)
            if info:
                if attempt > 1:
                    log_fix(f"docker pull {tag}: {last_error}", f"retried pull (attempt {attempt})", "ok")
                return entry_for(tag, info, attempt)
            last_error = "pulled but image inspect failed"
        else:
            last_error = (result.stderr.strip() or result.stdout.strip())[-500:]
        print(f"    failed: {last_error[-200:]}", flush=True)
        if attempt < attempts_allowed:
            time.sleep(WAITS[min(attempt - 1, len(WAITS) - 1)])
    log_fix(f"docker pull {tag}: {last_error}", f"retried {attempts_allowed} times", "still failing")
    return {"status": "pull_failed", "error": last_error, "attempts": attempts_allowed, "finished_at": utc_now()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="*", help="limit to these tags")
    parser.add_argument("--batch2", action="store_true", help="the batch 2 tags and their reserves")
    parser.add_argument("--batch3", action="store_true", help="the batch 3 tags and their reserves")
    parser.add_argument("--out", help="record file (default: prefetch.json, or prefetch-batchN.json with --batchN)")
    args = parser.parse_args()
    tags = args.only or (BATCH2_TAGS + BATCH2_RESERVE_TAGS if args.batch2
                         else BATCH3_TAGS + BATCH3_RESERVE_TAGS if args.batch3 else TAGS)
    global BATCH, OUT
    if args.batch2:
        BATCH, OUT = "batch2", OUT_BATCH2
    if args.batch3:
        BATCH, OUT = "batch3", RUNTIME_ROOT / "prefetch-batch3.json"
    if args.out:
        OUT = Path(args.out)

    record = read_json(OUT, None) or {"platform": PLATFORM, "started_at": utc_now(), "images": {}}
    queue = list(tags)
    retried_at_end: set[str] = set()
    while queue:
        tag = queue.pop(0)
        info = inspect(tag)
        if info and info.get("Architecture") == "arm64" and record["images"].get(tag, {}).get("status") == "ok":
            print(f"  have {tag:22} (arm64, already recorded)")
            continue
        entry = pull(tag, 5 if tag not in retried_at_end else 3)
        if entry["status"] == "pull_failed" and tag not in retried_at_end:
            retried_at_end.add(tag)
            queue.append(tag)
            log_fix(f"docker pull {tag} failed 5 times", "moved to end of queue", "pending")
        record["images"][tag] = entry
        write_json(OUT, record)
        print(f"       {tag:22} {entry['status']} {entry.get('repo_digest') or ''}", flush=True)

    record["finished_at"] = utc_now()
    write_json(OUT, record)
    failed = [t for t in tags if record["images"].get(t, {}).get("status") != "ok"]
    print("all arm64 images present" if not failed else f"failed: {failed}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
