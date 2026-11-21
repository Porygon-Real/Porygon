#!/usr/bin/env python3
"""Remove the old amd64 images used by the static vulnerability days.

Only tags on the fixed allow-list below are touched. Each one is removed only if
Docker reports it as amd64. No --force, no prune. Images used by a container are
reported and skipped. The before/after state is saved to
datasets/runtime/image-cleanup.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dataset"))
from common import ROOT, run, utc_now, write_json  # noqa: E402

OUT = ROOT / "datasets" / "runtime" / "image-cleanup.json"

ALLOW_LIST = [
    "python:latest", "ruby:latest", "golang:latest", "wordpress:latest", "python:3.8", "mysql:8.4",
    "httpd:latest", "node:22", "nextcloud:latest", "ubuntu:22.04", "redis:latest", "php:7.4-apache",
    "mariadb:latest", "tomcat:latest", "eclipse-temurin:21", "ghost:latest", "debian:bookworm",
    "rabbitmq:latest", "python:3.6", "mongo:latest", "traefik:latest", "rust:latest", "drupal:latest",
    "almalinux:9", "memcached:latest", "node:16",
]

# Never removed, whatever happens to the list above.
PROTECTED_PREFIXES = (
    "porygon-", "postgres:17.10-bookworm", "falcosecurity/", "alpine:", "nginxinc/", "mongo:8",
    "webgoat/", "pgvector/", "dxflrs/", "expos", "ghcr.io/drizzle-team/",
)


def snapshot() -> dict:
    images = run(["docker", "image", "ls", "--format", "{{json .}}"]).stdout.splitlines()
    df = run(["docker", "system", "df", "--format", "{{json .}}"]).stdout.splitlines()
    host = run(["df", "-k", "/"]).stdout
    return {
        "taken_at": utc_now(),
        "images": [json.loads(line) for line in images if line.strip()],
        "docker_system_df": [json.loads(line) for line in df if line.strip()],
        "host_df_root": host,
    }


def main() -> int:
    assert len(ALLOW_LIST) == 26 and len(set(ALLOW_LIST)) == 26
    for tag in ALLOW_LIST:
        if tag.startswith(PROTECTED_PREFIXES):
            raise SystemExit(f"allow-list contains a protected image: {tag}")

    record = {"started_at": utc_now(), "allow_list": ALLOW_LIST, "before": snapshot(), "results": {}}
    containers = run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.ImageID}}"]).stdout

    for tag in ALLOW_LIST:
        inspect = run(["docker", "image", "inspect", tag])
        if inspect.returncode != 0:
            record["results"][tag] = {"status": "not_present"}
            print(f"  {tag:24} not present")
            continue
        info = json.loads(inspect.stdout)[0]
        arch = info.get("Architecture")
        entry = {"image_id": info.get("Id"), "architecture": arch, "repo_digests": info.get("RepoDigests")}
        if arch != "amd64":
            entry["status"] = "skipped_not_amd64"
        else:
            users = [line for line in containers.splitlines()
                     if line.split("\t")[1:2] == [tag] or info.get("Id", "x") in line]
            if users:
                entry |= {"status": "skipped_in_use", "containers": users}
            else:
                result = run(["docker", "image", "rm", tag])
                entry |= {"status": "removed" if result.returncode == 0 else "rm_failed",
                          "stdout": result.stdout.strip()[-1000:], "stderr": result.stderr.strip()[-1000:]}
        record["results"][tag] = entry
        print(f"  {tag:24} {entry['status']}")

    record["after"] = snapshot()
    record["finished_at"] = utc_now()
    write_json(OUT, record)
    counts: dict[str, int] = {}
    for entry in record["results"].values():
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    print(counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
