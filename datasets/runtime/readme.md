# Runtime monitoring dataset (Porygon, 20 Nov 2026)

Porygon's runtime path (Falco eBPF → telemetry → backend) monitored 22 real
container images running on a single arm64 host. Each image ran a real
service under a normal load. Porygon learned a baseline for it, then 30
one-minute test windows were scored and checked by its detection rules. The
ground truth for each window (normal, hard negative, abnormal) was recorded
before that window started. Every number in this folder was copied or counted
from Porygon's own API responses and database. Nothing was estimated, filled
in or edited.

## Files

| File | Contents |
|---|---|
| `windows.csv` | One row per test window (660): scenario, commands, return code, ground truth, Porygon score and band, rules fired, incident, verdicts and outcomes |
| `rule_matches.csv` | Every detection-rule match per window |
| `process_events.csv` | Every Falco process event Porygon stored, learning and test phases |
| `images.csv` | One row per image: tag, digest, recipe, start command, seed, training period, baseline quality |
| `summary.json` | Confusion matrices overall, per image, per scenario and per kind; per-rule counts; hard-negative FPR; host facts |
| `manifest.json` | SHA-256 of every file in this folder |
| `raw/<image>/` | Untouched records: `status.json`, `baseline.json`, `learning-events.json`, and Porygon's score, detection and event JSON per window |
| `raw-invalid/` | The 8 runs invalidated by the sensor gap (see Incidents), kept unchanged |
| `run-log.jsonl` | Every automatic fix and every approved action, one JSON line each |
| `image-cleanup.json`, `prefetch.json`, `prefetch.log` | Removal of the old amd64 images, and the arm64 download with digests |
| `logs/` | Console output of each image run and of the batch |

Scripts: `scripts/runtime/` (`run_image.py`, `run_batch.py`, `export.py`, `validate.py`).
Make targets: `runtime-up`, `runtime-image IMAGE=<key>`, `runtime-all`, `runtime-build`.

## Host

macOS 26.6.2 on arm64 with Docker Desktop 29.1.3 (Linux kernel 6.12.54-linuxkit,
10 CPUs, 7.65 GiB memory), and Falco 0.45.1 (eBPF). All images are `linux/arm64`;
their digests are in `images.csv` and `prefetch.json`.

## Images (22)

- **Services (14):** redis, memcached, mongo, mysql:8.4, mariadb, httpd, tomcat,
  traefik, rabbitmq, wordpress (with a mariadb sidecar), drupal, nextcloud,
  ghost, php:7.4-apache.
- **Runtimes (8), each running a small server:**
  - python:latest, python:3.8 and python:3.6 run `python -m http.server`;
  - node:22 and node:16 run a small HTTP server;
  - eclipse-temurin:21 runs `jwebserver`;
  - golang runs `go run` on a mounted read-only file;
  - ruby runs a small TCPServer.

  The exact commands are in `images.csv`.

## Protocol

1. **Isolation.** The target container runs on its own `--internal` Docker
   network, with no route to the internet, a memory limit of 1 GB and a limit
   of 512 processes. Docker cannot publish ports for a container on an internal
   network, so a small nginx stream relay joins the internal network and the
   default bridge, and publishes only `127.0.0.1`. The load drivers use that
   relay, so they add no processes inside the monitored container.
2. **Learning (30 min).**
   - A host-side driver sends steady normal load: HTTP requests, Redis, Memcached, MySQL, MongoDB or AMQP operations, at about 2 per second.
   - The container is restarted at 10 and 20 minutes.
   - Porygon then builds a baseline: 60-second windows, at least 20 events and at least 3 non-empty windows. If the quality check fails, learning is extended once by 10 minutes.
   - The baseline is then activated.
3. **Test (30 windows of 60 s).** A schedule seeded per image
   (`sha256("porygon-runtime:<key>")`) gives each image:
   - **normal, 12 windows:** 11 × `RT-NORMAL` and 1 × `RT-NORMAL-RESTART`;
   - **hard negative, 6 windows:** 2 × `RT-HN-ADMIN` (the service's own admin command), 2 × `RT-HN-MAINT-SHELL` (`id; uname -a; ps`), 2 × `RT-HN-LOGS` (`docker logs`);
   - **abnormal, 12 windows:**
     - `RT-AB-SHELL-RECON`, `RT-AB-READ-SHADOW`;
     - `RT-AB-EGRESS` (203.0.113.1, a documentation address) and `RT-AB-NC-CONNECT` (10.255.255.1);
     - `RT-AB-DROPPED-SCRIPT`, `RT-AB-RENAMED-BINARY`, `RT-AB-ROOT-EXEC`;
     - `SCN-LOG4SHELL-SIM`, `SCN-RUNC-ESCAPE-SIM`, `SCN-FLOOD`;
     - `RT-AB-LOW-SLOW`, `RT-AB-PKG-INSTALL`.

   The normal load keeps running through every window.
4. **Scoring.** 45 s after each window ends, Porygon's anomaly score
   (Jensen–Shannon bands: baseline_like < 0.25, elevated < 0.5, high < 0.75,
   extreme) is computed and its detection rules are run.
   - **Incident verdict:** abnormal if Porygon created an incident.
   - **Score verdict:** abnormal if the band is elevated or higher.
   - `action_seen_by_falco` records whether the action's processes appear in Porygon's stored events.

## Results (660 windows, 22 images)

| Verdict | TP | FP | TN | FN | Recall | Precision | FPR | Accuracy |
|---|---|---|---|---|---|---|---|---|
| Incident | 225 | 62 | 334 | 39 | 0.852 | 0.784 | 0.157 | 0.847 |
| Score band | 108 | 9 | 387 | 156 | 0.409 | 0.923 | 0.023 | 0.750 |

- **Normal windows:** 0 false positives in 264.
- **Hard negatives:** false-positive rate 0.470 (62 of 132).
  - `RT-HN-MAINT-SHELL`: 42 of 44 flagged.
  - `RT-HN-ADMIN`: 20 of 44 flagged.
  - `RT-HN-LOGS`: 0 of 44 flagged.
- **Abnormal, per scenario (detected / 22):**
  - `RT-AB-PKG-INSTALL` 22;
  - `RT-AB-SHELL-RECON`, `RT-AB-READ-SHADOW`, `RT-AB-DROPPED-SCRIPT`, `RT-AB-RENAMED-BINARY`, `RT-AB-LOW-SLOW`, `SCN-FLOOD`, `SCN-LOG4SHELL-SIM` and `SCN-RUNC-ESCAPE-SIM` 21 each;
  - `RT-AB-ROOT-EXEC` 20;
  - `RT-AB-EGRESS` 14;
  - `RT-AB-NC-CONNECT` 1.
- **Rules (windows fired):**
  - POR-DET-004 (new process for the image) fired in 225 abnormal and 62 normal windows, and drove every incident.
  - POR-DET-006 is informational and fired in all 660 windows.
  - POR-DET-001 fired in 13 abnormal windows.
  - POR-DET-003 fired in 1 abnormal window.
- **Per image:** recall is 0.83–1.00 for 21 images. **mysql is the exception at 0.17**, because of its coreutils multicall binary (see Findings).

Full breakdowns are in `summary.json`.

## Findings

- **POR-DET-004 does nearly all the work.** Most abnormal windows are caught
  because the attacker's process is new for that image. The anomaly score alone
  catches less than half (recall 0.41), but almost never fires on normal
  windows.
- **Hard negatives are the main source of false positives.** A legitimate
  operator who runs `id`, `uname` or `ps`, or a service's admin tool, is flagged
  as often as an attacker running the same commands, because the rule only
  checks whether the process is new.
- **A multicall binary hides attacks (mysql).** The mysql image ships GNU
  coreutils as a single multicall binary, so Falco reports `/usr/bin/coreutils`
  as the executable for `cat`, `chmod`, `cp`, `date`, `id`, `uname`, `whoami`
  and others. It does so even for the renamed `/tmp/kdevtmpfsi` (see
  `process_events.csv`; mysql is the only image with these events).
  - The entrypoint ran coreutils applets (`date`, `id`, `dirname`, `mkdir`)
    during learning, so `/usr/bin/coreutils` is in mysql's baseline.
  - Porygon's detection (`backend/src/porygon_api/detection.py`) resolves
    applet names only for `busybox` and `toybox` (`MULTICALL_BINARY_NAMES`).
    Every other coreutils applet therefore counts as an already-seen
    executable, and POR-DET-004 cannot report it as new.
  - As a result, 10 of mysql's 12 attacks were not flagged, although Falco saw
    every one of them.
  - The 2 attacks that were caught ran separate binaries: `microdnf` with
    `gpg` in the package-install window, and `curl` in the egress window.
  - Porygon's code was not changed for this dataset.
- **Missing tools lead to missed attacks.** `nc` is absent from 21 of the 22
  images (return code 127), and `wget`/`curl` are absent from several. The
  attempt then runs only `sh`, which is already in the baseline.
- **POR-DET-002 and POR-DET-003 could not fire.** `docker run --health-cmd` is
  always run through `/bin/sh -c` as uid 0, so a shell and root were part of
  every baseline. This was reviewed in the redis pilot and the protocol was
  kept unchanged.

## Incidents during collection

All are logged in `run-log.jsonl`.

- **Relay instead of a published port.** The plan's internal network with a
  published port is impossible in Docker. The nginx relay was added instead,
  and the target still has no internet route.
- **Download problems.**
  - Docker Hub timeouts for eclipse-temurin, mysql and mongo were fixed by automatic retries.
  - The redis pull stalled and was killed and retried.
  - `alpine:3.22.2` was pulled by tag for a probe; it has the same digest as the copy already present.
- **Script fixes before the batch.**
  - A missing directory caused an error when writing the relay config.
  - The AMQP driver now declares a durable queue, because RabbitMQ 4 rejects transient non-exclusive queues.

  The redis pilot was reviewed and approved before the other 21 images ran.
- **Sensor gap, 13:53–16:39 UTC.**
  - What happened: telemetry rotated the Falco output file at the 64 MiB limit and recreated it as `porygon:porygon 0640`. Falco (root without capabilities) could no longer write to it, and no process events were stored after 13:54 UTC.
  - Affected runs: 4 images (drupal, ghost, python-3.6, temurin-21) lost their later test windows, and 4 (mongo, golang, nextcloud, mariadb) could not build a baseline.
  - The batch was stopped. With approval:
    - the empty file was removed so Falco recreated it;
    - `PORYGON_FALCO_ROTATE_BYTES` was raised to 10 GiB in `.env` for collection;
    - the 8 affected runs were moved, unchanged, to `raw-invalid/`;
    - those 8 images and wordpress were re-run from 16:40 UTC.

  The rotation code itself is unchanged.

## Batch 2 (held-out images)

Batch 2 is a held-out test set of 22 further images, collected 2026-11-20 to 2026-11-21 under the
**same protocol and with no change to Porygon**: 30 min learning + 30 × 60 s test
windows = 60 min per image. Its purpose is to show whether batch 1's results hold
on images Porygon had never seen. Batch 2 monitored
22.0 hours in total (660 test windows), measured from the
recorded timestamps; the whole dataset now holds
44.0 monitored hours.
Every table carries a `batch` column (`batch1`/`batch2`); batch 1's rows are
unchanged apart from that column.

### Images

- **Services and servers (14):** caddy (`caddy:2`, complete), consul (`hashicorp/consul:latest`, complete), couchdb (`couchdb:3`, complete), gitea (`gitea/gitea:latest`, complete), grafana (`grafana/grafana:latest`, complete), influxdb (`influxdb:2`, complete), mosquitto (`eclipse-mosquitto:2`, complete), nats (`nats:alpine`, complete), nginx (`nginx:1.27`, complete), php83 (`php:8.3-apache`, complete), postgres-16 (`postgres:16`, complete), prometheus (`prom/prometheus:latest`, complete), registry (`registry:2`, complete), valkey (`valkey/valkey:8`, complete).
- **GNU coreutils-single images (4), the batch 1 mysql finding re-tested:** mysql-9 (`mysql:9`, complete), ubi9-httpd (`registry.access.redhat.com/ubi9/httpd-24`, complete), ubi9-nginx (`registry.access.redhat.com/ubi9/nginx-124`, complete), ubi9-python (`registry.access.redhat.com/ubi9/python-312`, complete).
- **Runtimes running a small server (4):** node-20-alpine (`node:20-alpine`, complete), perl (`perl:5.40`, complete), python-3.12-alpine (`python:3.12-alpine`, complete), ruby-3.3-alpine (`ruby:3.3-alpine`, complete).

  The exact start commands, digests and recipes are in `images.csv`.

### Substitutions

None: every one of the 22 primary images was pulled as a native arm64 build and ran.

### Files added by batch 2

| File | Contents |
|---|---|
| `substitutions.csv` | Which primary image was replaced by which reserve, and why |
| `batch2-preflight.json` | Free disk, Docker usage, service health, Falco liveness and the rotation limit before batch 2 started |
| `batch2-plan.json` | Which images batch 2 selected, which it rejected and why |
| `prefetch-batch2.json`, `prefetch-batch2.log` | The arm64 download for batch 2, with digests |
| `batch2-sensor-gaps.json` | Written only if the watchdog detects a Falco sensor gap; this run had none, so the file is absent |
| `archive/batch1-2026-11-21/` | Batch 1's tables and checksums as they were before batch 2, used to prove batch 1 did not change |

Scripts added: `scripts/runtime/run_batch2.sh` (the whole unattended run),
`plan_batch2.py` (substitutions), `watchdog_batch2.py` (the Falco watchdog),
`preflight_batch2.py`, `check_recipe.py` and `verify_batch1_unchanged.py`.
Make targets: `runtime-batch2`, `runtime-check-recipe IMAGE=<key>`, `runtime-verify-batch1`.

## Results: batch 1 against batch 2

| Verdict | Batch | Images | Windows | TP | FP | TN | FN | Recall | Precision | FPR | Hard-neg FPR |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Incident | batch1 | 22 | 660 | 225 | 62 | 334 | 39 | 0.852 | 0.784 | 0.157 | 0.470 |
| Incident | batch2 | 22 | 660 | 206 | 54 | 342 | 58 | 0.780 | 0.792 | 0.136 | 0.409 |
| Incident | combined | 44 | 1320 | 431 | 116 | 676 | 97 | 0.816 | 0.788 | 0.146 | 0.439 |
| Score band | batch1 | 22 | 660 | 108 | 9 | 387 | 156 | 0.409 | 0.923 | 0.023 | 0.045 |
| Score band | batch2 | 22 | 660 | 70 | 3 | 393 | 194 | 0.265 | 0.959 | 0.008 | 0.000 |
| Score band | combined | 44 | 1320 | 178 | 12 | 780 | 350 | 0.337 | 0.937 | 0.015 | n/a |

Per image, per scenario, per kind and per rule figures for both batches, and the
`per_batch` block, are in `summary.json`.

## Coreutils images (batch 2)

Batch 1 found that mysql's GNU coreutils multicall binary hid 10 of its 12
attacks, because Porygon resolves applet names only for busybox and toybox.
Batch 2 re-tests that on four images built the same way. The data decides:

| Image | Tag | Abnormal recall | Multicall events | `coreutils` in the baseline | Falco executable for the attack processes |
|---|---|---:|---:|---|---|
| mysql-9 | `mysql:9` | 0.167 | 379 | yes | `/usr/bin/bash` 520, `/usr/bin/coreutils` 379, `/usr/bin/mysqladmin` 361 |
| ubi9-httpd | `registry.access.redhat.com/ubi9/httpd-24` | 0.167 | 370 | yes | `/usr/bin/bash` 522, `/usr/bin/coreutils` 370, `/usr/bin/curl` 359 |
| ubi9-nginx | `registry.access.redhat.com/ubi9/nginx-124` | 0.833 | 295 | no | `/usr/bin/bash` 519, `/usr/bin/curl` 359, `/usr/bin/coreutils` 295 |
| ubi9-python | `registry.access.redhat.com/ubi9/python-312` | 0.250 | 298 | yes | `/usr/bin/bash` 516, `/usr/bin/curl` 358, `/usr/bin/coreutils` 298 |

- `mysql-9`: 10 of 12 abnormal windows not flagged (RT-AB-DROPPED-SCRIPT, RT-AB-LOW-SLOW, RT-AB-NC-CONNECT, RT-AB-READ-SHADOW, RT-AB-RENAMED-BINARY, RT-AB-ROOT-EXEC, RT-AB-SHELL-RECON, SCN-FLOOD, SCN-LOG4SHELL-SIM, SCN-RUNC-ESCAPE-SIM)
- `ubi9-httpd`: 10 of 12 abnormal windows not flagged (RT-AB-DROPPED-SCRIPT, RT-AB-EGRESS, RT-AB-LOW-SLOW, RT-AB-NC-CONNECT, RT-AB-READ-SHADOW, RT-AB-RENAMED-BINARY, RT-AB-SHELL-RECON, SCN-FLOOD, SCN-LOG4SHELL-SIM, SCN-RUNC-ESCAPE-SIM)
- `ubi9-nginx`: 2 of 12 abnormal windows not flagged (RT-AB-EGRESS, RT-AB-NC-CONNECT)
- `ubi9-python`: 9 of 12 abnormal windows not flagged (RT-AB-DROPPED-SCRIPT, RT-AB-LOW-SLOW, RT-AB-NC-CONNECT, RT-AB-READ-SHADOW, RT-AB-RENAMED-BINARY, RT-AB-SHELL-RECON, SCN-FLOOD, SCN-LOG4SHELL-SIM, SCN-RUNC-ESCAPE-SIM)

The baseline column is what decides the outcome, not the image family. In `mysql-9`, `ubi9-httpd`, `ubi9-python` the multicall binary was already in the baseline's observed executables, so every applet an attack ran resolved to a binary POR-DET-004 had seen before and the rule stayed silent. In `ubi9-nginx` the learning phase never executed it, so the first applet the attacks ran made `/usr/bin/coreutils` itself a previously unseen executable and the rule fired normally. The gap is therefore not 'coreutils images are invisible' but 'an executable that enters the baseline takes every applet reachable through it with it'.

## Incidents during collection (batch 2)

Automatic fixes recorded in `run-log.jsonl` (batch 2 lines), by step: `drivers` 1, `export` 1, `plan` 16, `prefetch` 1, `watchdog` 3.

The sensor watchdog ran throughout and found no gap: every liveness check saw Porygon store the event from a real `docker exec` in the watchdog's own throwaway container, so no run was invalidated.

## Batch 3 (second held-out set)

Batch 3 is a second held-out set of 22 images, collected 2026-11-21 under the
**same protocol, with the same Porygon (detection matcher v5)**: 30 min learning +
30 × 60 s test windows = 60 min per image. No batch 3 image has the same digest
as any batch 1 or batch 2 image. Batch 3 monitored 22.0 hours
(660 test windows), measured from the recorded timestamps; the whole
dataset now holds 66.0 monitored hours. Every table's `batch` column now
takes `batch1`, `batch2` or `batch3`; the batch 1 and batch 2 rows are unchanged.

### Images

adminer (`adminer:latest`, complete), ghost-5-alpine (`ghost:5-alpine`, complete), golang-1.22-alpine (`golang:1.22-alpine`, complete), httpd-alpine (`httpd:2.4-alpine`, complete), influxdb-1 (`influxdb:1.11`, complete), mariadb-11 (`mariadb:11`, complete), memcached-alpine (`memcached:1.6-alpine`, complete), mongo-7 (`mongo:7`, complete), nginx-alpine (`nginx:alpine`, complete), node-18-slim (`node:18-bookworm-slim`, complete), php82-cli (`php:8.2-cli`, complete), postgres-15-alpine (`postgres:15-alpine`, complete), python-3.11-slim (`python:3.11-slim`, complete), rabbitmq-3-mgmt (`rabbitmq:3-management-alpine`, complete), redis-alpine (`redis:7.4-alpine`, complete), temurin-21-alpine (`eclipse-temurin:21-alpine`, complete), tomcat-9 (`tomcat:9-jdk17`, complete), traefik-2 (`traefik:v2.11`, complete), ubi9-nodejs (`registry.access.redhat.com/ubi9/nodejs-20`, complete), ubi9-php (`registry.access.redhat.com/ubi9/php-82`, complete), varnish (`varnish:7`, complete), vault (`hashicorp/vault:latest`, complete).

The exact start commands, digests and recipes are in `images.csv`.

### Same Porygon as batches 1 and 2

24 checks (pre-flight, before every image, and at the end) read the matcher revision from the running backend container: 24 of 24 passed. Revisions seen: `porygon.detection.matcher.v5`; backend image IDs seen: `sha256:83b4854da6dd`. Every check is in `batch3-matcher-checks.jsonl`.

### Substitutions

None: every one of the 22 primary images ran.

### Files added by batch 3

| File | Contents |
|---|---|
| `batch3-preflight.json` | Free disk, Docker usage, service health and Falco liveness before batch 3 |
| `batch3-matcher-checks.jsonl` | The detection matcher revision and backend image, checked before every image |
| `batch3-plan.json` | Which images batch 3 selected or rejected, and why |
| `prefetch-batch3.json`, `prefetch-batch3.log` | The arm64 download for batch 3, with digests |
| `archive/batch1-2-2026-11-21/` | Batches 1 and 2's tables and checksums before batch 3, used to prove they did not change |

## Results: all three batches

| Verdict | Batch | Images | Windows | TP | FP | TN | FN | Recall | Precision | FPR | Hard-neg FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Incident | batch1 | 22 | 660 | 225 | 62 | 334 | 39 | 0.852 | 0.784 | 0.157 | 0.470 |
| Incident | batch2 | 22 | 660 | 206 | 54 | 342 | 58 | 0.780 | 0.792 | 0.136 | 0.409 |
| Incident | batch3 | 22 | 660 | 229 | 58 | 338 | 35 | 0.867 | 0.798 | 0.146 | 0.439 |
| Incident | **combined** | 66 | 1980 | 660 | 174 | 1014 | 132 | 0.833 | 0.791 | 0.146 | 0.439 |
| Score band | batch1 | 22 | 660 | 108 | 9 | 387 | 156 | 0.409 | 0.923 | 0.023 | 0.045 |
| Score band | batch2 | 22 | 660 | 70 | 3 | 393 | 194 | 0.265 | 0.959 | 0.008 | 0.000 |
| Score band | batch3 | 22 | 660 | 62 | 4 | 392 | 202 | 0.235 | 0.939 | 0.010 | 0.015 |
| Score band | **combined** | 66 | 1980 | 240 | 16 | 1172 | 552 | 0.303 | 0.938 | 0.013 | n/a |

## Coreutils images (batch 3)

| Image | Tag | Abnormal recall | `coreutils` events | `coreutils` in the baseline |
|---|---|---:|---:|---|
| ubi9-nodejs | `registry.access.redhat.com/ubi9/nodejs-20` | 0.833 | 295 | no |
| ubi9-php | `registry.access.redhat.com/ubi9/php-82` | 0.250 | 298 | yes |

- `ubi9-nodejs`: 2 of 12 abnormal windows not flagged (RT-AB-EGRESS, RT-AB-NC-CONNECT)
- `ubi9-php`: 9 of 12 abnormal windows not flagged (RT-AB-DROPPED-SCRIPT, RT-AB-LOW-SLOW, RT-AB-NC-CONNECT, RT-AB-READ-SHADOW, RT-AB-RENAMED-BINARY, RT-AB-SHELL-RECON, SCN-FLOOD, SCN-LOG4SHELL-SIM, SCN-RUNC-ESCAPE-SIM)

These are observed results under matcher v5, the same matcher as batches 1 and 2. They are not a test of any later matcher.

## Incidents during collection (batch 3)

Automatic fixes and events recorded in `run-log.jsonl` (batch 3 lines), by step: `recipe` 1, `smoke-test` 1, `watchdog` 1.

The sensor watchdog ran throughout and found no gap, so no batch 3 run was invalidated.

## Limits

- One host, one run per image, and 30 test windows per image. There are no
  repeated runs, so no confidence intervals are given.
- The attacks are scripted simulations run with `docker exec`: harmless
  copies of attacker behaviour, with no exploits, no malware and no internet
  access. They arrive through the container runtime, not through the
  service's network port.
- The ground truth comes from the protocol design. Hard negatives are
  labelled normal even when they look suspicious.
- The load is a defined driver at about 2 operations per second, not real
  users.
- Every baseline contains the shell-form healthcheck (see Findings).
- Images built on a GNU coreutils multicall binary (here only mysql:8.4) are
  under-detected by POR-DET-004. Porygon resolves applet names only for
  busybox and toybox, so mysql's recall reflects this gap in Porygon rather
  than its general detection ability (see Findings).
- Docker Desktop runs a LinuxKit VM, which is not a production kernel.
- The redis pilot and the first 12 images ran before the sensor gap. The other
  9 ran after it, with a raised rotation limit. Porygon's code, rules and
  thresholds were otherwise identical throughout.
- Batch 2 adds 22 held-out images under the identical protocol, so the
  combined figures cover 44 images and 1,320 windows on the same host. The
  two batches were collected on different days; Porygon's code, rules and
  thresholds were identical for both.
- Batch 2's images were never used to choose or tune anything in Porygon,
  which is what makes them held out. They were chosen to fill batch 1's
  gaps (coreutils-single images, busybox/Alpine images, new service types),
  so batch 2 is deliberately not a random sample of container images.
- CouchDB ships no working `weatherreport`, so its `RT-HN-ADMIN` command is the
  documented `_node/_local/_system` admin call made with the image's own `curl`
  rather than a service CLI (recorded in its recipe's `fixes`).
- Batch 3 adds 22 more held-out images under the identical protocol and the same
  detection matcher (v5), checked before every image. Like batch 2, its images were
  chosen to widen coverage, not sampled at random.
