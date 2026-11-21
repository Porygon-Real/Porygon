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
