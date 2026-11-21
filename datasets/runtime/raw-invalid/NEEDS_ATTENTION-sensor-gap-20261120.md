# Needs attention (2026-11-20, ~20:30 IST)

## What happened

At **13:53 UTC** Porygon's telemetry service rotated the Falco event file after it reached
`PORYGON_FALCO_ROTATE_BYTES` (64 MiB). The rotation renames the file and recreates it itself
(`telemetry/src/porygon_telemetry/file_source.py:160-161`, `active.touch(mode=0o660)`), so the new
file is owned `porygon:porygon` with mode `0640`. Falco runs as root with all capabilities dropped
and is not in that group, so it cannot write to the new file:

```
falco-1  | 2026-11-20T14:47:58+0000: file: failed to open output file /var/log/porygon/falco-events.jsonl
```

From 13:54 to 14:50 UTC there were **57 minutes with zero process events** in `process_exec_events`
(none before 13:54). Docker runtime events (collector path) kept arriving.

## Effect on the dataset

| Images | State |
|---|---|
| redis (pilot), memcached, httpd, traefik, python:latest, rabbitmq, node:22, php:7.4, ruby, tomcat, python:3.8, mysql, node:16 | complete, unaffected (no event gap before 13:54) |
| drupal, ghost, python:3.6, temurin-21 (round 4) | learning OK; the last 13-16 test windows each were scored with **no process events** (sensor down) |
| mongo, golang, nextcloud, mariadb (round 5) | **failed**: baseline had 0 process events, also after the 10-min extension |
| wordpress | not run |

Nothing was filled in or edited. The affected windows and failed runs are recorded exactly as they happened.

## Already done

- Batch queue stopped; the 4 running images finished (failed) and removed their containers (exact name + label). No runtime containers are left.
- Porygon stack left running and untouched.

## Proposed commands (need your approval)

1. **Restore Falco's output now** (removes the empty 0-byte file so Falco recreates it as root, as at first start):
   ```bash
   docker exec porygon-telemetry-1 sh -c 'test ! -s /var/log/porygon/falco-events.jsonl && rm /var/log/porygon/falco-events.jsonl'
   ```
2. **Stop it happening again during the re-run.** Either:
   - (a) config only, recommended for now: raise the rotation limit to its maximum so it cannot trigger during collection, then restart telemetry
     ```bash
     echo 'PORYGON_FALCO_ROTATE_BYTES=10737418240' >> .env   # replaces the 64 MiB setting
     docker compose up -d --wait telemetry
     ```
   - (b) or fix the rotation code in telemetry (a Porygon code change; better after the dataset).
3. **Keep the affected records, re-run the 9 images.** Move (not delete) the affected raw folders aside and re-run:
   ```bash
   mkdir -p datasets/runtime/raw-invalid
   for k in drupal ghost python-3.6 temurin-21 mongo golang nextcloud mariadb; do mv datasets/runtime/raw/$k datasets/runtime/raw-invalid/$k-sensor-gap-20261120; done
   caffeinate -i .venv/bin/python scripts/runtime/run_batch.py drupal ghost python-3.6 temurin-21 mongo golang nextcloud mariadb wordpress
   ```
   About 3 rounds of ~66 min (~3.3 h). The readme will report the sensor gap and the re-run under "Incidents during collection".
