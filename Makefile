SHELL := /bin/bash

.PHONY: init config build up down reset logs ps test verify verify-static verify-unit verify-live-safe verify-scanner-live verify-experiment-live verify-response-live experiment-smoke experiment-replay experiment-pilot experiment-validate experiment-confirmatory study review-package review-status review-apply runtime-cleanup runtime-prefetch runtime-venv runtime-up runtime-image runtime-all runtime-build

init:
	@test -f .env || (cp .env.example .env && \
		python3 -c 'from functools import reduce; import os, secrets, sys; from pathlib import Path; p=Path(".env"); socket_gid=0 if sys.platform == "darwin" else os.stat("/var/run/docker.sock").st_gid; replacements={"replace-with-a-long-local-development-password":secrets.token_urlsafe(32),"replace-with-at-least-32-random-characters":secrets.token_urlsafe(48),"replace-with-a-different-32-character-random-token":secrets.token_urlsafe(48),"replace-with-docker-socket-gid":str(socket_gid)}; p.write_text(reduce(lambda value, item: value.replace(*item), replacements.items(), p.read_text(encoding="utf-8")), encoding="utf-8")' && \
		chmod 0600 .env && echo "Created .env with separate local credentials and the Docker socket group ID.")

config:
	docker compose config --quiet

build:
	docker compose build backend collector telemetry responder scanner

up:
	docker compose up --detach --build --wait

ps:
	docker compose ps

logs:
	docker compose logs --follow --tail=100

down:
	docker compose down

reset:
	docker compose down --volumes --remove-orphans

verify:
	./scripts/verify_all.sh all

verify-static:
	./scripts/verify_all.sh static

verify-unit:
	./scripts/verify_all.sh unit

verify-live-safe:
	./scripts/verify_all.sh live-safe

verify-scanner-live:
	./scripts/verify_all.sh scanner-live

# Non-disruptive real-container acceptance: pulls a pinned digest, exercises one
# disposable labelled container, and reconciles its telemetry end to end.
verify-experiment-live:
	./scripts/verify_all.sh experiment-live

# DISRUPTIVE: requires PORYGON_RESPONSE_EXECUTION_MODE=live in .env and may
# pause or stop the disposable containment target. It is never part of `make verify`.
verify-response-live:
	./scripts/verify_containment_response.sh

test: verify-unit

experiment-smoke:
	python3 -m experiments.run smoke

experiment-replay:
	@test -n "$(RUN_DIR)" || (echo "RUN_DIR is required" >&2; exit 2)
	python3 -m experiments.run replay "$(RUN_DIR)"

# Real containers pulled by immutable digest. Pilot evidence only: it may inform
# engineering and variance estimates, never a confirmatory or paper claim.
experiment-pilot:
	python3 -m experiments.run pilot $(PILOT_ARGS)

# One command for the whole pipeline: environment and protocol validation, real
# container collection, split assignment, profile/score/detect, storage accounting,
# and the results page. Resumable; every stage is recorded in a study manifest.
study:
	python3 -m experiments.run study $(STUDY_ARGS)

review-package:
	python3 scripts/review_gate.py prepare

review-status:
	python3 scripts/review_gate.py status

review-apply:
	python3 scripts/review_gate.py apply

experiment-validate:
	@test -n "$(RUN_DIR)" || (echo "RUN_DIR is required" >&2; exit 2)
	python3 experiments/validate_artifacts.py "$(RUN_DIR)"

experiment-confirmatory:
	python3 -m experiments.run confirmatory --protocol "$(or $(PROTOCOL),docs/research/research-protocol.md)"

# Runtime monitoring dataset (see scripts/runtime/). Native arm64 images, each run live
# for one hour through Falco -> Porygon. The responder service stays off.
RUNTIME_SERVICES := postgres backend gateway collector telemetry falco falco-events-init

runtime-cleanup:
	python3 scripts/runtime/cleanup_amd64.py

runtime-prefetch:
	python3 scripts/runtime/prefetch_arm64.py

# pg8000 drives postgres and paho-mqtt is kept available alongside the stdlib MQTT driver.
runtime-venv:
	test -x .venv/bin/python || python3 -m venv .venv
	.venv/bin/python -c 'import pymysql, pymongo, pika, pg8000' 2>/dev/null || \
		.venv/bin/pip install pymysql pymongo pika pg8000 paho-mqtt

runtime-up: runtime-venv
	docker compose up -d --build --wait $(RUNTIME_SERVICES)

runtime-image: runtime-up
	@test -n "$(IMAGE)" || (echo "IMAGE is required, e.g. make runtime-image IMAGE=redis" >&2; exit 2)
	caffeinate -i .venv/bin/python scripts/runtime/run_image.py $(IMAGE)

runtime-all: runtime-up
	caffeinate -i .venv/bin/python scripts/runtime/run_batch.py

runtime-build:
	python3 scripts/runtime/export.py
	python3 scripts/runtime/validate.py
