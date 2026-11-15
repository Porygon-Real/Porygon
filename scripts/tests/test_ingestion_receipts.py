"""Exercise durable ingestion receipt binding without Docker or live services."""

import json
import shutil
import subprocess
import sys

import pytest

from scripts import verification_receipts as receipts


SATURATION = {
    "configured_event_limit": 100,
    "observed_outbox_count": 100,
    "current_run_canary_count": 24,
    "overflow_before": 8,
    "overflow_after": 17,
    "overflow_delta": 9,
    "docker_api_event_count": 131,
    "requested_exec_operations": 40,
    "initial_queue_depth": 0,
}
PERSISTENCE = {
    "api_event_count": 131,
    "postgres_row_count": 131,
    "replay_count_before": 131,
    "replay_count_after": 131,
    "replay_row_growth": 0,
    "final_queue_depth": 0,
    "final_queue_observed_at_ns": 1_900_000_000_000_000_000,
}
RUN_ID = "20261030t120000z-42"
HOST_ID = "fixture-docker-host"
NOW = 1_900_000_000


@pytest.fixture
def receipt_root(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "verify_event_ingestion.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (root / "artifacts/local").mkdir(parents=True)
    monkeypatch.setattr(
        receipts,
        "source_identity",
        lambda _: {"commit": "a" * 40, "tree_sha256": "b" * 64},
    )
    return root


def write_stage(root, stage, values, now=NOW):
    return receipts.write_receipt(
        stage=stage,
        run_id=RUN_ID,
        host_id=HOST_ID,
        directory=root / "artifacts/local" / f"ingest-{RUN_ID}",
        values=values,
        root=root,
        now_epoch=now,
    )


def validate(root, **kwargs):
    now_epoch = kwargs.pop("now_epoch", NOW)
    return receipts.validate_receipts(
        run_id=RUN_ID,
        host_id=HOST_ID,
        directory=root / "artifacts/local" / f"ingest-{RUN_ID}",
        root=root,
        now_epoch=now_epoch,
        **kwargs,
    )


def test_saturation_receipt_survives_interrupted_final_stage(receipt_root):
    scripts = receipt_root / "scripts"
    for name in ("verification_receipts.py", "source_identity.py"):
        shutil.copy2(receipts.ROOT / "scripts" / name, scripts / name)
    write_args = [
        "write",
        "--stage",
        "saturation",
        "--run-id",
        RUN_ID,
        "--host-id",
        HOST_ID,
        "--directory",
        f"artifacts/local/ingest-{RUN_ID}",
    ]
    for key, value in SATURATION.items():
        write_args.extend(("--field", f"{key}={value}"))
    code = (
        "from pathlib import Path\n"
        "import sys\n"
        "from scripts import verification_receipts as r\n"
        "r.ROOT = Path('.').resolve()\n"
        "r.source_identity = lambda _: {'commit': 'a'*40, 'tree_sha256': 'b'*64}\n"
        f"status = r.main({write_args!r})\n"
        "sys.exit(23 if status == 0 else status)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=receipt_root,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 23
    path = receipt_root / "artifacts/local" / f"ingest-{RUN_ID}" / "saturation.json"
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    validate_code = (
        "from pathlib import Path\n"
        "import sys\n"
        "from scripts import verification_receipts as r\n"
        "r.ROOT = Path('.').resolve()\n"
        "r.source_identity = lambda _: {'commit': 'a'*40, 'tree_sha256': 'b'*64}\n"
        f"sys.exit(r.main(['validate', '--run-id', {RUN_ID!r}, '--host-id', {HOST_ID!r}, "
        f"'--directory', 'artifacts/local/ingest-{RUN_ID}']))\n"
    )
    rejected = subprocess.run(
        [sys.executable, "-c", validate_code],
        cwd=receipt_root,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert rejected.returncode == 1


def test_complete_receipts_validate_as_one_run(receipt_root):
    write_stage(receipt_root, "saturation", SATURATION)
    write_stage(receipt_root, "persistence", PERSISTENCE, now=NOW + 1)

    saturation, persistence = validate(receipt_root, now_epoch=NOW + 1)

    assert saturation["run_id"] == persistence["run_id"] == RUN_ID
    assert saturation["source_tree_sha256"] == persistence["source_tree_sha256"]


def test_missing_empty_mismatched_and_stale_receipts_fail_closed(receipt_root):
    write_stage(receipt_root, "saturation", SATURATION)
    persistence_path = write_stage(receipt_root, "persistence", PERSISTENCE)
    assert validate(receipt_root)

    with pytest.raises(ValueError, match="binding mismatch"):
        receipts.validate_receipts(
            run_id=RUN_ID,
            host_id="different-host",
            directory=receipt_root / "artifacts/local" / f"ingest-{RUN_ID}",
            root=receipt_root,
            now_epoch=NOW,
        )
    with pytest.raises(ValueError, match="stale"):
        receipts.validate_receipts(
            run_id=RUN_ID,
            host_id=HOST_ID,
            directory=receipt_root / "artifacts/local" / f"ingest-{RUN_ID}",
            root=receipt_root,
            now_epoch=NOW + receipts.MAX_AGE_SECONDS + 1,
        )

    document = json.loads(persistence_path.read_text(encoding="utf-8"))
    document["created_at_epoch"] = float("nan")
    persistence_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="timestamp"):
        validate(receipt_root)

    persistence_path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        validate(receipt_root)


def test_receipt_rejects_inconsistent_persistence_counts(receipt_root):
    write_stage(receipt_root, "saturation", SATURATION)
    inconsistent = dict(PERSISTENCE, postgres_row_count=130)
    with pytest.raises(ValueError, match="persistence evidence"):
        write_stage(receipt_root, "persistence", inconsistent)


@pytest.mark.parametrize(
    "overrides",
    [
        {"replay_count_before": 130, "replay_count_after": 130},
        {"current_run_canary_count": 101},
    ],
)
def test_receipt_rejects_inconsistent_replay_or_canary_counts(receipt_root, overrides):
    if "current_run_canary_count" in overrides:
        invalid = dict(SATURATION, **overrides)
        with pytest.raises(ValueError, match="saturation evidence"):
            write_stage(receipt_root, "saturation", invalid)
    else:
        write_stage(receipt_root, "saturation", SATURATION)
        invalid = dict(PERSISTENCE, **overrides)
        with pytest.raises(ValueError, match="persistence evidence"):
            write_stage(receipt_root, "persistence", invalid)


def test_cross_stage_api_count_must_match_saturation_identity(receipt_root):
    write_stage(receipt_root, "saturation", SATURATION)
    write_stage(
        receipt_root,
        "persistence",
        dict(PERSISTENCE, api_event_count=130, postgres_row_count=130,
             replay_count_before=130, replay_count_after=130),
        now=NOW + 1,
    )

    with pytest.raises(ValueError, match="stages are inconsistent"):
        validate(receipt_root, now_epoch=NOW + 1)


def test_receipt_rejects_verifier_source_drift(receipt_root):
    write_stage(receipt_root, "saturation", SATURATION)
    write_stage(receipt_root, "persistence", PERSISTENCE, now=NOW + 1)
    verifier = receipt_root / "scripts" / "verify_event_ingestion.sh"
    verifier.write_text("#!/usr/bin/env bash\n# changed after capture\n", encoding="utf-8")

    with pytest.raises(ValueError, match="binding mismatch"):
        validate(receipt_root)


def test_receipt_does_not_replace_existing_run_stage(receipt_root):
    path = write_stage(receipt_root, "saturation", SATURATION)
    original = path.read_bytes()

    with pytest.raises(FileExistsError):
        write_stage(receipt_root, "saturation", SATURATION)

    assert path.read_bytes() == original
