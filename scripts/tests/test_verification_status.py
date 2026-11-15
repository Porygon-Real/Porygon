"""Exercise aggregate gate status propagation in a disposable script copy."""

import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest

from scripts import verification_receipts


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def test_interrupted_aggregate_keeps_prior_stage_results(tmp_path):
    root = tmp_path / "verification-copy"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "verify_all.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    results = tmp_path / "results.tsv"
    results.write_text("static\tpassed\t3\tmake verify-static\n", encoding="utf-8")

    ledger_path = verification_receipts.write_status(
        run_id="interrupted-fixture",
        results_path=results,
        status="interrupted",
        completed=False,
        root=root,
    )

    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert ledger["status"] == "interrupted"
    assert ledger["completed"] is False
    assert ledger["stages"] == [
        {
            "name": "static",
            "status": "passed",
            "duration_seconds": 3,
            "command": "make verify-static",
        }
    ]
    assert ledger_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("ingestion_status", "detection_status", "expected_children"),
    [(17, 0, ["ingestion"]), (0, 19, ["ingestion", "detection"])],
)
def test_live_safe_aggregate_preserves_child_failures(
    tmp_path, ingestion_status, detection_status, expected_children
):
    root = tmp_path / "verification-copy"
    scripts = root / "scripts"
    children = scripts / "children.log"
    (scripts).mkdir(parents=True)
    (scripts / "verify_all.sh").write_text(
        (SOURCE_ROOT / "scripts/verify_all.sh").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (scripts / "verification_receipts.py").write_text(
        (SOURCE_ROOT / "scripts/verification_receipts.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (scripts / "source_identity.py").write_text(
        (SOURCE_ROOT / "scripts/source_identity.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    ingestion = scripts / "verify_event_ingestion.sh"
    ingestion.write_text(
        "#!/usr/bin/env bash\n"
        f"cat > {shlex.quote(str(root / 'ingestion-stdin'))}\n"
        f"printf '%s\\n' ingestion >> {shlex.quote(str(children))}\n"
        f"exit {ingestion_status}\n",
        encoding="utf-8",
    )
    detection = scripts / "verify_detection_engine.sh"
    detection.write_text(
        "#!/usr/bin/env bash\n"
        f"cat > {shlex.quote(str(root / 'detection-stdin'))}\n"
        f"printf '%s\\n' detection >> {shlex.quote(str(children))}\n"
        f"exit {detection_status}\n",
        encoding="utf-8",
    )
    ingestion.chmod(0o755)
    detection.chmod(0o755)
    private_bin = root / ".venv/bin"
    private_bin.mkdir(parents=True)
    docker = private_bin / "docker"
    docker.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    (root / ".env").write_text(
        "POSTGRES_DB=fixture_db\n"
        "POSTGRES_USER=fixture_user\n"
        "POSTGRES_PASSWORD=fixture-unused-password-0000000000\n"
        "PORYGON_INTERNAL_API_TOKEN=" + "i" * 32 + "\n"
        "PORYGON_OPERATOR_API_TOKEN=" + "o" * 32 + "\n"
        "DOCKER_GID=1000\n"
        "PORYGON_RESPONSE_EXECUTION_MODE=disabled\n",
        encoding="utf-8",
    )

    environment = dict(os.environ)
    environment.pop("PORYGON_VERIFY_BASE_URL", None)
    environment["PORYGON_VERIFY_RUN_ID"] = "20261030t120000z-verify"
    environment["PATH"] = f"{private_bin}:{environment.get('PATH', '')}"
    result = subprocess.run(
        ["bash", str(scripts / "verify_all.sh"), "live-safe"],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        input="aggregate-input-must-not-reach-child\n",
        check=False,
        timeout=15,
    )

    expected_status = ingestion_status or detection_status
    assert result.returncode == expected_status
    assert children.read_text(encoding="utf-8").splitlines() == expected_children
    for child_name in expected_children:
        assert (root / f"{child_name}-stdin").read_bytes() == b""
    manifest = json.loads(
        (root / "artifacts/verification-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "failed"
    live_gate = next(gate for gate in manifest["gates"] if gate["name"] == "live-safe")
    assert live_gate["status"] == "failed"
    ledger = json.loads(
        (root / "artifacts/local/verification-runs/20261030t120000z-verify/stages.json").read_text(
            encoding="utf-8"
        )
    )
    assert ledger["completed"] is True
    assert ledger["status"] == "failed"
    assert ledger["stages"] == [
        {
            "name": "live-safe",
            "status": "failed",
            "duration_seconds": ledger["stages"][0]["duration_seconds"],
            "command": "make verify-live-safe",
        }
    ]
