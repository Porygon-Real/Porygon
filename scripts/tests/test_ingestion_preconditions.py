import os
from pathlib import Path
import re
import subprocess
import textwrap


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "verify_event_ingestion.sh"


def run_outbox_wait(tmp_path, mode, stage="fixture-stage"):
    source = VERIFIER.read_text(encoding="utf-8")
    functions = re.search(
        r"collector_queue_depth\(\) \{.*?(?=\ncurl --fail --silent --show-error \"\$\{base_url\}/health/live\")",
        source,
        re.DOTALL,
    )
    assert functions, "could not extract the verifier's outbox wait functions"
    post_recovery = source.split(
        'pass "Collector replay did not duplicate stored events"', 1
    )[1].split("docker compose up --detach --no-deps --force-recreate --wait collector", 1)[0]
    assert 'wait_for_empty_outbox "after backend recovery"' in post_recovery

    curl = tmp_path / "curl"
    curl.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json, os
            from datetime import datetime, timedelta, timezone
            count_path = os.environ['CURL_COUNT_PATH']
            try:
                count = int(open(count_path, encoding='utf-8').read())
            except FileNotFoundError:
                count = 0
            open(count_path, 'w', encoding='utf-8').write(str(count + 1))
            mode = os.environ['CURL_MODE']
            if mode == 'traffic_after_zero':
                depth = 0 if count == 0 else 17
                observed = datetime.now(timezone.utc)
            elif mode == 'stale_zero':
                depth = 0
                observed = datetime.now(timezone.utc) - timedelta(seconds=60)
            else:
                depth = 0
                observed = datetime.now(timezone.utc) - timedelta(seconds=2)
            print(json.dumps([{
                'service_name': 'collector',
                'instance_id': 'fixture-instance',
                'docker_host_id': 'fixture-host',
                'status': 'healthy',
                'last_seen_at': observed.isoformat(),
                'service_metadata': {'capability': 'event-ingestion', 'queue_depth': depth},
            }]))
            """
        ),
        encoding="utf-8",
    )
    curl.chmod(0o700)
    harness = tmp_path / "wait.sh"
    harness.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "base_url=http://fixture",
                "collector_host_id=fixture-host",
                "collector_instance_id=fixture-instance",
                "heartbeat_interval=2",
                "outbox_drain_timeout=1",
                "pass() { :; }",
                "fail() { exit 41; }",
                "sleep() { :; }",
                functions.group(0),
                f'wait_for_empty_outbox "{stage}"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    harness.chmod(0o700)
    env = os.environ.copy()
    env.update(
        PATH=f"{tmp_path}:{env['PATH']}",
        CURL_COUNT_PATH=str(tmp_path / "curl-count"),
        CURL_MODE=mode,
    )
    return subprocess.run(
        ["bash", str(harness)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


def test_fresh_zero_snapshot_is_accepted_even_if_traffic_resumes(tmp_path):
    result = run_outbox_wait(tmp_path, "traffic_after_zero", "after backend recovery")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "curl-count").read_text(encoding="utf-8") == "1"


def test_stale_or_pre_wait_zero_snapshot_is_rejected(tmp_path):
    stale_dir = tmp_path / "stale"
    stale_dir.mkdir()
    stale = run_outbox_wait(stale_dir, "stale_zero")
    assert stale.returncode == 41

    before_wait_dir = tmp_path / "before-wait"
    before_wait_dir.mkdir()
    before_wait = run_outbox_wait(before_wait_dir, "before_wait_zero")
    assert before_wait.returncode == 41
