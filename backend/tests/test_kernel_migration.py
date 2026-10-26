"""Full migration chain in an isolated PostgreSQL schema; never production data."""
import os
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text, inspect


@pytest.mark.skipif(os.environ.get("PORYGON_TEST_POSTGRES") != "1", reason="PostgreSQL required")
def test_kernel_migration_roundtrip_and_evidence_preservation():
    from porygon_api.config import get_settings
    schema = "test_kernel_" + uuid4().hex
    admin = create_engine(get_settings().database_url)
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PGOPTIONS=f"-csearch_path={schema}")
    def migrate(*args):
        return subprocess.run(["alembic", *args], cwd=root, env=env, capture_output=True, text=True)
    with admin.begin() as conn:
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    target = create_engine(get_settings().database_url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        assert migrate("upgrade", "head", "--sql").returncode == 0
        assert migrate("upgrade", "head").returncode == 0
        assert "kernel_runtime_events" in inspect(target).get_table_names()
        assert migrate("downgrade", "incident_episode_grouping").returncode == 0
        assert "kernel_runtime_events" not in inspect(target).get_table_names()
        assert migrate("upgrade", "head").returncode == 0
        with target.begin() as conn:
            conn.execute(text("""INSERT INTO kernel_runtime_events
                (event_id,sensor_instance_id,source,rule_name,priority,event_type,runtime_action,
                reported_container_id,correlation_status,time_nano,process_pid,return_value,
                occurred_at,received_at,output_fields,raw_event)
                VALUES (:id,'test','falco','test','Notice','memfd_create','memfd_create',
                'abcdef123456','unresolved',1,1,3,now(),now(),'{}','{}')"""), {"id": "a" * 64})
        assert migrate("downgrade", "incident_episode_grouping").returncode != 0
        with target.connect() as conn:
            assert conn.scalar(text("SELECT count(*) FROM kernel_runtime_events")) == 1
    finally:
        target.dispose()
        with admin.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        admin.dispose()
