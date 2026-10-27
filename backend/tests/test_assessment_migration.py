"""Assessment schema upgrades offline and refuses destructive evidence removal."""

import os
from pathlib import Path
import subprocess
from uuid import uuid4
import pytest
from sqlalchemy import create_engine, inspect, text


@pytest.mark.skipif(
    os.environ.get("PORYGON_TEST_POSTGRES") != "1", reason="PostgreSQL required"
)
def test_assessment_migration_roundtrip_and_target_preservation():
    from porygon_api.config import get_settings

    schema = "test_assessments_" + uuid4().hex
    admin = create_engine(get_settings().database_url)
    target = create_engine(
        get_settings().database_url, connect_args={"options": f"-csearch_path={schema}"}
    )
    env = dict(os.environ, PGOPTIONS=f"-csearch_path={schema}")

    def migrate(*args):
        return subprocess.run(
            ["alembic", *args],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
        )

    with admin.begin() as connection:
        connection.execute(text(f"CREATE SCHEMA {schema}"))
    try:
        assert migrate("upgrade", "head", "--sql").returncode == 0
        assert migrate("upgrade", "head").returncode == 0
        assert "assessment_jobs" in inspect(target).get_table_names()
        assert migrate("downgrade", "enrolled_credentials").returncode == 0
        assert migrate("upgrade", "head").returncode == 0
        with target.begin() as connection:
            connection.execute(
                text("""INSERT INTO assessment_targets
                (target_id,docker_host_id,container_id,image_digest,context_hash,context_manifest,window_seconds,
                 next_window_start,allowed_lateness_seconds,enabled,coverage_state,created_by,created_at)
                VALUES ('target','host',:cid,'example@sha256:'||:digest,:digest,'{}',30,now(),10,true,'unprofiled','test',now())"""),
                {"cid": "a" * 64, "digest": "b" * 64},
            )
        assert migrate("downgrade", "enrolled_credentials").returncode != 0
        with target.connect() as connection:
            assert (
                connection.scalar(text("SELECT count(*) FROM assessment_targets")) == 1
            )
    finally:
        target.dispose()
        with admin.begin() as connection:
            connection.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        admin.dispose()
