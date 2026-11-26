"""Credential migration round-trip and data-loss guard use isolated PostgreSQL."""
import os
from pathlib import Path
import subprocess
from uuid import uuid4
import pytest
from sqlalchemy import create_engine, inspect, text


@pytest.mark.skipif(os.environ.get('PORYGON_TEST_POSTGRES')!='1',reason='PostgreSQL required')
def test_credential_migration_preserves_existing_tables_and_refuses_evidence_loss():
    from porygon_api.config import get_settings
    schema='test_credentials_'+uuid4().hex
    admin=create_engine(get_settings().database_url)
    target=create_engine(get_settings().database_url,connect_args={'options':f'-csearch_path={schema}'})
    env=dict(os.environ,PGOPTIONS=f'-csearch_path={schema}')
    def migrate(*args):
        return subprocess.run(['alembic',*args],cwd=Path(__file__).resolve().parents[1],
                              env=env,capture_output=True,text=True)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA {schema}'))
    try:
        assert migrate('upgrade','head','--sql').returncode==0
        assert migrate('upgrade','head').returncode==0
        assert 'api_credentials' in inspect(target).get_table_names()
        assert migrate('downgrade','kernel_runtime_events').returncode==0
        assert 'api_credentials' not in inspect(target).get_table_names()
        assert migrate('upgrade','head').returncode==0
        with target.begin() as connection:
            connection.execute(text("""INSERT INTO api_credentials
                (credential_id,token_sha256,subject,kind,roles,scopes,host_ids,created_at,created_by)
                VALUES ('test',:hash,'human:test','operator','["admin"]','[]','[]',now(),'human:test')"""),
                {'hash':'a'*64})
        assert migrate('downgrade','kernel_runtime_events').returncode!=0
        with target.connect() as connection:
            assert connection.scalar(text('SELECT count(*) FROM api_credentials'))==1
    finally:
        target.dispose()
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA {schema} CASCADE'))
        admin.dispose()
