"""Enroll revocable credentials and freeze response host identities."""
from alembic import op
import sqlalchemy as sa

revision = 'enrolled_credentials'
down_revision = 'kernel_runtime_events'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('api_credentials',
        sa.Column('credential_id', sa.String(36), primary_key=True),
        sa.Column('token_sha256', sa.String(64), nullable=False),
        sa.Column('subject', sa.String(128), nullable=False),
        sa.Column('kind', sa.String(16), nullable=False),
        sa.Column('roles', sa.JSON(), nullable=False),
        sa.Column('scopes', sa.JSON(), nullable=False),
        sa.Column('host_ids', sa.JSON(), nullable=False),
        sa.Column('service_name', sa.String(64), nullable=True),
        sa.Column('instance_id', sa.String(128), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by', sa.String(128), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by', sa.String(128), nullable=True),
        sa.Column('replaces_credential_id', sa.String(36), nullable=True),
        sa.UniqueConstraint('token_sha256', name='uq_api_credentials_token_sha256'),
        sa.UniqueConstraint('replaces_credential_id', name='uq_api_credentials_replacement'),
        sa.CheckConstraint("kind IN ('operator','service')", name='ck_api_credentials_kind'))
    op.create_index('ix_api_credentials_subject', 'api_credentials', ['subject'])
    for table in ('response_recommendations', 'response_executions'):
        op.add_column(table, sa.Column('target_docker_host_id', sa.String(128), nullable=True))


def downgrade():
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM api_credentials)
          OR EXISTS (SELECT 1 FROM response_recommendations WHERE target_docker_host_id IS NOT NULL)
          OR EXISTS (SELECT 1 FROM response_executions WHERE target_docker_host_id IS NOT NULL)
        THEN RAISE EXCEPTION 'Downgrade would remove credential or response identity evidence'; END IF;
        END $$""")
    for table in ('response_executions', 'response_recommendations'):
        op.drop_column(table, 'target_docker_host_id')
    op.drop_table('api_credentials')
