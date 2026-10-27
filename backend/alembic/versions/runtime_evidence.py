"""Observed process provenance and immutable evidence/model artifacts."""
from alembic import op
import sqlalchemy as sa
revision='runtime_evidence'
down_revision='continuous_assessment'
branch_labels=None
depends_on=None


def upgrade():
    op.alter_column("incidents","anomaly_score",existing_type=sa.Float(),nullable=True)
    op.add_column("process_exec_events",sa.Column("exec_return_value",sa.BigInteger(),nullable=True))
    op.add_column("process_exec_events",sa.Column("event_direction",sa.String(1),nullable=True))
    for table in ('process_exec_events','kernel_runtime_events'):
        for name,kind in [('sensor_epoch',sa.String(128)),('process_start_ns',sa.BigInteger()),
            ('parent_start_ns',sa.BigInteger()),('pid_namespace_start_ns',sa.BigInteger()),
            ('exe_from_memfd',sa.Boolean()),('exe_writable',sa.Boolean())]:
            op.add_column(table,sa.Column(name,kind,nullable=True))
    op.create_table('runtime_evidence_bundles',
        sa.Column('bundle_hash',sa.String(64),primary_key=True),
        sa.Column('score_id',sa.String(36),sa.ForeignKey('anomaly_scores.score_id',ondelete='RESTRICT'),nullable=False),
        sa.Column('contract',sa.String(64),nullable=False),sa.Column('rules_hash',sa.String(64),nullable=False),
        sa.Column('document',sa.JSON(),nullable=False),sa.Column('feature_document',sa.JSON(),nullable=False),
        sa.Column('model_prediction',sa.JSON(),nullable=False),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False))
    op.create_table('advisory_models',sa.Column('artifact_hash',sa.String(64),primary_key=True),
        sa.Column('artifact',sa.JSON(),nullable=False),sa.Column('approved_by',sa.String(128),nullable=False),
        sa.Column('evaluation_reference',sa.String(255),nullable=False),sa.Column('active',sa.Boolean(),nullable=False),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False))

    op.create_table('model_quality_locks',
        sa.Column('artifact_hash',sa.String(64),sa.ForeignKey('advisory_models.artifact_hash',ondelete='RESTRICT'),primary_key=True),
        sa.Column('criteria_hash',sa.String(64),nullable=False),sa.Column('criteria',sa.JSON(),nullable=False),
        sa.Column('locked_by',sa.String(128),nullable=False),sa.Column('locked_at',sa.DateTime(timezone=True),nullable=False))


def downgrade():
    op.execute("""DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM incidents WHERE anomaly_score IS NULL) THEN RAISE EXCEPTION 'Unavailable incident distances cannot be fabricated'; END IF;
    IF EXISTS(SELECT 1 FROM runtime_evidence_bundles) OR EXISTS(SELECT 1 FROM advisory_models)
      OR EXISTS(SELECT 1 FROM process_exec_events WHERE sensor_epoch IS NOT NULL OR process_start_ns IS NOT NULL)
      OR EXISTS(SELECT 1 FROM kernel_runtime_events WHERE sensor_epoch IS NOT NULL OR process_start_ns IS NOT NULL)
    THEN RAISE EXCEPTION 'Downgrade would remove observed provenance evidence'; END IF; END $$""")
    op.alter_column("incidents","anomaly_score",existing_type=sa.Float(),nullable=False)
    op.drop_column("process_exec_events","exec_return_value")
    op.drop_column("process_exec_events","event_direction")
    op.drop_table('model_quality_locks')
    op.drop_table('advisory_models');op.drop_table('runtime_evidence_bundles')
    for table in ('process_exec_events','kernel_runtime_events'):
        for field in ('sensor_epoch','process_start_ns','parent_start_ns','pid_namespace_start_ns','exe_from_memfd','exe_writable'):
            op.drop_column(table,field)
