"""Transactional notification delivery and separate sensor health evidence."""
from alembic import op
import sqlalchemy as sa
revision='operational_delivery'
down_revision='runtime_evidence'
branch_labels=None
depends_on=None


def upgrade():
    op.add_column('incidents',sa.Column('notification_revision',sa.Integer(),nullable=False,server_default='0'))
    op.create_table('notification_deliveries',
        sa.Column('delivery_id',sa.String(36),primary_key=True),sa.Column('delivery_key',sa.String(64),nullable=False),
        sa.Column('incident_id',sa.String(36),sa.ForeignKey('incidents.incident_id',ondelete='RESTRICT'),nullable=False),
        sa.Column('revision',sa.Integer(),nullable=False),sa.Column('destination_id',sa.String(64),nullable=False),
        sa.Column('destination_config_hash',sa.String(64),nullable=False),sa.Column('payload_bytes',sa.Text(),nullable=False),
        sa.Column('state',sa.String(16),nullable=False),sa.Column('generation',sa.Integer(),nullable=False),
        sa.Column('attempts',sa.Integer(),nullable=False),sa.Column('lease_owner',sa.String(128)),
        sa.Column('lease_expires_at',sa.DateTime(timezone=True)),sa.Column('next_retry_at',sa.DateTime(timezone=True)),
        sa.Column('error_category',sa.String(32)),sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('delivered_at',sa.DateTime(timezone=True)),sa.UniqueConstraint('delivery_key',name='uq_notification_delivery_key'))
    op.create_index('ix_notification_delivery_claim','notification_deliveries',['state','next_retry_at','lease_expires_at'])
    op.create_table('sensor_health_samples',sa.Column('sample_id',sa.String(64),primary_key=True),
        sa.Column('docker_host_id',sa.String(128),nullable=False),sa.Column('service_name',sa.String(64),nullable=False),
        sa.Column('instance_id',sa.String(128),nullable=False),sa.Column('counter_epoch',sa.String(128),nullable=False),
        sa.Column('sequence',sa.BigInteger(),nullable=False),sa.Column('observed_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('received_at',sa.DateTime(timezone=True),nullable=False),sa.Column('metrics',sa.JSON(),nullable=False),
        sa.UniqueConstraint('service_name','instance_id','counter_epoch','sequence',name='uq_sensor_health_sequence'))
    op.create_index('ix_sensor_health_host_time','sensor_health_samples',['docker_host_id','observed_at'])


def downgrade():
    op.execute("""DO $$ BEGIN IF EXISTS(SELECT 1 FROM notification_deliveries) OR EXISTS(SELECT 1 FROM sensor_health_samples)
      THEN RAISE EXCEPTION 'Downgrade would remove delivery or coverage evidence'; END IF; END $$""")
    op.drop_table('sensor_health_samples');op.drop_table('notification_deliveries');op.drop_column('incidents','notification_revision')
