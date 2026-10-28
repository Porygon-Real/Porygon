"""Partition operational identities by the authenticated assigned Docker host."""
from alembic import op
import sqlalchemy as sa
revision = 'host_health_identity'
down_revision = 'operational_delivery'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('service_heartbeats', sa.Column('docker_host_id', sa.String(128), nullable=False, server_default='unknown'))
    # Legacy metadata is not authenticated historical evidence; leave it unknown.
    op.drop_constraint('uq_service_heartbeat_identity', 'service_heartbeats', type_='unique')
    op.create_unique_constraint('uq_service_heartbeat_host_identity', 'service_heartbeats', ['docker_host_id', 'service_name', 'instance_id'])
    op.drop_constraint('uq_sensor_health_sequence', 'sensor_health_samples', type_='unique')
    op.create_unique_constraint('uq_sensor_health_host_sequence', 'sensor_health_samples', ['docker_host_id', 'service_name', 'instance_id', 'counter_epoch', 'sequence'])


def downgrade():
    op.execute("""DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM service_heartbeats GROUP BY service_name, instance_id HAVING count(*) > 1)
       OR EXISTS (SELECT 1 FROM sensor_health_samples GROUP BY service_name, instance_id, counter_epoch, sequence HAVING count(*) > 1)
    THEN RAISE EXCEPTION 'Downgrade would collapse independent host evidence'; END IF;
    END $$""")
    op.drop_constraint('uq_sensor_health_host_sequence', 'sensor_health_samples', type_='unique')
    op.create_unique_constraint('uq_sensor_health_sequence', 'sensor_health_samples', ['service_name', 'instance_id', 'counter_epoch', 'sequence'])
    op.drop_constraint('uq_service_heartbeat_host_identity', 'service_heartbeats', type_='unique')
    op.create_unique_constraint('uq_service_heartbeat_identity', 'service_heartbeats', ['service_name', 'instance_id'])
    op.drop_column('service_heartbeats', 'docker_host_id')
