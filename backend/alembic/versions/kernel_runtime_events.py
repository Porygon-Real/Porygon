"""Add separate typed non-exec kernel evidence without altering legacy streams."""

from alembic import op
import sqlalchemy as sa

revision = "kernel_runtime_events"
down_revision = "incident_episode_grouping"
branch_labels = None
depends_on = None


def upgrade():
    columns = [sa.Column("event_id", sa.String(64), primary_key=True)]
    strings = {
        "sensor_instance_id": 128,
        "sensor_hostname": 255,
        "source": 32,
        "rule_name": 255,
        "priority": 32,
        "event_type": 64,
        "runtime_action": 32,
        "reported_docker_host_id": 128,
        "reported_container_id": 128,
        "docker_host_id": 128,
        "container_id": 128,
        "container_name": 255,
        "image_id": 128,
        "image_digest": 255,
        "correlation_status": 32,
        "process_name": 255,
        "remote_address": 45,
        "local_address": 45,
    }
    required = {
        "sensor_instance_id",
        "source",
        "rule_name",
        "priority",
        "event_type",
        "runtime_action",
        "reported_container_id",
        "correlation_status",
    }
    columns += [
        sa.Column(name, sa.String(size), nullable=name not in required)
        for name, size in strings.items()
    ]
    columns += [
        sa.Column(name, sa.Text(), nullable=True)
        for name in ("image_ref", "executable", "command_line", "file_path", "memory_name")
    ]
    columns += [
        sa.Column(name, sa.BigInteger(), nullable=name in {"event_number", "user_uid"})
        for name in ("time_nano", "event_number", "process_pid", "user_uid", "return_value")
    ]
    columns += [
        sa.Column(name, sa.Integer(), nullable=True) for name in ("remote_port", "local_port")
    ]
    columns += [
        sa.Column(name, sa.DateTime(timezone=True), nullable=False)
        for name in ("occurred_at", "received_at")
    ]
    columns += [
        sa.Column(name, sa.JSON(), nullable=False) for name in ("output_fields", "raw_event")
    ]
    op.create_table(
        "kernel_runtime_events",
        *columns,
        sa.CheckConstraint(
            "runtime_action IN ('net_outbound','memfd_create','file_write_open','file_write')",
            name="ck_kernel_events_action",
        ),
        sa.CheckConstraint(
            "correlation_status IN ('resolved','unresolved','ambiguous')",
            name="ck_kernel_events_correlation",
        ),
    )
    for name, fields in (
        ("host_container_time", ["docker_host_id", "container_id", "time_nano"]),
        ("action_time", ["runtime_action", "occurred_at"]),
        ("image_time", ["image_digest", "occurred_at"]),
    ):
        op.create_index("ix_kernel_events_" + name, "kernel_runtime_events", fields)
    op.create_index(
        "ix_kernel_events_pending_identity",
        "kernel_runtime_events",
        ["received_at"],
        postgresql_where=sa.text("image_id IS NULL OR image_digest IS NULL"),
    )


def downgrade():
    op.execute("""DO $$ BEGIN IF EXISTS (SELECT 1 FROM kernel_runtime_events) THEN
        RAISE EXCEPTION 'Kernel evidence must be explicitly preserved before removing its storage';
        END IF; END $$""")
    op.drop_table("kernel_runtime_events")
