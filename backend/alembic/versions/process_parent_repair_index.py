"""Index bounded late-parent repair without locking normal event writes.

Revision ID: process_parent_repair_index
Revises: 0012_custom_rule_lifecycle
"""
from alembic import op
import sqlalchemy as sa

revision = "process_parent_repair_index"
down_revision = "0012_custom_rule_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.create_index(
            "ix_process_exec_events_pending_parent",
            "process_exec_events",
            ["received_at"],
            postgresql_where=sa.text("parent_event_id IS NULL AND container_id IS NOT NULL"),
            postgresql_concurrently=True,
            if_not_exists=True,
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.drop_index(
            "ix_process_exec_events_pending_parent",
            table_name="process_exec_events",
            postgresql_concurrently=True,
            if_exists=True,
        )
