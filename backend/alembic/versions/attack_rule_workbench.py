"""Add immutable custom-rule revisions, lifecycle evidence and run snapshots.

Revision ID: attack_rule_workbench
Revises: model_promotion_review
"""

from alembic import op
import sqlalchemy as sa


revision = "attack_rule_workbench"
down_revision = "model_promotion_review"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_detection_runs_status", "detection_runs", type_="check")
    op.create_check_constraint(
        "ck_detection_runs_status",
        "detection_runs",
        "status IN ('insufficient_data', 'no_findings', 'findings_only', 'incident_created', "
        "'incident_updated', 'budget_exhausted', 'rule_evidence_incomplete', 'rule_error')",
    )
    op.drop_constraint("ck_custom_detection_rules_target", "custom_detection_rules", type_="check")
    op.create_check_constraint(
        "ck_custom_detection_rules_target",
        "custom_detection_rules",
        "target IN ('process', 'runtime', 'kernel')",
    )
    op.add_column(
        "custom_detection_rules",
        sa.Column("lifecycle_state", sa.String(length=24), nullable=False, server_default="draft"),
    )
    op.add_column(
        "custom_detection_rules",
        sa.Column("current_revision_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "custom_detection_rules",
        sa.Column("active_revision_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "custom_detection_rules",
        sa.Column("candidate_state", sa.String(length=16), nullable=False, server_default="none"),
    )
    op.execute(
        "UPDATE custom_detection_rules SET lifecycle_state = "
        "CASE WHEN enabled THEN 'legacy_active' ELSE 'disabled' END"
    )
    op.drop_index("uq_custom_detection_rules_slug_enabled", table_name="custom_detection_rules")
    op.create_index(
        "uq_custom_detection_rules_slug_live",
        "custom_detection_rules",
        ["slug"], unique=True,
        postgresql_where=sa.text("lifecycle_state <> 'disabled'"),
        sqlite_where=sa.text("lifecycle_state <> 'disabled'"),
    )
    op.create_check_constraint(
        "ck_custom_detection_rules_lifecycle_state",
        "custom_detection_rules",
        "lifecycle_state IN ('legacy_active', 'draft', 'shadow', 'active', 'disabled')",
    )
    op.create_check_constraint(
        "ck_custom_detection_rules_candidate_state",
        "custom_detection_rules",
        "candidate_state IN ('draft', 'shadow', 'none')",
    )
    op.create_index(
        "ix_custom_detection_rules_lifecycle_state",
        "custom_detection_rules",
        ["lifecycle_state"],
    )
    op.create_index(
        "ix_process_exec_lifetime_context",
        "process_exec_events",
        ["docker_host_id", "container_id", "sensor_instance_id", "sensor_epoch",
         "pid_namespace_start_ns", "process_pid", "process_start_ns", "time_nano", "event_id"],
        postgresql_where=sa.text(
            "correlation_status = 'resolved' AND exec_return_value = 0 AND event_direction = '<'"
        ),
    )

    op.create_table(
        "custom_detection_rule_revisions",
        sa.Column("revision_hash", sa.String(length=64), primary_key=True),
        sa.Column(
            "custom_rule_id",
            sa.String(length=36),
            sa.ForeignKey("custom_detection_rules.custom_rule_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_foreign_key(
        "fk_custom_detection_rules_active_revision",
        "custom_detection_rules", "custom_detection_rule_revisions",
        ["active_revision_hash"], ["revision_hash"], ondelete="RESTRICT",
    )
    op.create_index(
        "ix_custom_detection_rule_revisions_rule",
        "custom_detection_rule_revisions",
        ["custom_rule_id", "created_at"],
    )

    op.create_table(
        "custom_detection_rule_receipts",
        sa.Column("receipt_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "custom_rule_id",
            sa.String(length=36),
            sa.ForeignKey("custom_detection_rules.custom_rule_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("revision_hash", sa.String(length=64),
                  sa.ForeignKey("custom_detection_rule_revisions.revision_hash", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("interpreter_hash", sa.String(length=64), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("receipt_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('preview', 'shadow')", name="ck_custom_rule_receipt_kind"),
    )
    op.create_index(
        "ix_custom_detection_rule_receipts_rule",
        "custom_detection_rule_receipts",
        ["custom_rule_id", "created_at"],
    )
    op.create_index(
        "ix_custom_detection_rule_receipts_revision",
        "custom_detection_rule_receipts",
        ["revision_hash", "kind", "created_at"],
    )

    op.create_table(
        "custom_detection_rule_audit",
        sa.Column("audit_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "custom_rule_id",
            sa.String(length=36),
            sa.ForeignKey("custom_detection_rules.custom_rule_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("revision_hash", sa.String(length=64),
                  sa.ForeignKey("custom_detection_rule_revisions.revision_hash", ondelete="RESTRICT"),
                  nullable=True),
        sa.Column("action", sa.String(length=24), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("reference", sa.String(length=255), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_custom_detection_rule_audit_rule",
        "custom_detection_rule_audit",
        ["custom_rule_id", "created_at"],
    )

    op.add_column(
        "detection_runs",
        sa.Column("custom_rule_snapshot", sa.JSON(), nullable=True),
    )
    op.add_column(
        "detection_runs",
        sa.Column("custom_rule_interpreter_hash", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    if op.get_context().as_sql:
        op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM custom_detection_rule_revisions)
           OR EXISTS (SELECT 1 FROM custom_detection_rule_receipts)
           OR EXISTS (SELECT 1 FROM custom_detection_rule_audit)
        THEN RAISE EXCEPTION 'Downgrade would erase custom rule provenance'; END IF;
        IF EXISTS (SELECT 1 FROM custom_detection_rules WHERE target = 'kernel')
        THEN RAISE EXCEPTION 'Downgrade would remove the kernel custom-rule target'; END IF;
        IF EXISTS (SELECT 1 FROM detection_runs WHERE status IN ('budget_exhausted', 'rule_evidence_incomplete', 'rule_error')
                   OR custom_rule_snapshot IS NOT NULL OR custom_rule_interpreter_hash IS NOT NULL)
        THEN RAISE EXCEPTION 'Downgrade would remove rule-evaluation status or run snapshots'; END IF;
        END; $$""")
    else:
        bind = op.get_bind()
        provenance_rows = bind.execute(sa.text(
            "SELECT (SELECT count(*) FROM custom_detection_rule_revisions) + "
            "(SELECT count(*) FROM custom_detection_rule_receipts) + "
            "(SELECT count(*) FROM custom_detection_rule_audit)"
        )).scalar_one()
        if provenance_rows:
            raise RuntimeError("Downgrade would erase custom rule provenance")
        kernel_rules = bind.execute(sa.text(
            "SELECT count(*) FROM custom_detection_rules WHERE target = 'kernel'"
        )).scalar_one()
        if kernel_rules:
            raise RuntimeError("Downgrade would remove the kernel custom-rule target")
        new_run_rows = bind.execute(sa.text(
            "SELECT count(*) FROM detection_runs WHERE status IN "
            "('budget_exhausted', 'rule_evidence_incomplete', 'rule_error') "
            "OR custom_rule_snapshot IS NOT NULL OR custom_rule_interpreter_hash IS NOT NULL"
        )).scalar_one()
        if new_run_rows:
            raise RuntimeError("Downgrade would remove rule-evaluation status or run snapshots")
    op.drop_constraint("ck_detection_runs_status", "detection_runs", type_="check")
    op.create_check_constraint(
        "ck_detection_runs_status", "detection_runs",
        "status IN ('insufficient_data', 'no_findings', 'findings_only', 'incident_created', 'incident_updated')",
    )
    op.drop_column("detection_runs", "custom_rule_interpreter_hash")
    op.drop_column("detection_runs", "custom_rule_snapshot")
    op.drop_index("ix_process_exec_lifetime_context", table_name="process_exec_events")
    op.drop_index("ix_custom_detection_rule_audit_rule", table_name="custom_detection_rule_audit")
    op.drop_table("custom_detection_rule_audit")
    op.drop_index("ix_custom_detection_rule_receipts_revision", table_name="custom_detection_rule_receipts")
    op.drop_index("ix_custom_detection_rule_receipts_rule", table_name="custom_detection_rule_receipts")
    op.drop_table("custom_detection_rule_receipts")
    op.drop_index("ix_custom_detection_rule_revisions_rule", table_name="custom_detection_rule_revisions")
    op.drop_index("ix_custom_detection_rules_lifecycle_state", table_name="custom_detection_rules")
    op.drop_constraint(
        "ck_custom_detection_rules_lifecycle_state", "custom_detection_rules", type_="check"
    )
    op.drop_index("uq_custom_detection_rules_slug_live", table_name="custom_detection_rules")
    op.drop_constraint(
        "fk_custom_detection_rules_active_revision", "custom_detection_rules", type_="foreignkey"
    )
    op.drop_constraint(
        "ck_custom_detection_rules_candidate_state", "custom_detection_rules", type_="check"
    )
    op.drop_column("custom_detection_rules", "candidate_state")
    op.drop_column("custom_detection_rules", "active_revision_hash")
    op.drop_table("custom_detection_rule_revisions")
    op.drop_column("custom_detection_rules", "current_revision_hash")
    op.drop_column("custom_detection_rules", "lifecycle_state")
    op.create_index(
        "uq_custom_detection_rules_slug_enabled", "custom_detection_rules", ["slug"],
        unique=True, postgresql_where=sa.text("enabled"), sqlite_where=sa.text("enabled"),
    )
    op.drop_constraint("ck_custom_detection_rules_target", "custom_detection_rules", type_="check")
    op.create_check_constraint(
        "ck_custom_detection_rules_target", "custom_detection_rules",
        "target IN ('process', 'runtime')",
    )
