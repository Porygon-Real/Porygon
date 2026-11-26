"""Preserve every detection run while grouping active workload incident episodes."""

from alembic import op
import sqlalchemy as sa

revision = "incident_episode_grouping"
down_revision = "process_parent_repair_index"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("incidents", sa.Column("grouping_key", sa.String(64), nullable=True))
    op.add_column(
        "incidents", sa.Column("latest_detection_run_id", sa.String(36), nullable=True)
    )
    op.create_foreign_key(
        "fk_incidents_latest_detection_run",
        "incidents",
        "detection_runs",
        ["latest_detection_run_id"],
        ["run_id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "uq_incidents_active_group",
        "incidents",
        ["grouping_key"],
        unique=True,
        postgresql_where=sa.text(
            "grouping_key IS NOT NULL AND status IN ('open','acknowledged')"
        ),
    )
    op.create_table(
        "detection_incident_links",
        sa.Column(
            "detection_run_id",
            sa.String(36),
            sa.ForeignKey("detection_runs.run_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "incident_id",
            sa.String(36),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_detection_incident_links_incident_id",
        "detection_incident_links",
        ["incident_id"],
    )
    op.add_column(
        "response_recommendations",
        sa.Column("evidence_run_id", sa.String(36), nullable=True),
    )
    op.create_foreign_key(
        "fk_response_recommendations_evidence_run",
        "response_recommendations",
        "detection_runs",
        ["evidence_run_id"],
        ["run_id"],
        ondelete="RESTRICT",
    )
    op.drop_constraint("ck_detection_runs_status", "detection_runs", type_="check")
    op.create_check_constraint(
        "ck_detection_runs_status",
        "detection_runs",
        "status IN ('insufficient_data','no_findings','findings_only','incident_created','incident_updated')",
    )


def downgrade():
    # Older readers cannot represent multiple windows per incident. Refuse a
    # destructive downgrade rather than silently orphaning those run mappings.
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM detection_runs WHERE status='incident_updated') THEN
            RAISE EXCEPTION 'Grouped incident history requires this schema; export and resolve it before downgrade';
        END IF;
    END $$""")
    op.drop_constraint("ck_detection_runs_status", "detection_runs", type_="check")
    op.create_check_constraint(
        "ck_detection_runs_status",
        "detection_runs",
        "status IN ('insufficient_data','no_findings','findings_only','incident_created')",
    )
    op.drop_constraint(
        "fk_response_recommendations_evidence_run",
        "response_recommendations",
        type_="foreignkey",
    )
    op.drop_column("response_recommendations", "evidence_run_id")
    op.drop_table("detection_incident_links")
    op.drop_index("uq_incidents_active_group", table_name="incidents")
    op.drop_constraint(
        "fk_incidents_latest_detection_run", "incidents", type_="foreignkey"
    )
    op.drop_column("incidents", "latest_detection_run_id")
    op.drop_column("incidents", "grouping_key")
