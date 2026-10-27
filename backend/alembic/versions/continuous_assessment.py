"""Durable scoped assessment scheduling and explicit profile approvals."""

from alembic import op
import sqlalchemy as sa

revision = "continuous_assessment"
down_revision = "enrolled_credentials"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "anomaly_scores", sa.Column("assessment_scope", sa.JSON(), nullable=True)
    )
    op.create_table(
        "assessment_targets",
        sa.Column("target_id", sa.String(36), primary_key=True),
        sa.Column("docker_host_id", sa.String(128), nullable=False),
        sa.Column("container_id", sa.String(64), nullable=False),
        sa.Column("image_digest", sa.String(255), nullable=False),
        sa.Column("context_hash", sa.String(64), nullable=False),
        sa.Column("context_manifest", sa.JSON, nullable=False),
        sa.Column("window_seconds", sa.Integer, nullable=False),
        sa.Column("next_window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("allowed_lateness_seconds", sa.Integer, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("active_profile_id", sa.String(36), nullable=True),
        sa.Column("coverage_state", sa.String(32), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "docker_host_id",
            "container_id",
            "image_digest",
            "context_hash",
            name="uq_assessment_target_scope",
        ),
    )
    op.create_table(
        "managed_profiles",
        sa.Column("enrollment_id", sa.String(36), primary_key=True),
        sa.Column(
            "target_id",
            sa.String(36),
            sa.ForeignKey("assessment_targets.target_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "profile_id",
            sa.String(36),
            sa.ForeignKey("behavior_profiles.profile_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("artifact_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("provenance", sa.JSON, nullable=False),
        sa.Column("shadow_result", sa.JSON, nullable=True),
        sa.Column("proposed_by", sa.String(128), nullable=False),
        sa.Column("approved_by", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "target_id", "artifact_hash", name="uq_managed_profile_artifact"
        ),
    )
    op.create_table(
        "assessment_jobs",
        sa.Column("job_id", sa.String(36), primary_key=True),
        sa.Column("assessment_key", sa.String(64), nullable=False),
        sa.Column(
            "target_id",
            sa.String(36),
            sa.ForeignKey("assessment_targets.target_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "profile_enrollment_id",
            sa.String(36),
            sa.ForeignKey("managed_profiles.enrollment_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("config_hash", sa.String(64), nullable=False),
        sa.Column("config_manifest", sa.JSON, nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("generation", sa.Integer, nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("lease_owner", sa.String(128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "score_id",
            sa.String(36),
            sa.ForeignKey("anomaly_scores.score_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "detection_run_id",
            sa.String(36),
            sa.ForeignKey("detection_runs.run_id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("coverage", sa.JSON, nullable=False),
        sa.Column("error_category", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("assessment_key", name="uq_assessment_job_key"),
    )
    op.create_table(
        "assessment_audits",
        sa.Column("audit_id", sa.String(36), primary_key=True),
        sa.Column("audit_key", sa.String(64), unique=True, nullable=False),
        sa.Column(
            "target_id",
            sa.String(36),
            sa.ForeignKey("assessment_targets.target_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_assessment_job_claim",
        "assessment_jobs",
        ["state", "next_retry_at", "lease_expires_at"],
    )


def downgrade():
    op.execute("""DO $$ BEGIN
        IF EXISTS (SELECT 1 FROM assessment_jobs) OR EXISTS (SELECT 1 FROM assessment_targets)
           OR EXISTS (SELECT 1 FROM anomaly_scores WHERE assessment_scope IS NOT NULL)
        THEN RAISE EXCEPTION 'Downgrade would remove assessment evidence'; END IF;
        END $$""")
    for table in (
        "assessment_audits",
        "assessment_jobs",
        "managed_profiles",
        "assessment_targets",
    ):
        op.drop_table(table)
    op.drop_column("anomaly_scores", "assessment_scope")
