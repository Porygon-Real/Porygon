"""Persist exact model/comparator evidence and the verified review actor."""
from alembic import op
import sqlalchemy as sa
revision='model_promotion_review'
down_revision='host_health_identity'
branch_labels=None
depends_on=None


def upgrade():
    op.create_table('model_promotion_reviews',sa.Column('review_hash',sa.String(64),primary_key=True),
        sa.Column('artifact_hash',sa.String(64),sa.ForeignKey('advisory_models.artifact_hash',ondelete='RESTRICT'),nullable=False),
        sa.Column('document',sa.JSON(),nullable=False),sa.Column('reviewed_by',sa.String(128),nullable=False),
        sa.Column('reviewed_at',sa.DateTime(timezone=True),nullable=False))


def downgrade():
    op.execute("""DO $$ BEGIN IF EXISTS(SELECT 1 FROM model_promotion_reviews)
      THEN RAISE EXCEPTION 'Downgrade would erase model promotion evidence'; END IF; END $$""")
    op.drop_table('model_promotion_reviews')
