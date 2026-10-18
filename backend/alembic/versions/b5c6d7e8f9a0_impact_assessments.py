"""AI systems: impact assessments (ISO/IEC 42005, DPIA, FRIA in one)

Revision ID: b5c6d7e8f9a0
Revises: a4b5c6d7e8f9

Versioned answers to one questionnaire per AI system; a draft is edited,
an approved version is never changed.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b5c6d7e8f9a0"
down_revision = "a4b5c6d7e8f9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_impact_assessments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("system_id", sa.Integer(), sa.ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("template_version", sa.String(20), nullable=False),
        sa.Column("answers", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.Column("approved_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("review_due", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("system_id", "version", name="uq_impact_assessment_version"),
    )
    op.create_index("ix_ai_impact_assessments_org_id", "ai_impact_assessments", ["org_id"])
    op.create_index("ix_ai_impact_assessments_system_id", "ai_impact_assessments", ["system_id"])


def downgrade():
    op.drop_index("ix_ai_impact_assessments_system_id", table_name="ai_impact_assessments")
    op.drop_index("ix_ai_impact_assessments_org_id", table_name="ai_impact_assessments")
    op.drop_table("ai_impact_assessments")
