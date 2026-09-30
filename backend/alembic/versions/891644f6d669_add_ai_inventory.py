"""add AI inventory (ai_systems, ai_system_data_links)

Revision ID: 891644f6d669
Revises: 4182c0d3c4e1
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "891644f6d669"
down_revision = "4182c0d3c4e1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_systems",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("kind", sa.String(30), nullable=False, server_default="other"),
        sa.Column("source_key", sa.String(120)),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL")),
        sa.Column("provider_id", sa.Integer(), sa.ForeignKey("ai_providers.id", ondelete="SET NULL")),
        sa.Column("deployment_id", sa.Integer(), sa.ForeignKey("model_deployments.id", ondelete="SET NULL")),
        sa.Column("use_case_id", sa.Integer(), sa.ForeignKey("ai_use_cases.id", ondelete="SET NULL")),
        sa.Column("shadow_tool", sa.String(255)),
        sa.Column("owner_user_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("business_owner", sa.String(255)),
        sa.Column("lifecycle_stage", sa.String(20), nullable=False, server_default="idea"),
        sa.Column("review_status", sa.String(20), nullable=False, server_default="unreviewed"),
        sa.Column("domain", sa.String(50), nullable=False, server_default="general"),
        sa.Column("risk_flags", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("suggested_risk_tier", sa.String(20)),
        sa.Column("risk_assessment", postgresql.JSONB()),
        sa.Column("confirmed_risk_tier", sa.String(20)),
        sa.Column("risk_justification", sa.Text()),
        sa.Column("risk_confirmed_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("risk_confirmed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "source_key", name="uq_ai_system_source"),
    )
    op.create_index("ix_ai_systems_id", "ai_systems", ["id"])
    op.create_index("ix_ai_systems_org_id", "ai_systems", ["org_id"])

    op.create_table(
        "ai_system_data_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("system_id", sa.Integer(), sa.ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relation", sa.String(20), nullable=False),
        sa.Column("dataset_id", sa.Integer(), sa.ForeignKey("datasets.id", ondelete="CASCADE")),
        sa.Column("collection_id", sa.Integer(), sa.ForeignKey("document_collections.id", ondelete="CASCADE")),
        sa.Column("external_name", sa.String(255)),
        sa.Column("contains_pii", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("notes", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_ai_system_data_links_id", "ai_system_data_links", ["id"])
    op.create_index("ix_ai_system_data_links_system_id", "ai_system_data_links", ["system_id"])


def downgrade():
    op.drop_index("ix_ai_system_data_links_system_id", table_name="ai_system_data_links")
    op.drop_index("ix_ai_system_data_links_id", table_name="ai_system_data_links")
    op.drop_table("ai_system_data_links")
    op.drop_index("ix_ai_systems_org_id", table_name="ai_systems")
    op.drop_index("ix_ai_systems_id", table_name="ai_systems")
    op.drop_table("ai_systems")
