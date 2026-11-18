"""Rule packs: an organization's own packs and each application to a level

Revision ID: 4a7c2e9f1b3d
Revises: 3f6a9c1e5d7b
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "4a7c2e9f1b3d"
down_revision = "3f6a9c1e5d7b"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_packs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("level", sa.String(10), nullable=False, server_default="any"),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("source_yaml", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("kind IN ('profile', 'guard')", name="ck_policy_packs_kind"),
        sa.CheckConstraint("level IN ('org', 'team', 'agent', 'any')", name="ck_policy_packs_level"),
    )
    op.create_index("ix_policy_packs_org_id", "policy_packs", ["org_id"])
    op.create_index("uq_policy_packs_name", "policy_packs", ["org_id", "name"], unique=True)

    op.create_table(
        "policy_pack_applications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("pack_ref", sa.String(120), nullable=False),
        sa.Column("pack_name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("scope", sa.String(10), nullable=False),
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id", ondelete="CASCADE")),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("delta", postgresql.JSONB()),
        sa.Column("previous", postgresql.JSONB()),
        sa.Column("applied", postgresql.JSONB(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("applied_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("undone_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("undone_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("scope IN ('org', 'team', 'agent')", name="ck_policy_pack_applications_scope"),
    )
    op.create_index("ix_policy_pack_applications_org_id", "policy_pack_applications", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_policy_pack_applications_org_id", table_name="policy_pack_applications")
    op.drop_table("policy_pack_applications")
    op.drop_index("uq_policy_packs_name", table_name="policy_packs")
    op.drop_index("ix_policy_packs_org_id", table_name="policy_packs")
    op.drop_table("policy_packs")
