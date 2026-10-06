"""agent enrollment tokens and proof of possession for keys

Revision ID: b4d6f8a0c2e5
Revises: a8c3e5f1b7d9

Direct registration and key replacement without proof are switched off for
every organization (allow_direct_registration false); an admin can switch
them back on per organization.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b4d6f8a0c2e5"
down_revision = "a8c3e5f1b7d9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_enrollments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("purpose", sa.String(10), nullable=False, server_default="new"),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("token_prefix", sa.String(20), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id")),
        sa.Column("name", sa.String(255)),
        sa.Column("description", sa.Text()),
        sa.Column("agent_type", sa.String(50)),
        sa.Column("owner_team", sa.String(100)),
        sa.Column("capabilities", postgresql.JSONB()),
        sa.Column("allowed_tools", postgresql.JSONB()),
        sa.Column("allowed_models", postgresql.JSONB()),
        sa.Column("max_delegation_depth", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("require_hybrid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("discovered_agent_id", sa.Integer(), sa.ForeignKey("discovered_agents.id", ondelete="SET NULL")),
        sa.Column("challenge", sa.String(64)),
        sa.Column("challenge_expires_at", sa.DateTime(timezone=True)),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_agent_enrollments_org_id", "agent_enrollments", ["org_id"])
    op.create_index("ix_agent_enrollments_token_hash", "agent_enrollments", ["token_hash"], unique=True)

    op.add_column("agents", sa.Column("key_challenge", sa.String(64)))
    op.add_column("agents", sa.Column("key_challenge_expires_at", sa.DateTime(timezone=True)))
    op.add_column("agent_signing_keys", sa.Column("proof", postgresql.JSONB()))
    op.add_column("agent_identity_settings",
                  sa.Column("allow_direct_registration", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("agent_identity_settings", "allow_direct_registration")
    op.drop_column("agent_signing_keys", "proof")
    op.drop_column("agents", "key_challenge_expires_at")
    op.drop_column("agents", "key_challenge")
    op.drop_index("ix_agent_enrollments_token_hash", table_name="agent_enrollments")
    op.drop_table("agent_enrollments")
