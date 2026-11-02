"""agent_manifests: the Agent Manifests (AgenTrust v0.2) issued for agents.

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_manifests",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("manifest_id", sa.String(36), nullable=False, unique=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("previous_manifest_id", sa.String(36)),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("envelope", sa.LargeBinary(), nullable=False),
        sa.Column("key_fingerprint", sa.String(80), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        if_not_exists=True,
    )
    op.create_index("ix_agent_manifests_org_id", "agent_manifests", ["org_id"], if_not_exists=True)
    op.create_index("ix_agent_manifests_agent_id", "agent_manifests", ["agent_id"], if_not_exists=True)


def downgrade() -> None:
    op.drop_table("agent_manifests", if_exists=True)
