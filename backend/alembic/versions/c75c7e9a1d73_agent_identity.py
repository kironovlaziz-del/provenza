"""agent identity: key lifecycle columns, settings

Revision ID: c75c7e9a1d73
Revises: 53dfb62a2740
"""
from alembic import op
import sqlalchemy as sa

revision = "c75c7e9a1d73"
down_revision = "53dfb62a2740"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("agents", sa.Column("previous_api_key_hash", sa.String(64)))
    op.add_column("agents", sa.Column("previous_key_expires_at", sa.DateTime(timezone=True)))
    op.add_column("agents", sa.Column("api_key_rotated_at", sa.DateTime(timezone=True)))
    op.add_column("agents", sa.Column("api_key_revoked_at", sa.DateTime(timezone=True)))
    op.add_column("agents", sa.Column("api_key_last_used_at", sa.DateTime(timezone=True)))
    op.create_index("ix_agents_previous_api_key_hash", "agents", ["previous_api_key_hash"])

    op.create_table(
        "agent_identity_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("require_agent_key", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rotation_grace_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_agent_identity_settings_id", "agent_identity_settings", ["id"])


def downgrade():
    op.drop_index("ix_agent_identity_settings_id", table_name="agent_identity_settings")
    op.drop_table("agent_identity_settings")
    op.drop_index("ix_agents_previous_api_key_hash", table_name="agents")
    for col in ("api_key_last_used_at", "api_key_revoked_at", "api_key_rotated_at",
                "previous_key_expires_at", "previous_api_key_hash"):
        op.drop_column("agents", col)
