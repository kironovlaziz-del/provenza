"""Strict agent identity: signed action requests (single-use nonces); no keyless agents

Revision ID: b7e9a1c3d5f6
Revises: a6d8f0b2c4e7

  * action_nonces                    - nonces of signed /agents/actions/check requests
  * agent_identity_settings.allow_keyless_agents - removed: an agent without a key
                                       cannot act, there is no setting for it any more
"""
import sqlalchemy as sa
from alembic import op

revision = "b7e9a1c3d5f6"
down_revision = "a6d8f0b2c4e7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "action_nonces",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("agent_id", "nonce", name="uq_action_nonce"),
    )
    op.create_index("ix_action_nonces_created_at", "action_nonces", ["created_at"])
    op.drop_column("agent_identity_settings", "allow_keyless_agents")


def downgrade():
    op.add_column("agent_identity_settings", sa.Column("allow_keyless_agents", sa.Boolean(), nullable=False,
                                                       server_default=sa.false()))
    op.drop_index("ix_action_nonces_created_at", table_name="action_nonces")
    op.drop_table("action_nonces")
