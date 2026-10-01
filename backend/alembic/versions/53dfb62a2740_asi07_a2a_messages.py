"""ASI07 agent-to-agent messages: settings, channels, messages

Revision ID: 53dfb62a2740
Revises: a1bdc78dd2c2
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "53dfb62a2740"
down_revision = "a1bdc78dd2c2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "a2a_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("mode", sa.String(20), nullable=False, server_default="monitor"),
        sa.Column("allow_same_chain", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("max_age_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("message_ttl_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_a2a_settings_id", "a2a_settings", ["id"])

    op.create_table(
        "a2a_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("from_agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("to_agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("bidirectional", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("disabled_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_a2a_channels_id", "a2a_channels", ["id"])
    op.create_index("ix_a2a_channels_org_id", "a2a_channels", ["org_id"])

    op.create_table(
        "a2a_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("from_agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("to_agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("chain_id", sa.Integer(), sa.ForeignKey("delegation_chains.id", ondelete="SET NULL")),
        sa.Column("message_type", sa.String(50)),
        sa.Column("payload_sha256", sa.String(64)),
        sa.Column("nonce", sa.String(128)),
        sa.Column("issued_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("signature_valid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("reasons", postgresql.JSONB(), nullable=False),
        sa.Column("findings", postgresql.JSONB(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("receive_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("org_id", "from_agent_id", "nonce", name="uq_a2a_nonce"),
    )
    for ix in ("id", "org_id", "from_agent_id", "to_agent_id", "created_at"):
        op.create_index(f"ix_a2a_messages_{ix}", "a2a_messages", [ix])


def downgrade():
    for ix in ("created_at", "to_agent_id", "from_agent_id", "org_id", "id"):
        op.drop_index(f"ix_a2a_messages_{ix}", table_name="a2a_messages")
    op.drop_table("a2a_messages")
    op.drop_index("ix_a2a_channels_org_id", table_name="a2a_channels")
    op.drop_index("ix_a2a_channels_id", table_name="a2a_channels")
    op.drop_table("a2a_channels")
    op.drop_index("ix_a2a_settings_id", table_name="a2a_settings")
    op.drop_table("a2a_settings")
