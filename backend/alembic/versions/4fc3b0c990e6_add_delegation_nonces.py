"""add delegation_nonces (replay protection)

Revision ID: 4fc3b0c990e6
Revises: d5e7f9a1b3c5
"""
from alembic import op
import sqlalchemy as sa

revision = "4fc3b0c990e6"
down_revision = "d5e7f9a1b3c5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "delegation_nonces",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("from_agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("org_id", "from_agent_id", "nonce", name="uq_delegation_nonce"),
    )
    op.create_index("ix_delegation_nonces_id", "delegation_nonces", ["id"])
    op.create_index("ix_delegation_nonces_created_at", "delegation_nonces", ["created_at"])


def downgrade():
    op.drop_index("ix_delegation_nonces_created_at", table_name="delegation_nonces")
    op.drop_index("ix_delegation_nonces_id", table_name="delegation_nonces")
    op.drop_table("delegation_nonces")
