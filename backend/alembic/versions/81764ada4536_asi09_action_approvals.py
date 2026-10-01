"""ASI09 human approval records (who approved which exact arguments)

Revision ID: 81764ada4536
Revises: 34f28137dd99
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "81764ada4536"
down_revision = "34f28137dd99"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_action_approvals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("action_id", sa.Integer(), sa.ForeignKey("agent_actions.id", ondelete="CASCADE"),
                  nullable=False, unique=True),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("decided_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("decided_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("self_approved", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("typed_confirmation", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("flags", postgresql.JSONB()),
    )
    op.create_index("ix_agent_action_approvals_id", "agent_action_approvals", ["id"])
    op.create_index("ix_agent_action_approvals_org_id", "agent_action_approvals", ["org_id"])


def downgrade():
    op.drop_index("ix_agent_action_approvals_org_id", table_name="agent_action_approvals")
    op.drop_index("ix_agent_action_approvals_id", table_name="agent_action_approvals")
    op.drop_table("agent_action_approvals")
