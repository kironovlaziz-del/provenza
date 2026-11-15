"""Task mandates: a task a person gave an agent, signed; named by checks; the org setting

Revision ID: 1d4e7a9c3b5f
Revises: f2a3b4c5d6e7
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "1d4e7a9c3b5f"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "task_mandates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("task", sa.Text(), nullable=False),
        sa.Column("tools", postgresql.JSONB(none_as_null=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("signed", postgresql.JSONB(), nullable=False),
        sa.Column("statement_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
    )
    op.create_index("ix_task_mandates_org_id", "task_mandates", ["org_id"])
    op.create_index("ix_task_mandates_agent_id", "task_mandates", ["agent_id"])
    op.add_column("agent_action_checks", sa.Column(
        "mandate_id", sa.Integer(), sa.ForeignKey("task_mandates.id", ondelete="SET NULL"), nullable=True))
    op.add_column("agent_action_checks", sa.Column("mandate_sha256", sa.String(64), nullable=True))
    op.add_column("agent_identity_settings", sa.Column(
        "require_task_mandate", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("agent_identity_settings", "require_task_mandate")
    op.drop_column("agent_action_checks", "mandate_sha256")
    op.drop_column("agent_action_checks", "mandate_id")
    op.drop_index("ix_task_mandates_agent_id", table_name="task_mandates")
    op.drop_index("ix_task_mandates_org_id", table_name="task_mandates")
    op.drop_table("task_mandates")
