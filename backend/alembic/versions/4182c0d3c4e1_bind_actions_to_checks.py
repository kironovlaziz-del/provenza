"""bind recorded agent actions to single-use policy checks

Revision ID: 4182c0d3c4e1
Revises: 4fc3b0c990e6
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "4182c0d3c4e1"
down_revision = "4fc3b0c990e6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_action_checks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("chain_id", sa.Integer(), sa.ForeignKey("delegation_chains.id", ondelete="CASCADE")),
        sa.Column("action_type", sa.String(50)),
        sa.Column("tool_name", sa.String(100)),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("action_capabilities", postgresql.JSONB()),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column("incident_type", sa.String(50)),
        sa.Column("policy_id", sa.Integer(), sa.ForeignKey("agent_policies.id")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_agent_action_checks_id", "agent_action_checks", ["id"])
    op.create_index("ix_agent_action_checks_token", "agent_action_checks", ["token"], unique=True)
    op.create_index("ix_agent_action_checks_org_id", "agent_action_checks", ["org_id"])

    op.add_column("agent_actions", sa.Column("check_id", sa.Integer(), nullable=True))
    op.add_column("agent_actions", sa.Column("signed_payload", postgresql.JSONB(), nullable=True))
    op.create_foreign_key("fk_agent_actions_check_id", "agent_actions", "agent_action_checks", ["check_id"], ["id"])
    op.create_index("ix_agent_actions_check_id", "agent_actions", ["check_id"])


def downgrade():
    op.drop_index("ix_agent_actions_check_id", table_name="agent_actions")
    op.drop_constraint("fk_agent_actions_check_id", "agent_actions", type_="foreignkey")
    op.drop_column("agent_actions", "signed_payload")
    op.drop_column("agent_actions", "check_id")
    op.drop_index("ix_agent_action_checks_org_id", table_name="agent_action_checks")
    op.drop_index("ix_agent_action_checks_token", table_name="agent_action_checks")
    op.drop_index("ix_agent_action_checks_id", table_name="agent_action_checks")
    op.drop_table("agent_action_checks")
