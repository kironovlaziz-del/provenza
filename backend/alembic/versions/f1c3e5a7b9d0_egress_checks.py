"""Egress checks: is an agent's host confined to the egress proxy, and may acting depend on it

Revision ID: f1c3e5a7b9d0
Revises: e0b2d4f6a8c9

  * agent_egress_checks                                   - targets, beacon, signed report, verdict
  * agent_identity_settings.require_confined_egress       - act only from a confined host
  * agent_identity_settings.egress_check_max_age_hours    - how recent that check must be
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f1c3e5a7b9d0"
down_revision = "e0b2d4f6a8c9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_egress_checks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token", sa.String(64), nullable=False, unique=True),
        sa.Column("targets", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("beacon_hit_at", sa.DateTime(timezone=True)),
        sa.Column("beacon_ip", sa.String(64)),
        sa.Column("reported_at", sa.DateTime(timezone=True)),
        sa.Column("results", postgresql.JSONB()),
        sa.Column("verdict", sa.String(20), nullable=False, server_default="pending"),
    )
    op.create_index("ix_agent_egress_checks_org_id", "agent_egress_checks", ["org_id"])
    op.create_index("ix_agent_egress_checks_agent_id", "agent_egress_checks", ["agent_id"])
    op.add_column("agent_identity_settings", sa.Column("require_confined_egress", sa.Boolean(), nullable=False,
                                                       server_default=sa.false()))
    op.add_column("agent_identity_settings", sa.Column("egress_check_max_age_hours", sa.Integer(), nullable=False,
                                                       server_default="24"))


def downgrade():
    op.drop_column("agent_identity_settings", "egress_check_max_age_hours")
    op.drop_column("agent_identity_settings", "require_confined_egress")
    op.drop_index("ix_agent_egress_checks_agent_id", table_name="agent_egress_checks")
    op.drop_index("ix_agent_egress_checks_org_id", table_name="agent_egress_checks")
    op.drop_table("agent_egress_checks")
