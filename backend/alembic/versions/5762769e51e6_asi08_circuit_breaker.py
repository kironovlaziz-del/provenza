"""ASI08 chain circuit breaker: settings table + breaker columns on chains

Revision ID: 5762769e51e6
Revises: 891644f6d669
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "5762769e51e6"
down_revision = "891644f6d669"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("delegation_chains", sa.Column("breaker_tripped_at", sa.DateTime(timezone=True)))
    op.add_column("delegation_chains", sa.Column("breaker_reset_at", sa.DateTime(timezone=True)))
    op.add_column("delegation_chains", sa.Column("breaker_details", postgresql.JSONB()))

    op.create_table(
        "agent_breaker_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("max_denials", sa.Integer(), nullable=False),
        sa.Column("max_incidents", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "agent_id", name="uq_breaker_org_agent"),
    )
    op.create_index("ix_agent_breaker_settings_id", "agent_breaker_settings", ["id"])
    op.create_index("ix_agent_breaker_settings_org_id", "agent_breaker_settings", ["org_id"])
    op.create_index("uq_breaker_org_default", "agent_breaker_settings", ["org_id"], unique=True,
                    postgresql_where=sa.text("agent_id IS NULL"))


def downgrade():
    op.drop_index("uq_breaker_org_default", table_name="agent_breaker_settings")
    op.drop_index("ix_agent_breaker_settings_org_id", table_name="agent_breaker_settings")
    op.drop_index("ix_agent_breaker_settings_id", table_name="agent_breaker_settings")
    op.drop_table("agent_breaker_settings")
    op.drop_column("delegation_chains", "breaker_details")
    op.drop_column("delegation_chains", "breaker_reset_at")
    op.drop_column("delegation_chains", "breaker_tripped_at")
