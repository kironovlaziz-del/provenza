"""Automatic containment: boundary denials, its settings, a signed release

Revision ID: 3f6a9c1e5d7b
Revises: 2e5f8b0d4c6a
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "3f6a9c1e5d7b"
down_revision = "2e5f8b0d4c6a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_action_checks",
                  sa.Column("boundary", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.create_index("ix_agent_action_checks_boundary", "agent_action_checks", ["agent_id", "created_at"],
                    postgresql_where=sa.text("boundary"))
    op.add_column("behavior_settings",
                  sa.Column("containment_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("behavior_settings",
                  sa.Column("containment_max_boundary", sa.Integer(), nullable=False, server_default="3"))
    op.add_column("behavior_settings",
                  sa.Column("containment_window_seconds", sa.Integer(), nullable=False, server_default="600"))
    op.add_column("behavior_settings",
                  sa.Column("tripwire_tools", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")))
    op.add_column("agent_baselines", sa.Column("quarantine_release", postgresql.JSONB(none_as_null=True),
                                               nullable=True))


def downgrade() -> None:
    op.drop_column("agent_baselines", "quarantine_release")
    op.drop_column("behavior_settings", "tripwire_tools")
    op.drop_column("behavior_settings", "containment_window_seconds")
    op.drop_column("behavior_settings", "containment_max_boundary")
    op.drop_column("behavior_settings", "containment_enabled")
    op.drop_index("ix_agent_action_checks_boundary", table_name="agent_action_checks")
    op.drop_column("agent_action_checks", "boundary")
