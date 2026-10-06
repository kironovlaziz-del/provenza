"""kill switch: stops at agent, team, all-agents and organization-traffic level, with undo

Revision ID: f1c3e5a7b9d2
Revises: e9b1d3f5a7c2

Earlier kills (POST /agents/{id}/kill) left no event, so they have nothing
to undo; agents they suspended stay suspended as before.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f1c3e5a7b9d2"
down_revision = "e9b1d3f5a7c2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "kill_switch_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("scope", sa.String(12), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL")),
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id", ondelete="SET NULL")),
        sa.Column("target_name", sa.String(255)),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("stopped", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("lifted_at", sa.DateTime(timezone=True)),
        sa.Column("lifted_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("lift_reason", sa.Text()),
        sa.Column("lift_result", postgresql.JSONB()),
        sa.CheckConstraint("scope IN ('agent', 'team', 'all_agents', 'org_traffic')", name="ck_kill_switch_scope"),
    )
    op.create_index("ix_kill_switch_events_org_id", "kill_switch_events", ["org_id"])
    op.create_index("ix_kill_switch_active", "kill_switch_events", ["org_id"],
                    postgresql_where=sa.text("lifted_at IS NULL"))


def downgrade():
    op.drop_index("ix_kill_switch_active", table_name="kill_switch_events")
    op.drop_index("ix_kill_switch_events_org_id", table_name="kill_switch_events")
    op.drop_table("kill_switch_events")
