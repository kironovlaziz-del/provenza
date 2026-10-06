"""hierarchical policies: organization, team and agent levels

Revision ID: e9b1d3f5a7c2
Revises: d7f9b1c3e5a8

No level exists after upgrading, so nothing is enforced differently until
an admin writes one; the gateway settings keep applying as before.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e9b1d3f5a7c2"
down_revision = "d7f9b1c3e5a8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "policy_layers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("scope", sa.String(10), nullable=False),
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id")),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id")),
        sa.Column("document", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("source_yaml", sa.Text()),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("scope IN ('org', 'team', 'agent')", name="ck_policy_layers_scope"),
        sa.CheckConstraint("(scope = 'team') = (team_id IS NOT NULL) AND (scope = 'agent') = (agent_id IS NOT NULL)",
                           name="ck_policy_layers_target"),
    )
    op.create_index("ix_policy_layers_org_id", "policy_layers", ["org_id"])
    op.create_index("uq_policy_layers_org", "policy_layers", ["org_id"], unique=True,
                    postgresql_where=sa.text("scope = 'org'"))
    op.create_index("uq_policy_layers_team", "policy_layers", ["team_id"], unique=True,
                    postgresql_where=sa.text("scope = 'team'"))
    op.create_index("uq_policy_layers_agent", "policy_layers", ["agent_id"], unique=True,
                    postgresql_where=sa.text("scope = 'agent'"))


def downgrade():
    op.drop_index("uq_policy_layers_agent", table_name="policy_layers")
    op.drop_index("uq_policy_layers_team", table_name="policy_layers")
    op.drop_index("uq_policy_layers_org", table_name="policy_layers")
    op.drop_index("ix_policy_layers_org_id", table_name="policy_layers")
    op.drop_table("policy_layers")
