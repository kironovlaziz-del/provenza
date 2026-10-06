"""teams and role templates

Revision ID: c6e8a0b2d4f7
Revises: b4d6f8a0c2e5

Every distinct non-empty agents.owner_team / open enrollment owner_team of an
organization becomes a team, and those agents and enrollments are linked to
it. No roles are created: existing agents keep their own rights.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c6e8a0b2d4f7"
down_revision = "b4d6f8a0c2e5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "teams",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("parent_id", sa.Integer(), sa.ForeignKey("teams.id")),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "name", name="uq_teams_org_name"),
    )
    op.create_index("ix_teams_org_id", "teams", ["org_id"])

    op.create_table(
        "role_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id")),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("capabilities", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("allowed_tools", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("allowed_models", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("max_delegation_depth", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("require_hybrid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("require_attestation", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_role_templates_org_id", "role_templates", ["org_id"])
    op.create_index("uq_role_templates_team_name", "role_templates", ["org_id", "team_id", "name"], unique=True,
                    postgresql_where=sa.text("team_id IS NOT NULL"))
    op.create_index("uq_role_templates_org_name", "role_templates", ["org_id", "name"], unique=True,
                    postgresql_where=sa.text("team_id IS NULL"))

    op.add_column("agents", sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id")))
    op.add_column("agents", sa.Column("role_id", sa.Integer(), sa.ForeignKey("role_templates.id")))
    op.create_index("ix_agents_team_id", "agents", ["team_id"])
    op.create_index("ix_agents_role_id", "agents", ["role_id"])
    op.add_column("agent_enrollments", sa.Column("team_id", sa.Integer(), sa.ForeignKey("teams.id")))
    op.add_column("agent_enrollments", sa.Column("role_id", sa.Integer(), sa.ForeignKey("role_templates.id")))

    # free-text owner_team -> teams
    op.execute("""
        INSERT INTO teams (org_id, name, created_at)
        SELECT DISTINCT org_id, btrim(owner_team), now() FROM (
            SELECT org_id, owner_team FROM agents
            UNION ALL
            SELECT org_id, owner_team FROM agent_enrollments WHERE used_at IS NULL AND revoked_at IS NULL
        ) s
        WHERE owner_team IS NOT NULL AND btrim(owner_team) <> ''
        ON CONFLICT (org_id, name) DO NOTHING
    """)
    op.execute("""
        UPDATE agents a SET team_id = t.id, owner_team = t.name
        FROM teams t WHERE t.org_id = a.org_id AND t.name = btrim(a.owner_team)
    """)
    op.execute("""
        UPDATE agent_enrollments e SET team_id = t.id, owner_team = t.name
        FROM teams t
        WHERE t.org_id = e.org_id AND t.name = btrim(e.owner_team)
          AND e.used_at IS NULL AND e.revoked_at IS NULL
    """)


def downgrade():
    op.drop_column("agent_enrollments", "role_id")
    op.drop_column("agent_enrollments", "team_id")
    op.drop_index("ix_agents_role_id", table_name="agents")
    op.drop_index("ix_agents_team_id", table_name="agents")
    op.drop_column("agents", "role_id")
    op.drop_column("agents", "team_id")
    op.drop_index("uq_role_templates_org_name", table_name="role_templates")
    op.drop_index("uq_role_templates_team_name", table_name="role_templates")
    op.drop_index("ix_role_templates_org_id", table_name="role_templates")
    op.drop_table("role_templates")
    op.drop_index("ix_teams_org_id", table_name="teams")
    op.drop_table("teams")
