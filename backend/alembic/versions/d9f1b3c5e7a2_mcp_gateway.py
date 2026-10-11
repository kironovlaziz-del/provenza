"""MCP gateway: upstream servers, their tools, who executed an action

Revision ID: d9f1b3c5e7a2
Revises: c7e9a1b3d5f8

Agents reach MCP servers only through Provenza (app/pvp/mcp_gateway.py):
  * mcp_servers - the upstream servers; the credential is stored encrypted
  * mcp_tools   - each server's tools as last synced; approval stays in the
                  Tool Registry (pinned digest)
  * agent_actions.executed_by - "mcp_gateway" when Provenza made the call
    itself; NULL (every existing row) = the agent reported and signed it
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d9f1b3c5e7a2"
down_revision = "c7e9a1b3d5f8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mcp_servers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("slug", sa.String(40), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("protocol", sa.String(20), nullable=False, server_default="auto"),
        sa.Column("detected_version", sa.String(20)),
        sa.Column("auth_header", sa.String(100), nullable=False, server_default="Authorization"),
        sa.Column("auth_secret_encrypted", sa.Text()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("server_info", postgresql.JSONB()),
        sa.Column("last_synced_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "slug", name="uq_mcp_servers_slug"),
    )
    op.create_index("ix_mcp_servers_org_id", "mcp_servers", ["org_id"])
    op.create_table(
        "mcp_tools",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("server_id", sa.Integer(), sa.ForeignKey("mcp_servers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("exposed_name", sa.String(100), nullable=False),
        sa.Column("definition", postgresql.JSONB(), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("registry_entry_id", sa.Integer(),
                  sa.ForeignKey("tool_registry_entries.id", ondelete="SET NULL")),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("removed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("server_id", "name", name="uq_mcp_tools_name"),
    )
    op.create_index("ix_mcp_tools_org_id", "mcp_tools", ["org_id"])
    op.create_index("ix_mcp_tools_server_id", "mcp_tools", ["server_id"])
    op.add_column("agent_actions", sa.Column("executed_by", sa.String(20)))


def downgrade():
    op.drop_column("agent_actions", "executed_by")
    op.drop_index("ix_mcp_tools_server_id", table_name="mcp_tools")
    op.drop_index("ix_mcp_tools_org_id", table_name="mcp_tools")
    op.drop_table("mcp_tools")
    op.drop_index("ix_mcp_servers_org_id", table_name="mcp_servers")
    op.drop_table("mcp_servers")
