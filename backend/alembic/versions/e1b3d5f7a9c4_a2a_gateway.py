"""A2A gateway: remote peers and which agent owns which task

Revision ID: e1b3d5f7a9c4
Revises: d9f1b3c5e7a2

Agents reach remote A2A agents only through Provenza (app/pvp/a2a_gateway.py):
  * a2a_peers - the peers; the card is pinned through the Tool Registry
                ("a2a.<slug>"), the credential stored encrypted
  * a2a_tasks - task id -> the agent that created it, so no agent can read
                or cancel another agent's task
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e1b3d5f7a9c4"
down_revision = "d9f1b3c5e7a2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "a2a_peers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("slug", sa.String(40), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("card_url", sa.String(500), nullable=False),
        sa.Column("auth_header", sa.String(100), nullable=False, server_default="Authorization"),
        sa.Column("auth_secret_encrypted", sa.Text()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("card", postgresql.JSONB()),
        sa.Column("card_digest", sa.String(64)),
        sa.Column("endpoint_url", sa.String(500)),
        sa.Column("protocol_version", sa.String(10)),
        sa.Column("registry_entry_id", sa.Integer(),
                  sa.ForeignKey("tool_registry_entries.id", ondelete="SET NULL")),
        sa.Column("last_synced_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "slug", name="uq_a2a_peers_slug"),
    )
    op.create_index("ix_a2a_peers_org_id", "a2a_peers", ["org_id"])
    op.create_table(
        "a2a_tasks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("peer_id", sa.Integer(), sa.ForeignKey("a2a_peers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("task_id", sa.String(200), nullable=False),
        sa.Column("context_id", sa.String(200)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("peer_id", "task_id", name="uq_a2a_tasks_task"),
    )
    op.create_index("ix_a2a_tasks_org_id", "a2a_tasks", ["org_id"])
    op.create_index("ix_a2a_tasks_peer_id", "a2a_tasks", ["peer_id"])
    op.create_index("ix_a2a_tasks_agent_id", "a2a_tasks", ["agent_id"])


def downgrade():
    op.drop_index("ix_a2a_tasks_agent_id", table_name="a2a_tasks")
    op.drop_index("ix_a2a_tasks_peer_id", table_name="a2a_tasks")
    op.drop_index("ix_a2a_tasks_org_id", table_name="a2a_tasks")
    op.drop_table("a2a_tasks")
    op.drop_index("ix_a2a_peers_org_id", table_name="a2a_peers")
    op.drop_table("a2a_peers")
