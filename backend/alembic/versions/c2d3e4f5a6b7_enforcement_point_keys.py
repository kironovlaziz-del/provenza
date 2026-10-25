"""Enforcement point keys: egress proxies sign what they witness

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6

docs/pvp/edge.md, section 4: an egress proxy generates its own Ed25519 key on
its host and registers the public half (egress_proxies.public_key); what it
forwarded carries its signed receipt (agent_actions.witness), which is part
of the action's evidence.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c2d3e4f5a6b7"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("egress_proxies", sa.Column("public_key", sa.Text()))
    op.add_column("egress_proxies", sa.Column("key_registered_at", sa.DateTime(timezone=True)))
    op.add_column("agent_actions", sa.Column("witness", postgresql.JSONB()))


def downgrade():
    op.drop_column("agent_actions", "witness")
    op.drop_column("egress_proxies", "key_registered_at")
    op.drop_column("egress_proxies", "public_key")
