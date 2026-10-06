"""derived capabilities: tools require capabilities, hops delegate tools

Revision ID: f2a7c4e9d1b3
Revises: e3b6d9f2a4c8
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f2a7c4e9d1b3"
down_revision = "e3b6d9f2a4c8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tool_registry_entries", sa.Column("required_capabilities", postgresql.JSONB()))
    op.add_column("delegation_hops", sa.Column("delegated_tools", postgresql.JSONB()))


def downgrade():
    op.drop_column("delegation_hops", "delegated_tools")
    op.drop_column("tool_registry_entries", "required_capabilities")
