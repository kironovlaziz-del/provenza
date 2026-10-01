"""ASI04 Tool Registry: registry entries + supply-chain mode per organization

Revision ID: 34f28137dd99
Revises: 5762769e51e6
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "34f28137dd99"
down_revision = "5762769e51e6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tool_registry_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("pattern", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False, server_default="tool"),
        sa.Column("display_name", sa.String(255)),
        sa.Column("source", sa.String(500)),
        sa.Column("publisher", sa.String(255)),
        sa.Column("pinned_version", sa.String(100)),
        sa.Column("pinned_digest", sa.String(100)),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("discovered", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("seen_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("approved_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("drift_details", postgresql.JSONB()),
        sa.Column("notes", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "pattern", name="uq_tool_registry_pattern"),
    )
    op.create_index("ix_tool_registry_entries_id", "tool_registry_entries", ["id"])
    op.create_index("ix_tool_registry_entries_org_id", "tool_registry_entries", ["org_id"])

    op.create_table(
        "supply_chain_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("mode", sa.String(20), nullable=False, server_default="monitor"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_supply_chain_settings_id", "supply_chain_settings", ["id"])


def downgrade():
    op.drop_index("ix_supply_chain_settings_id", table_name="supply_chain_settings")
    op.drop_table("supply_chain_settings")
    op.drop_index("ix_tool_registry_entries_org_id", table_name="tool_registry_entries")
    op.drop_index("ix_tool_registry_entries_id", table_name="tool_registry_entries")
    op.drop_table("tool_registry_entries")
