"""PVP Input Guard: log of refused requests

Revision ID: c7e9a1b3d5f8
Revises: b5e7a9c1d3f6

A request the Input Guard refuses never becomes a PVP message
(app/pvp/guard.py). What it was is kept here as a hash, a size and, per
finding, a code and a JSON path - never the content.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c7e9a1b3d5f8"
down_revision = "b5e7a9c1d3f6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pvp_guard_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL")),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("protocol", sa.String(20), nullable=False),
        sa.Column("route", sa.String(50), nullable=False),
        sa.Column("reason", sa.String(100), nullable=False),
        sa.Column("findings", postgresql.JSONB(), nullable=False),
        sa.Column("body_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("client_ip", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_pvp_guard_log_org_created", "pvp_guard_log", ["org_id", "created_at"])
    op.create_index("ix_pvp_guard_log_agent_id", "pvp_guard_log", ["agent_id"])


def downgrade():
    op.drop_index("ix_pvp_guard_log_agent_id", table_name="pvp_guard_log")
    op.drop_index("ix_pvp_guard_log_org_created", table_name="pvp_guard_log")
    op.drop_table("pvp_guard_log")
