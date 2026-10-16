"""Egress sensor: per-organization policy settings

Revision ID: f5c7d9e1b3a5
Revises: e4b6c8d0f2a3

Adds egress_policy_settings: one row per organization, holding the values
the sensor reads on every policy fetch (refresh and heartbeat intervals,
defaults for new workloads). A row is created lazily on first read; until
then the values in this migration's server_default are what the API serves.
"""
import sqlalchemy as sa
from alembic import op

revision = "f5c7d9e1b3a5"
down_revision = "e4b6c8d0f2a3"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "egress_policy_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"),
                  nullable=False, unique=True),
        sa.Column("refresh_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("heartbeat_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("default_mode", sa.String(10), nullable=False, server_default="observe"),
        sa.Column("default_dns", sa.String(10), nullable=False, server_default="off"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_egress_policy_settings_org_id", "egress_policy_settings", ["org_id"], unique=True)


def downgrade():
    op.drop_index("ix_egress_policy_settings_org_id", table_name="egress_policy_settings")
    op.drop_table("egress_policy_settings")
