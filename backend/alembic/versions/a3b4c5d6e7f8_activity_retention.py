"""Egress policy settings: activity retention

Revision ID: a3b4c5d6e7f8
Revises: f2b3c4d5e6f7

How long sampled allowed connections stay in sensor_activity. 0 disables
pruning. server_default=30 so existing rows get a value without a backfill.
"""
import sqlalchemy as sa
from alembic import op

revision = "a3b4c5d6e7f8"
down_revision = "f2b3c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "egress_policy_settings",
        sa.Column("activity_retention_days", sa.Integer(), nullable=False, server_default="30"),
    )


def downgrade():
    op.drop_column("egress_policy_settings", "activity_retention_days")
