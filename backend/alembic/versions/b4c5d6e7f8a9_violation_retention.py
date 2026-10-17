"""Egress policy settings: violation retention

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8

Companion to activity_retention_days, for egress_violations. 0 disables
pruning. server_default=30 so existing rows get a value without a backfill.
"""
import sqlalchemy as sa
from alembic import op

revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "egress_policy_settings",
        sa.Column("violation_retention_days", sa.Integer(), nullable=False, server_default="30"),
    )


def downgrade():
    op.drop_column("egress_policy_settings", "violation_retention_days")
