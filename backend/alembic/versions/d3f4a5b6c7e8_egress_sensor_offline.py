"""Egress sensor: track when we last warned the org about a silent sensor

Revision ID: d3f4a5b6c7e8
Revises: c2f3a4b5d6e7
"""
import sqlalchemy as sa
from alembic import op

revision = "d3f4a5b6c7e8"
down_revision = "a7d9f1b3c5e6"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("egress_sensors", sa.Column("offline_notified_at", sa.DateTime(timezone=True)))


def downgrade():
    op.drop_column("egress_sensors", "offline_notified_at")
