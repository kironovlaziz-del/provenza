"""Egress sensor: per-minute rates

Revision ID: f2b3c4d5e6f7
Revises: e1a2b3c4d5e6

The daemon now computes per-minute rates from a sliding 60s window and
sends them in every heartbeat. Nullable so an old sensor that does not
send them yet reads as null rather than as a fake zero.
"""
import sqlalchemy as sa
from alembic import op

revision = "f2b3c4d5e6f7"
down_revision = "e1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("egress_sensors", sa.Column("allowed_per_min", sa.BigInteger(), nullable=True))
    op.add_column("egress_sensors", sa.Column("denied_per_min", sa.BigInteger(), nullable=True))
    op.add_column("egress_sensors", sa.Column("observed_per_min", sa.BigInteger(), nullable=True))


def downgrade():
    op.drop_column("egress_sensors", "observed_per_min")
    op.drop_column("egress_sensors", "denied_per_min")
    op.drop_column("egress_sensors", "allowed_per_min")
