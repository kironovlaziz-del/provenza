"""Egress sensor: traffic counters

Revision ID: d9e0f1a2b3c4
Revises: d9e0f1a2b3c4

Adds three totals to egress_sensors, updated on every heartbeat: allowed,
denied and observed governed socket decisions since the sensor started.
The UI shows them as a rate; a sensor restart resets all three to zero.
"""
import sqlalchemy as sa
from alembic import op

revision = "d9e0f1a2b3c4"
down_revision = "d9e0f1a2b3c4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("egress_sensors",
                  sa.Column("allowed_total", sa.BigInteger(), nullable=False, server_default="0"))
    op.add_column("egress_sensors",
                  sa.Column("denied_total", sa.BigInteger(), nullable=False, server_default="0"))
    op.add_column("egress_sensors",
                  sa.Column("observed_total", sa.BigInteger(), nullable=False, server_default="0"))


def downgrade():
    op.drop_column("egress_sensors", "observed_total")
    op.drop_column("egress_sensors", "denied_total")
    op.drop_column("egress_sensors", "allowed_total")
