"""A sensor's host services and containers, from its heartbeat

Revision ID: 8e4a2c9d5b17
Revises: 7d3f1b8e2a64

  * egress_sensors.units    - [{kind, name, runtime, id, cgroup}]: what an agent can
                              be attached to with a click (agent_network)
  * egress_sensors.units_at - when the sensor last sent the list
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "8e4a2c9d5b17"
down_revision = "7d3f1b8e2a64"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("egress_sensors", sa.Column("units", postgresql.JSONB(), nullable=True))
    op.add_column("egress_sensors", sa.Column("units_at", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column("egress_sensors", "units_at")
    op.drop_column("egress_sensors", "units")
