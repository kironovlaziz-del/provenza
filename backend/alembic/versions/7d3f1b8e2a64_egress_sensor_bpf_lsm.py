"""A sensor's BPF LSM state, from its heartbeat

Revision ID: 7d3f1b8e2a64
Revises: 6c2e9a4d1f70

  * egress_sensors.bpf_lsm - active, inactive, prepared (for the next boot) or
                             unavailable; NULL for a sensor that does not report it
"""
import sqlalchemy as sa
from alembic import op

revision = "7d3f1b8e2a64"
down_revision = "6c2e9a4d1f70"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("egress_sensors", sa.Column("bpf_lsm", sa.String(20), nullable=True))


def downgrade():
    op.drop_column("egress_sensors", "bpf_lsm")
