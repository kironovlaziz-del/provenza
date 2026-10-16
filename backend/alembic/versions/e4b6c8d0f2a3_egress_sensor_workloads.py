"""Egress sensor: per-workload snapshot (cgroups, DNS counters)

Revision ID: e4b6c8d0f2a3
Revises: e4b6c8d0f2a3

One row per (sensor, workload) with what the sensor reported on its last
heartbeat: how many cgroups are governed under the workload and how its
DNS proxy is doing. The row is overwritten on every heartbeat; when a
sensor stops reporting a workload, the row goes with it.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e4b6c8d0f2a3"
down_revision = "d3f4a5b6c7e8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "egress_sensor_workloads",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("sensor_id", sa.Integer(),
                  sa.ForeignKey("egress_sensors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("workload_id", sa.Integer(),
                  sa.ForeignKey("egress_workloads.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cgroups", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("processes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("privileged", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("dns_port", sa.Integer()),
        sa.Column("dns_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("dns_allowed", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("dns_denied", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("sensor_id", "workload_id", name="uq_egress_sensor_workloads"),
    )
    op.create_index("ix_egress_sensor_workloads_org_id", "egress_sensor_workloads", ["org_id"])
    op.create_index("ix_egress_sensor_workloads_sensor_id", "egress_sensor_workloads", ["sensor_id"])
    op.create_index("ix_egress_sensor_workloads_workload_id", "egress_sensor_workloads", ["workload_id"])


def downgrade():
    op.drop_index("ix_egress_sensor_workloads_workload_id", table_name="egress_sensor_workloads")
    op.drop_index("ix_egress_sensor_workloads_sensor_id", table_name="egress_sensor_workloads")
    op.drop_index("ix_egress_sensor_workloads_org_id", table_name="egress_sensor_workloads")
    op.drop_table("egress_sensor_workloads")
