"""Egress sensor: sampled activity

Revision ID: e1a2b3c4d5e6
Revises: d9e0f1a2b3c4

A new table for sampled allowed connections from the sensor's activity feed.
Separate from egress_violations so the two can have different retention.
"""
import sqlalchemy as sa
from alembic import op

revision = "e1a2b3c4d5e6"
down_revision = "d9e0f1a2b3c4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "sensor_activity",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("sensor_id", sa.Integer(), sa.ForeignKey("egress_sensors.id", ondelete="SET NULL")),
        sa.Column("workload_id", sa.Integer(), sa.ForeignKey("egress_workloads.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("protocol", sa.String(10)),
        sa.Column("dst_ip", sa.String(64)),
        sa.Column("dst_port", sa.Integer()),
        sa.Column("dst_name", sa.String(255)),
        sa.Column("comm", sa.String(64)),
        sa.Column("cgroup", sa.String(500)),
        sa.Column("isolated", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("count", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sensor_activity_org_id", "sensor_activity", ["org_id"])
    op.create_index("ix_sensor_activity_sensor_id", "sensor_activity", ["sensor_id"])
    op.create_index("ix_sensor_activity_workload_id", "sensor_activity", ["workload_id"])
    op.create_index("ix_sensor_activity_created_at", "sensor_activity", ["created_at"])
    op.create_index("ix_sensor_activity_org_time", "sensor_activity", ["org_id", "created_at"])
    op.create_index("ix_sensor_activity_sensor_time", "sensor_activity", ["sensor_id", "created_at"])


def downgrade():
    op.drop_index("ix_sensor_activity_sensor_time", table_name="sensor_activity")
    op.drop_index("ix_sensor_activity_org_time", table_name="sensor_activity")
    op.drop_index("ix_sensor_activity_created_at", table_name="sensor_activity")
    op.drop_index("ix_sensor_activity_workload_id", table_name="sensor_activity")
    op.drop_index("ix_sensor_activity_sensor_id", table_name="sensor_activity")
    op.drop_index("ix_sensor_activity_org_id", table_name="sensor_activity")
    op.drop_table("sensor_activity")
