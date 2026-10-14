"""Egress sensor: sensors, workloads, policy revisions, violations

Revision ID: b1e2f3a4c5d6
Revises: a2d4f6b8c0e1

  * egress_sensors            - registered sensors of an organization, with
                                the hash of their X-Sensor-Key
  * egress_workloads          - one row per governed workload; deletions are
                                soft (deleted_at) so violations keep resolving
  * egress_policy_revisions   - one monotonic counter per org; its value is
                                what the sensor compares against If-None-Match
  * egress_violations         - append-only events the sensors reported
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b1e2f3a4c5d6"
down_revision = "a2d4f6b8c0e1"
branch_labels = None
depends_on = None


def upgrade():
    # ---- egress_sensors ----
    op.create_table(
        "egress_sensors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("hostname", sa.String(255)),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(24), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("version", sa.String(100)),
        sa.Column("kernel", sa.String(100)),
        sa.Column("enforcing", sa.Boolean()),
        sa.Column("hooks", postgresql.JSONB()),
        sa.Column("warnings", postgresql.JSONB()),
        sa.Column("errors", postgresql.JSONB()),
        sa.Column("dropped_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("config_version", sa.String(64)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "name", name="uq_egress_sensors_name"),
    )
    op.create_index("ix_egress_sensors_org_id", "egress_sensors", ["org_id"])
    op.create_index("ix_egress_sensors_key_hash", "egress_sensors", ["key_hash"], unique=True)

    # ---- egress_workloads ----
    op.create_table(
        "egress_workloads",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("cgroup_patterns", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("run_as_users", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("egress_allow", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("ingress_allow", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("dns", sa.String(10), nullable=False, server_default="off"),
        sa.Column("mode", sa.String(10), nullable=False, server_default="observe"),
        sa.Column("isolated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("isolated_reason", sa.String(500)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "name", name="uq_egress_workloads_name"),
    )
    op.create_index("ix_egress_workloads_org_id", "egress_workloads", ["org_id"])
    op.create_index("ix_egress_workloads_agent_id", "egress_workloads", ["agent_id"])
    op.create_index("ix_egress_workloads_deleted_at", "egress_workloads", ["deleted_at"])
    op.create_index("ix_egress_workloads_active", "egress_workloads", ["org_id", "deleted_at"])

    # ---- egress_policy_revisions ----
    op.create_table(
        "egress_policy_revisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", name="uq_egress_policy_revisions_org"),
    )
    op.create_index("ix_egress_policy_revisions_org_id", "egress_policy_revisions", ["org_id"], unique=True)

    # ---- egress_violations ----
    op.create_table(
        "egress_violations",
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
        sa.Column("isolated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_egress_violations_org_id", "egress_violations", ["org_id"])
    op.create_index("ix_egress_violations_sensor_id", "egress_violations", ["sensor_id"])
    op.create_index("ix_egress_violations_workload_id", "egress_violations", ["workload_id"])
    op.create_index("ix_egress_violations_created_at", "egress_violations", ["created_at"])
    op.create_index("ix_egress_violations_org_time", "egress_violations", ["org_id", "created_at"])
    op.create_index("ix_egress_violations_workload_time", "egress_violations", ["workload_id", "created_at"])


def downgrade():
    op.drop_index("ix_egress_violations_workload_time", table_name="egress_violations")
    op.drop_index("ix_egress_violations_org_time", table_name="egress_violations")
    op.drop_index("ix_egress_violations_created_at", table_name="egress_violations")
    op.drop_index("ix_egress_violations_workload_id", table_name="egress_violations")
    op.drop_index("ix_egress_violations_sensor_id", table_name="egress_violations")
    op.drop_index("ix_egress_violations_org_id", table_name="egress_violations")
    op.drop_table("egress_violations")

    op.drop_index("ix_egress_policy_revisions_org_id", table_name="egress_policy_revisions")
    op.drop_table("egress_policy_revisions")

    op.drop_index("ix_egress_workloads_active", table_name="egress_workloads")
    op.drop_index("ix_egress_workloads_deleted_at", table_name="egress_workloads")
    op.drop_index("ix_egress_workloads_agent_id", table_name="egress_workloads")
    op.drop_index("ix_egress_workloads_org_id", table_name="egress_workloads")
    op.drop_table("egress_workloads")

    op.drop_index("ix_egress_sensors_key_hash", table_name="egress_sensors")
    op.drop_index("ix_egress_sensors_org_id", table_name="egress_sensors")
    op.drop_table("egress_sensors")
