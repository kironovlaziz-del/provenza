"""Restore the runtime daemon tables (dropped by e4b6d8f0a2c3)

Revision ID: c3e5a7b9d1f4
Revises: b7e9a1c3d5f6

The Provenza runtime daemon (daemon/, eBPF) governs the outbound connections of
workloads named by their cgroups:
  * runtime_workloads  - which cgroups, what they may connect to, in which mode
  * runtime_violations - connections outside that policy, deduplicated and counted
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c3e5a7b9d1f4"
down_revision = "b7e9a1c3d5f6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "runtime_workloads",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL")),
        sa.Column("cgroup_patterns", postgresql.JSONB(), nullable=False),
        sa.Column("egress_allow", postgresql.JSONB(), nullable=False),
        sa.Column("allow_dns", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("mode", sa.String(10), nullable=False, server_default="observe"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "name", name="uq_runtime_workloads_name"),
    )
    op.create_index("ix_runtime_workloads_org_id", "runtime_workloads", ["org_id"])
    op.create_table(
        "runtime_violations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("ingestion_sources.id", ondelete="SET NULL")),
        sa.Column("workload_id", sa.Integer(), sa.ForeignKey("runtime_workloads.id", ondelete="SET NULL")),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL")),
        sa.Column("dedupe_key", sa.String(64), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("action", sa.String(10), nullable=False),
        sa.Column("protocol", sa.String(4), nullable=False),
        sa.Column("dst_ip", sa.String(45), nullable=False),
        sa.Column("dst_port", sa.Integer(), nullable=False),
        sa.Column("comm", sa.String(16)),
        sa.Column("cgroup", sa.String(500)),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "dedupe_key", name="uq_runtime_violations_dedupe"),
    )
    op.create_index("ix_runtime_violations_org_id", "runtime_violations", ["org_id"])
    op.create_index("ix_runtime_violations_workload_id", "runtime_violations", ["workload_id"])


def downgrade():
    op.drop_index("ix_runtime_violations_workload_id", table_name="runtime_violations")
    op.drop_index("ix_runtime_violations_org_id", table_name="runtime_violations")
    op.drop_table("runtime_violations")
    op.drop_index("ix_runtime_workloads_org_id", table_name="runtime_workloads")
    op.drop_table("runtime_workloads")
