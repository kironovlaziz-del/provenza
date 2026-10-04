"""endpoint devices and discovered AI agents

Revision ID: c1d4e7a2b9f6
Revises: b7e3f1a9c2d5
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "c1d4e7a2b9f6"
down_revision = "b7e3f1a9c2d5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "endpoint_devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ingestion_source_id", sa.Integer(),
                  sa.ForeignKey("ingestion_sources.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.String(255), nullable=False),
        sa.Column("last_user", sa.String(255)),
        sa.Column("os", sa.String(30)),
        sa.Column("agent_version", sa.String(30)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("event_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.UniqueConstraint("org_id", "ingestion_source_id", "host_id", name="uq_endpoint_devices_host"),
    )
    op.create_index("ix_endpoint_devices_id", "endpoint_devices", ["id"])
    op.create_index("ix_endpoint_devices_org_id", "endpoint_devices", ["org_id"])

    op.create_table(
        "discovered_agents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("endpoint_devices.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("product", sa.String(60), nullable=False),
        sa.Column("risk_score", sa.Float()),
        sa.Column("evidence", postgresql.JSONB()),
        sa.Column("status", sa.String(20), nullable=False, server_default="new"),
        sa.Column("registered_agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="SET NULL")),
        sa.Column("decided_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("seen_count", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("org_id", "device_id", "product", name="uq_discovered_agents_device_product"),
    )
    op.create_index("ix_discovered_agents_id", "discovered_agents", ["id"])
    op.create_index("ix_discovered_agents_org_id", "discovered_agents", ["org_id"])
    op.create_index("ix_discovered_agents_device_id", "discovered_agents", ["device_id"])
    op.create_index("ix_discovered_agents_registered_agent_id", "discovered_agents", ["registered_agent_id"])


def downgrade():
    op.drop_table("discovered_agents")
    op.drop_table("endpoint_devices")
