"""ASI01 prompt-injection guard: settings, detections, chain taint

Revision ID: bce1cb07d220
Revises: 2bf4e59c5621
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "bce1cb07d220"
down_revision = "2bf4e59c5621"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "injection_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("mode", sa.String(20), nullable=False, server_default="monitor"),
        sa.Column("threshold", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_injection_settings_id", "injection_settings", ["id"])

    op.create_table(
        "injection_detections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("chain_id", sa.Integer(), sa.ForeignKey("delegation_chains.id", ondelete="SET NULL")),
        sa.Column("action_id", sa.Integer()),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("tool_name", sa.String(100)),
        sa.Column("path", sa.String(300)),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("findings", postgresql.JSONB(), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
    )
    for ix in ("id", "org_id", "agent_id", "detected_at"):
        op.create_index(f"ix_injection_detections_{ix}", "injection_detections", [ix])

    op.add_column("delegation_chains", sa.Column("tainted_at", sa.DateTime(timezone=True)))
    op.add_column("delegation_chains", sa.Column("taint_details", postgresql.JSONB()))


def downgrade():
    op.drop_column("delegation_chains", "taint_details")
    op.drop_column("delegation_chains", "tainted_at")
    for ix in ("detected_at", "agent_id", "org_id", "id"):
        op.drop_index(f"ix_injection_detections_{ix}", table_name="injection_detections")
    op.drop_table("injection_detections")
    op.drop_index("ix_injection_settings_id", table_name="injection_settings")
    op.drop_table("injection_settings")
