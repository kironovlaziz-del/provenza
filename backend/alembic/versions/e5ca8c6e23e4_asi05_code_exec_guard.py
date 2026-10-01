"""ASI05 code-execution guard: settings, detections

Revision ID: e5ca8c6e23e4
Revises: bce1cb07d220
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "e5ca8c6e23e4"
down_revision = "bce1cb07d220"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "code_exec_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("mode", sa.String(20), nullable=False, server_default="monitor"),
        sa.Column("code_tools", postgresql.JSONB(), nullable=False),
        sa.Column("approve_code_tools", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_code_exec_settings_id", "code_exec_settings", ["id"])

    op.create_table(
        "code_exec_detections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("chain_id", sa.Integer(), sa.ForeignKey("delegation_chains.id", ondelete="SET NULL")),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tool_name", sa.String(100)),
        sa.Column("code_tool", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("findings", postgresql.JSONB(), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
    )
    for ix in ("id", "org_id", "agent_id", "detected_at"):
        op.create_index(f"ix_code_exec_detections_{ix}", "code_exec_detections", [ix])


def downgrade():
    for ix in ("detected_at", "agent_id", "org_id", "id"):
        op.drop_index(f"ix_code_exec_detections_{ix}", table_name="code_exec_detections")
    op.drop_table("code_exec_detections")
    op.drop_index("ix_code_exec_settings_id", table_name="code_exec_settings")
    op.drop_table("code_exec_settings")
