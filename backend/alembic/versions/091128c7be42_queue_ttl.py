"""request pipeline TTL: enqueued_at, settings, sweeps

Revision ID: 091128c7be42
Revises: e5d813340c6d
"""
from alembic import op
import sqlalchemy as sa

revision = "091128c7be42"
down_revision = "e5d813340c6d"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ai_requests", sa.Column("enqueued_at", sa.DateTime(timezone=True)))
    op.create_index("ix_ai_requests_org_status", "ai_requests", ["org_id", "status"])

    op.create_table(
        "queue_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("queue_ttl_seconds", sa.Integer(), nullable=False, server_default="900"),
        sa.Column("approval_ttl_hours", sa.Integer(), nullable=False, server_default="72"),
        sa.Column("raw_prompt_retention_days", sa.Integer()),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_queue_settings_id", "queue_settings", ["id"])

    op.create_table(
        "queue_sweeps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("ran_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("trigger", sa.String(20), nullable=False),
        sa.Column("expired_queued", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expired_approvals", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_stuck", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("purged_prompts", sa.Integer(), nullable=False, server_default="0"),
    )
    for ix in ("id", "org_id", "ran_at"):
        op.create_index(f"ix_queue_sweeps_{ix}", "queue_sweeps", [ix])


def downgrade():
    for ix in ("ran_at", "org_id", "id"):
        op.drop_index(f"ix_queue_sweeps_{ix}", table_name="queue_sweeps")
    op.drop_table("queue_sweeps")
    op.drop_index("ix_queue_settings_id", table_name="queue_settings")
    op.drop_table("queue_settings")
    op.drop_index("ix_ai_requests_org_status", table_name="ai_requests")
    op.drop_column("ai_requests", "enqueued_at")
