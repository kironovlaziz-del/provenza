"""ASI10 behaviour monitor: baselines, anomalies, settings

Revision ID: 2bf4e59c5621
Revises: 81764ada4536
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "2bf4e59c5621"
down_revision = "81764ada4536"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_baselines",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("computed_at", sa.DateTime(timezone=True)),
        sa.Column("window_days", sa.Integer(), nullable=False, server_default="14"),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("span_days", sa.Float(), nullable=False, server_default="0"),
        sa.Column("tools", postgresql.JSONB()),
        sa.Column("hours", postgresql.JSONB()),
        sa.Column("p95_per_5min", sa.Float(), nullable=False, server_default="0"),
        sa.Column("denial_rate", sa.Float(), nullable=False, server_default="0"),
        sa.Column("mature", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("quarantine_released_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_agent_baselines_id", "agent_baselines", ["id"])
    op.create_index("ix_agent_baselines_org_id", "agent_baselines", ["org_id"])

    op.create_table(
        "agent_anomalies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tool_name", sa.String(100)),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("signals", postgresql.JSONB(), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
    )
    op.create_index("ix_agent_anomalies_id", "agent_anomalies", ["id"])
    op.create_index("ix_agent_anomalies_org_id", "agent_anomalies", ["org_id"])
    op.create_index("ix_agent_anomalies_agent_id", "agent_anomalies", ["agent_id"])
    op.create_index("ix_agent_anomalies_detected_at", "agent_anomalies", ["detected_at"])

    op.create_table(
        "behavior_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("mode", sa.String(20), nullable=False, server_default="monitor"),
        sa.Column("threshold", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("min_samples", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("baseline_days", sa.Integer(), nullable=False, server_default="14"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_behavior_settings_id", "behavior_settings", ["id"])
    # speeds up the per-agent time-window counts the monitor runs on every check
    op.create_index("ix_agent_action_checks_agent_created", "agent_action_checks", ["agent_id", "created_at"])


def downgrade():
    op.drop_index("ix_agent_action_checks_agent_created", table_name="agent_action_checks")
    op.drop_index("ix_behavior_settings_id", table_name="behavior_settings")
    op.drop_table("behavior_settings")
    for ix in ("detected_at", "agent_id", "org_id", "id"):
        op.drop_index(f"ix_agent_anomalies_{ix}", table_name="agent_anomalies")
    op.drop_table("agent_anomalies")
    op.drop_index("ix_agent_baselines_org_id", table_name="agent_baselines")
    op.drop_index("ix_agent_baselines_id", table_name="agent_baselines")
    op.drop_table("agent_baselines")
