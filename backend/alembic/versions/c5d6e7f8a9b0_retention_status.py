"""Egress policy settings: retention prune status

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9

Stores the outcome of the last prune per table (activity, violations) so
/metrics can expose "last pruned N seconds ago" and "last prune failed"
as gauges. The Celery workers run in their own process, so their
in-memory counters never reach /metrics; persisting the outcome here is
the reliable signal for retention health.
"""
import sqlalchemy as sa
from alembic import op

revision = "c5d6e7f8a9b0"
down_revision = "b4c5d6e7f8a9"
branch_labels = None
depends_on = None


def upgrade():
    for prefix in ("activity", "violation"):
        op.add_column(
            "egress_policy_settings",
            sa.Column(f"{prefix}_last_pruned_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.add_column(
            "egress_policy_settings",
            sa.Column(
                f"{prefix}_last_prune_rows",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
        )
        op.add_column(
            "egress_policy_settings",
            sa.Column(f"{prefix}_last_prune_error", sa.String(500), nullable=True),
        )


def downgrade():
    for prefix in ("violation", "activity"):
        op.drop_column("egress_policy_settings", f"{prefix}_last_prune_error")
        op.drop_column("egress_policy_settings", f"{prefix}_last_prune_rows")
        op.drop_column("egress_policy_settings", f"{prefix}_last_pruned_at")
