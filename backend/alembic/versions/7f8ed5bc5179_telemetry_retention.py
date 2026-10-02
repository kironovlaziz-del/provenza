"""agent telemetry retention: settings and sweep counters

Revision ID: 7f8ed5bc5179
Revises: cbb9bd478dbe
"""
from alembic import op
import sqlalchemy as sa

revision = "7f8ed5bc5179"
down_revision = "cbb9bd478dbe"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("queue_settings", sa.Column("agent_check_retention_days", sa.Integer(), server_default="90"))
    op.add_column("queue_settings", sa.Column("agent_content_retention_days", sa.Integer(), server_default="90"))
    op.add_column("queue_sweeps", sa.Column("purged_checks", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("queue_sweeps", sa.Column("scrubbed_content", sa.Integer(), nullable=False, server_default="0"))


def downgrade():
    op.drop_column("queue_sweeps", "scrubbed_content")
    op.drop_column("queue_sweeps", "purged_checks")
    op.drop_column("queue_settings", "agent_content_retention_days")
    op.drop_column("queue_settings", "agent_check_retention_days")
