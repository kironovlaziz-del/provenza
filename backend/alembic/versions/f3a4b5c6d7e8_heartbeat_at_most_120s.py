"""Egress sensors: heartbeat at most 120 seconds

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7

Commands reach a sensor with its heartbeat and expire in five minutes, so a
heartbeat near 300 s let a command expire before the sensor asked for it.
The settings API now accepts 10-120 s (the UI offered 30, 60 and 120 only);
an organization set above that through the API gets 120.
"""
from alembic import op

revision = "f3a4b5c6d7e8"
down_revision = "e2f3a4b5c6d7"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("UPDATE egress_policy_settings SET heartbeat_seconds = 120 WHERE heartbeat_seconds > 120")


def downgrade():
    # the previous values are not kept; 120 stays valid under the old limit
    pass
