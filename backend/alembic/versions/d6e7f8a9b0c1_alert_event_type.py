"""Notification channels: subscribe to alert events

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0

Alertmanager webhook now fans out 'alert' events through the existing
notification channels. Add that event type to every channel that was
created before the webhook existed, so operators do not have to touch
each one by hand. Channels created after this migration inherit 'alert'
from the UI's defaults.
"""
from alembic import op


revision = "d6e7f8a9b0c1"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        UPDATE notification_channels
        SET events_json = events_json || '["alert"]'::jsonb
        WHERE NOT (events_json @> '["alert"]'::jsonb)
    """)


def downgrade():
    # Removing 'alert' from events_json is best-effort: if the operator
    # later added it back manually, we do not strip their choice. Leave
    # rows untouched on downgrade.
    pass
