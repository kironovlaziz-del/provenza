"""ai_telemetry_events: an index on (org_id, domain, event_type) - who used an
AI service is read from the raw visits of its domain (Shadow AI, people per
sighting).

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
"""

from alembic import op

revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_ai_telemetry_events_org_domain", "ai_telemetry_events", ["org_id", "domain", "event_type"],
                    if_not_exists=True)


def downgrade() -> None:
    op.drop_index("ix_ai_telemetry_events_org_domain", table_name="ai_telemetry_events", if_exists=True)
