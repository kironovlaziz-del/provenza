"""signing_sessions.incident_id: the incident a blocked sign-in opened

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
"""

import sqlalchemy as sa
from alembic import op

revision = "e1f2a3b4c5d6"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("signing_sessions", sa.Column(
        "incident_id", sa.Integer(), sa.ForeignKey("ai_incidents.id", ondelete="SET NULL"), nullable=True))


def downgrade() -> None:
    op.drop_column("signing_sessions", "incident_id")
