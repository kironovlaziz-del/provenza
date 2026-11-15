"""Task mandates: what ended a task, signed

Revision ID: 2e5f8b0d4c6a
Revises: 1d4e7a9c3b5f
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "2e5f8b0d4c6a"
down_revision = "1d4e7a9c3b5f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("task_mandates", sa.Column("ended", postgresql.JSONB(none_as_null=True), nullable=True))


def downgrade() -> None:
    op.drop_column("task_mandates", "ended")
