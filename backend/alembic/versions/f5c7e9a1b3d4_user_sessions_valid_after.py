"""users.sessions_valid_after: a password change ends the user's other sessions

Revision ID: f5c7e9a1b3d4
Revises: e4b6d8f0a2c3
"""
import sqlalchemy as sa
from alembic import op

revision = "f5c7e9a1b3d4"
down_revision = "e4b6d8f0a2c3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("sessions_valid_after", sa.DateTime(timezone=True)))


def downgrade():
    op.drop_column("users", "sessions_valid_after")
