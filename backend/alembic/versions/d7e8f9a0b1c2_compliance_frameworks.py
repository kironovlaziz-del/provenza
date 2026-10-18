"""Organizations: the compliance frameworks they follow

Revision ID: d7e8f9a0b1c2
Revises: c6d7e8f9a0b1

NULL keeps every framework of the catalog, as before.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d7e8f9a0b1c2"
down_revision = "c6d7e8f9a0b1"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("organizations", sa.Column("compliance_frameworks", postgresql.JSONB()))


def downgrade():
    op.drop_column("organizations", "compliance_frameworks")
