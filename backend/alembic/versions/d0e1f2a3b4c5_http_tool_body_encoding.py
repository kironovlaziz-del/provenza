"""HTTP tools: the body's encoding (json or form)

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
"""

import sqlalchemy as sa
from alembic import op

revision = "d0e1f2a3b4c5"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # existing tools send JSON, as before; their pinned digest does not change
    # (the definition names the encoding only when it is "form")
    op.add_column("http_tools", sa.Column("body_encoding", sa.String(8), nullable=False, server_default="json"))


def downgrade() -> None:
    op.drop_column("http_tools", "body_encoding")
