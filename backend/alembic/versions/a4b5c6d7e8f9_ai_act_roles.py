"""AI systems: the organization's role under the EU AI Act

Revision ID: a4b5c6d7e8f9
Revises: f3a4b5c6d7e8

provider, deployer, importer, distributor (Art. 3), one or more per AI
system. The compliance catalog applies each obligation to the roles it
belongs to; a system without a stated role keeps all of them.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a4b5c6d7e8f9"
down_revision = "f3a4b5c6d7e8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ai_systems", sa.Column("ai_act_roles", postgresql.JSONB(), nullable=False,
                                          server_default=sa.text("'[]'::jsonb")))


def downgrade():
    op.drop_column("ai_systems", "ai_act_roles")
