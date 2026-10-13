"""AI provider policy of an organization: any provider, or self-hosted only

Revision ID: c8f0b2d4e6a7
Revises: c3e5a7b9d1f4

  * organizations.ai_provider_policy - any | self_hosted (services/provider_policy.py)
"""
import sqlalchemy as sa
from alembic import op

revision = "c8f0b2d4e6a7"
down_revision = "c3e5a7b9d1f4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("organizations", sa.Column("ai_provider_policy", sa.String(20), nullable=False,
                                             server_default="any"))


def downgrade():
    op.drop_column("organizations", "ai_provider_policy")
