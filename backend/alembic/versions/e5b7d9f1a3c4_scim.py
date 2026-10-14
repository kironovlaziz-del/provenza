"""SCIM 2.0 provisioning: the organization's token, and users linked to the identity provider

Revision ID: e5b7d9f1a3c4
Revises: d4a6c8e0f2b3

  * scim_settings                              - bearer token (hash only), on/off, role for new users
  * users.scim_external_id / scim_managed      - the IdP's id for a user, and whether it manages them
"""
import sqlalchemy as sa
from alembic import op

revision = "e5b7d9f1a3c4"
down_revision = "d4a6c8e0f2b3"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scim_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("token_hash", sa.String(64), unique=True),
        sa.Column("token_prefix", sa.String(20)),
        sa.Column("default_role", sa.String(20), nullable=False, server_default="user"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
    )
    op.add_column("users", sa.Column("scim_external_id", sa.String(255)))
    op.add_column("users", sa.Column("scim_managed", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("users", "scim_managed")
    op.drop_column("users", "scim_external_id")
    op.drop_table("scim_settings")
