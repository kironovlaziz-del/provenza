"""Single sign-on with OpenID Connect

Revision ID: f6c8e0a2b4d5
Revises: e5b7d9f1a3c4

  * oidc_settings        - the organization's provider, client, rules (secret encrypted)
  * users.oidc_subject   - the provider account bound by the first sign-in
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f6c8e0a2b4d5"
down_revision = "e5b7d9f1a3c4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "oidc_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("issuer", sa.String(500), nullable=False),
        sa.Column("client_id", sa.String(255), nullable=False),
        sa.Column("client_secret_encrypted", sa.Text()),
        sa.Column("email_claim", sa.String(50), nullable=False, server_default="email"),
        sa.Column("allowed_domains", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("jit", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("default_role", sa.String(20), nullable=False, server_default="user"),
        sa.Column("enforce", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("require_idp_mfa", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.add_column("users", sa.Column("oidc_subject", sa.String(600)))


def downgrade():
    op.drop_column("users", "oidc_subject")
    op.drop_table("oidc_settings")
