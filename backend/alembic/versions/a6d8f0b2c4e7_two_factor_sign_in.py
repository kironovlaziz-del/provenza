"""Two-factor sign-in (TOTP): per-user secret and recovery codes, organization policy

Revision ID: a6d8f0b2c4e7
Revises: f5c7e9a1b3d4
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a6d8f0b2c4e7"
down_revision = "f5c7e9a1b3d4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("users", sa.Column("totp_secret_encrypted", sa.Text()))
    op.add_column("users", sa.Column("totp_pending_encrypted", sa.Text()))
    op.add_column("users", sa.Column("totp_last_counter", sa.BigInteger()))
    op.add_column("users", sa.Column("mfa_recovery_hashes", postgresql.JSONB()))
    op.add_column("users", sa.Column("mfa_enabled_at", sa.DateTime(timezone=True)))
    op.add_column("organizations", sa.Column("mfa_required", sa.String(10), nullable=False, server_default="none"))


def downgrade():
    op.drop_column("organizations", "mfa_required")
    for col in ("mfa_enabled_at", "mfa_recovery_hashes", "totp_last_counter", "totp_pending_encrypted",
                "totp_secret_encrypted", "totp_enabled"):
        op.drop_column("users", col)
