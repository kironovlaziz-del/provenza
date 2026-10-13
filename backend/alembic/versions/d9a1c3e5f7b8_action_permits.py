"""Signed action permits: an organization permit key, and the permit of each check

Revision ID: d9a1c3e5f7b8
Revises: c8f0b2d4e6a7

  * permit_signing_keys                     - Ed25519 keys that sign permits (JWKS)
  * agent_action_checks.permit_jti          - the permit issued with an allowed verdict
  * agent_action_checks.permit_redeemed_at  - when a tool redeemed it (once)
"""
import sqlalchemy as sa
from alembic import op

revision = "d9a1c3e5f7b8"
down_revision = "c8f0b2d4e6a7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "permit_signing_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("kid", sa.String(64), nullable=False, unique=True),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("private_key_enc", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_permit_signing_keys_org_id", "permit_signing_keys", ["org_id"])
    op.add_column("agent_action_checks", sa.Column("permit_jti", sa.String(64)))
    op.add_column("agent_action_checks", sa.Column("permit_redeemed_at", sa.DateTime(timezone=True)))
    op.create_unique_constraint("uq_agent_action_checks_permit_jti", "agent_action_checks", ["permit_jti"])


def downgrade():
    op.drop_constraint("uq_agent_action_checks_permit_jti", "agent_action_checks", type_="unique")
    op.drop_column("agent_action_checks", "permit_redeemed_at")
    op.drop_column("agent_action_checks", "permit_jti")
    op.drop_index("ix_permit_signing_keys_org_id", table_name="permit_signing_keys")
    op.drop_table("permit_signing_keys")
