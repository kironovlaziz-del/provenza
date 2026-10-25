"""Passkeys and signing sessions of administrators and approvers

Revision ID: a0b1c2d3e4f5
Revises: f9a0b1c2d3e4

docs/pvp/edge.md, section 2: a person who signs (an administrator or an
approver) registers passkeys (user_passkeys: the public key only), and every
sign-in of theirs is a signing session (signing_sessions) - active, blocked
while another is open, or ended - whose browser-held key the passkey
certifies. A decision on a held agent action keeps its signed proof
(agent_action_approvals.signed).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a0b1c2d3e4f5"
down_revision = "f9a0b1c2d3e4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_passkeys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_id", sa.String(1400), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("alg", sa.Integer(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("label", sa.String(100), nullable=False),
        sa.Column("vouched_by_passkey_id", sa.Integer(), sa.ForeignKey("user_passkeys.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("credential_id"),
    )
    op.create_index("ix_user_passkeys_id", "user_passkeys", ["id"])
    op.create_index("ix_user_passkeys_org_id", "user_passkeys", ["org_id"])
    op.create_index("ix_user_passkeys_user_id", "user_passkeys", ["user_id"])
    op.create_table(
        "signing_sessions",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.Column("end_reason", sa.String(40)),
        sa.Column("ip", sa.String(64)),
        sa.Column("user_agent", sa.String(300)),
        sa.Column("public_key", sa.String(100)),
        sa.Column("certificate", postgresql.JSONB()),
        sa.Column("certified_at", sa.DateTime(timezone=True)),
        sa.Column("admitted_by", sa.String(32), sa.ForeignKey("signing_sessions.id", ondelete="SET NULL")),
        sa.Column("admission", postgresql.JSONB()),
        sa.Column("revocation", postgresql.JSONB()),
    )
    op.create_index("ix_signing_sessions_org_id", "signing_sessions", ["org_id"])
    op.create_index("ix_signing_sessions_user_id", "signing_sessions", ["user_id"])
    op.add_column("agent_action_approvals", sa.Column("signed", postgresql.JSONB()))


def downgrade():
    op.drop_column("agent_action_approvals", "signed")
    op.drop_table("signing_sessions")
    op.drop_table("user_passkeys")
