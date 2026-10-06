"""signing key revocation list; strict agent identity by default

Revision ID: a8c3e5f1b7d9
Revises: f2a7c4e9d1b3

Existing organizations move to the strict defaults too (decision recorded in
CHANGELOG): agents act only with their own key, agents without a signing key
cannot act, and agent-to-agent messages are enforced. Admins can relax each
setting again per organization; the UI warns while one is relaxed.
"""
import sqlalchemy as sa
from alembic import op

revision = "a8c3e5f1b7d9"
down_revision = "f2a7c4e9d1b3"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_key_revocations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("signing_key_id", sa.Integer(), sa.ForeignKey("agent_signing_keys.id")),
        sa.Column("fingerprint", sa.String(60), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("pq_public_key", sa.Text()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("untrusted_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("revoked_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.UniqueConstraint("org_id", "fingerprint", name="uq_agent_key_revocations_fp"),
    )
    op.create_index("ix_agent_key_revocations_org_id", "agent_key_revocations", ["org_id"])
    op.create_index("ix_agent_key_revocations_agent_id", "agent_key_revocations", ["agent_id"])
    op.execute("CREATE TRIGGER agent_key_revocations_append_only BEFORE UPDATE OR DELETE ON agent_key_revocations "
               "FOR EACH ROW EXECUTE FUNCTION provenza_audit_append_only()")
    op.execute("CREATE TRIGGER agent_key_revocations_no_truncate BEFORE TRUNCATE ON agent_key_revocations "
               "FOR EACH STATEMENT EXECUTE FUNCTION provenza_audit_append_only()")

    op.add_column("agent_identity_settings",
                  sa.Column("allow_keyless_agents", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.execute("UPDATE agent_identity_settings SET require_agent_key = true")
    op.execute("UPDATE a2a_settings SET mode = 'enforce'")


def downgrade():
    op.drop_column("agent_identity_settings", "allow_keyless_agents")
    op.execute("DROP TRIGGER IF EXISTS agent_key_revocations_append_only ON agent_key_revocations")
    op.execute("DROP TRIGGER IF EXISTS agent_key_revocations_no_truncate ON agent_key_revocations")
    op.drop_table("agent_key_revocations")
