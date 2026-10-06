"""audit key rotation: per-organization keys, quorum-approved rotations, signed handovers

Revision ID: e3b6d9f2a4c8
Revises: d5e8a1c3f7b2

The server-wide key created by d5e8a1c3f7b2 (org_id NULL) stays in use by the
organizations whose checkpoints it already signed, until each rotates; new
organizations get their own key. audit_key_handovers is append-only like
the log (same trigger function).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e3b6d9f2a4c8"
down_revision = "d5e8a1c3f7b2"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_index("uq_audit_signing_keys_active", table_name="audit_signing_keys")
    op.add_column("audit_signing_keys", sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id")))
    op.create_index("ix_audit_signing_keys_org_id", "audit_signing_keys", ["org_id"])

    op.create_table(
        "audit_key_rotations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("old_key_id", sa.Integer(), sa.ForeignKey("audit_signing_keys.id"), nullable=False),
        sa.Column("new_key_id", sa.Integer(), sa.ForeignKey("audit_signing_keys.id"), nullable=False),
        sa.Column("proposed_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activate_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("quorum", sa.Integer(), nullable=False),
        sa.Column("eligible_admins", postgresql.JSONB(), nullable=False),
        sa.Column("reason", sa.String(500)),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("decided_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_audit_key_rotations_org_id", "audit_key_rotations", ["org_id"])
    op.create_index("uq_audit_key_rotations_pending", "audit_key_rotations", ["org_id"], unique=True,
                    postgresql_where=sa.text("status = 'pending'"))

    op.create_table(
        "audit_key_rotation_approvals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rotation_id", sa.Integer(), sa.ForeignKey("audit_key_rotations.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("rotation_id", "user_id", name="uq_audit_key_rotation_approvals_user"),
    )
    op.create_index("ix_audit_key_rotation_approvals_rotation_id", "audit_key_rotation_approvals", ["rotation_id"])

    op.create_table(
        "audit_key_handovers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("rotation_id", sa.Integer(), sa.ForeignKey("audit_key_rotations.id"), nullable=False,
                  unique=True),
        sa.Column("tree_size", sa.BigInteger(), nullable=False),
        sa.Column("root_hash", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("old_key_id", sa.Integer(), sa.ForeignKey("audit_signing_keys.id"), nullable=False),
        sa.Column("new_key_id", sa.Integer(), sa.ForeignKey("audit_signing_keys.id"), nullable=False),
        sa.Column("old_fingerprint", sa.String(80), nullable=False),
        sa.Column("new_fingerprint", sa.String(80), nullable=False),
        sa.Column("old_public_key", sa.Text(), nullable=False),
        sa.Column("old_pq_public_key", sa.Text()),
        sa.Column("new_public_key", sa.Text(), nullable=False),
        sa.Column("new_pq_public_key", sa.Text()),
        sa.Column("old_signature", sa.Text(), nullable=False),
        sa.Column("old_pq_signature", sa.Text()),
        sa.Column("new_signature", sa.Text(), nullable=False),
        sa.Column("new_pq_signature", sa.Text()),
    )
    op.create_index("ix_audit_key_handovers_org_id", "audit_key_handovers", ["org_id"])
    op.execute("CREATE TRIGGER audit_key_handovers_append_only BEFORE UPDATE OR DELETE ON audit_key_handovers "
               "FOR EACH ROW EXECUTE FUNCTION provenza_audit_append_only()")
    op.execute("CREATE TRIGGER audit_key_handovers_no_truncate BEFORE TRUNCATE ON audit_key_handovers "
               "FOR EACH STATEMENT EXECUTE FUNCTION provenza_audit_append_only()")


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS audit_key_handovers_append_only ON audit_key_handovers")
    op.execute("DROP TRIGGER IF EXISTS audit_key_handovers_no_truncate ON audit_key_handovers")
    op.drop_table("audit_key_handovers")
    op.drop_table("audit_key_rotation_approvals")
    op.drop_index("uq_audit_key_rotations_pending", table_name="audit_key_rotations")
    op.drop_table("audit_key_rotations")
    # only the server-wide key may stay active for the old one-active-key index
    op.execute("UPDATE audit_signing_keys SET active = false WHERE org_id IS NOT NULL")
    op.drop_index("ix_audit_signing_keys_org_id", table_name="audit_signing_keys")
    op.drop_column("audit_signing_keys", "org_id")
    op.create_index("uq_audit_signing_keys_active", "audit_signing_keys", ["active"], unique=True,
                    postgresql_where=sa.text("active"))
