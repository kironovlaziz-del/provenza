"""Audit log witnesses: RFC 3161 time-stamps of checkpoints

Revision ID: d4a6c8e0f2b3
Revises: c2f3a4b5d6e7

  * audit_tsa_settings           - an organization's Time-Stamp Authority and what it must chain to
  * audit_checkpoint_timestamps  - verified tokens over checkpoint statements; append-only
"""
import sqlalchemy as sa
from alembic import op

revision = "d4a6c8e0f2b3"
down_revision = "c2f3a4b5d6e7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_tsa_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("trust_pem", sa.Text(), nullable=False),
        sa.Column("last_error", sa.String(500)),
        sa.Column("last_error_at", sa.DateTime(timezone=True)),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "audit_checkpoint_timestamps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("checkpoint_id", sa.Integer(), sa.ForeignKey("audit_checkpoints.id"), nullable=False),
        sa.Column("tsa_url", sa.String(500), nullable=False),
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("gen_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("serial", sa.String(64), nullable=False),
        sa.Column("tsa_subject", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("checkpoint_id", "tsa_url", name="uq_audit_checkpoint_tsa"),
    )
    op.create_index("ix_audit_checkpoint_timestamps_org_id", "audit_checkpoint_timestamps", ["org_id"])
    op.create_index("ix_audit_checkpoint_timestamps_checkpoint_id", "audit_checkpoint_timestamps", ["checkpoint_id"])
    # append-only, like the checkpoints (the function exists since d5e8a1c3f7b2)
    op.execute("CREATE TRIGGER audit_checkpoint_timestamps_append_only BEFORE UPDATE OR DELETE "
               "ON audit_checkpoint_timestamps FOR EACH ROW EXECUTE FUNCTION provenza_audit_append_only()")
    op.execute("CREATE TRIGGER audit_checkpoint_timestamps_no_truncate BEFORE TRUNCATE "
               "ON audit_checkpoint_timestamps FOR EACH STATEMENT EXECUTE FUNCTION provenza_audit_append_only()")


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS audit_checkpoint_timestamps_no_truncate ON audit_checkpoint_timestamps")
    op.execute("DROP TRIGGER IF EXISTS audit_checkpoint_timestamps_append_only ON audit_checkpoint_timestamps")
    op.drop_index("ix_audit_checkpoint_timestamps_checkpoint_id", table_name="audit_checkpoint_timestamps")
    op.drop_index("ix_audit_checkpoint_timestamps_org_id", table_name="audit_checkpoint_timestamps")
    op.drop_table("audit_checkpoint_timestamps")
    op.drop_table("audit_tsa_settings")
