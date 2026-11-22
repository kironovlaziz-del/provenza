"""Audit log publication: checkpoints published outside the server

Revision ID: 5b8d1f3a7c9e
Revises: 4a7c2e9f1b3d

  * audit_publication_settings     - where and how often an organization's checkpoints are published
                                      (Sigstore Rekor, an S3 bucket with Object Lock)
                                      and its publishing key; no row means the defaults
  * audit_checkpoint_publications  - each publication and its receipt; append-only
"""
import sqlalchemy as sa
from alembic import op

revision = "5b8d1f3a7c9e"
down_revision = "4a7c2e9f1b3d"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_publication_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("interval_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("rekor_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("rekor_url", sa.String(500), nullable=False, server_default="https://rekor.sigstore.dev"),
        sa.Column("rekor_public_key", sa.Text()),
        sa.Column("rekor_last_error", sa.String(500)),
        sa.Column("rekor_last_error_at", sa.DateTime(timezone=True)),
        sa.Column("s3_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("s3_endpoint", sa.String(500)),
        sa.Column("s3_region", sa.String(50)),
        sa.Column("s3_bucket", sa.String(100)),
        sa.Column("s3_prefix", sa.String(200)),
        sa.Column("s3_access_key", sa.String(200)),
        sa.Column("s3_secret_enc", sa.Text()),
        sa.Column("s3_retention_days", sa.Integer()),
        sa.Column("s3_last_error", sa.String(500)),
        sa.Column("s3_last_error_at", sa.DateTime(timezone=True)),
        sa.Column("publish_private_key_enc", sa.Text()),
        sa.Column("publish_public_key", sa.Text()),
        sa.Column("publish_key_fingerprint", sa.String(80)),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "audit_checkpoint_publications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("checkpoint_id", sa.Integer(), sa.ForeignKey("audit_checkpoints.id"), nullable=False),
        sa.Column("target", sa.String(20), nullable=False),
        sa.Column("destination", sa.String(500), nullable=False),
        sa.Column("reference", sa.String(200), nullable=False),
        sa.Column("location", sa.String(500)),
        sa.Column("log_index", sa.BigInteger()),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("receipt", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("checkpoint_id", "target", "destination", name="uq_audit_publication"),
    )
    op.create_index("ix_audit_checkpoint_publications_org_id", "audit_checkpoint_publications", ["org_id"])
    op.create_index("ix_audit_checkpoint_publications_checkpoint_id", "audit_checkpoint_publications",
                    ["checkpoint_id"])
    # append-only, like the checkpoints (the function exists since d5e8a1c3f7b2)
    op.execute("CREATE TRIGGER audit_checkpoint_publications_append_only BEFORE UPDATE OR DELETE "
               "ON audit_checkpoint_publications FOR EACH ROW EXECUTE FUNCTION provenza_audit_append_only()")
    op.execute("CREATE TRIGGER audit_checkpoint_publications_no_truncate BEFORE TRUNCATE "
               "ON audit_checkpoint_publications FOR EACH STATEMENT EXECUTE FUNCTION provenza_audit_append_only()")


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS audit_checkpoint_publications_no_truncate ON audit_checkpoint_publications")
    op.execute("DROP TRIGGER IF EXISTS audit_checkpoint_publications_append_only ON audit_checkpoint_publications")
    op.drop_index("ix_audit_checkpoint_publications_checkpoint_id", table_name="audit_checkpoint_publications")
    op.drop_index("ix_audit_checkpoint_publications_org_id", table_name="audit_checkpoint_publications")
    op.drop_table("audit_checkpoint_publications")
    op.drop_table("audit_publication_settings")
