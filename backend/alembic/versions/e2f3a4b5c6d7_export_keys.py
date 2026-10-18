"""Export keys: read-only machine credentials for SIEM/SOAR

Revision ID: e2f3a4b5c6d7
Revises: d6e7f8a9b0c1

GET /api/v1/egress-sensor/events is the feed a SIEM pulls. It accepted
only an administrator's JWT, which expires in 30 minutes and needs a
person's password; an export key is a long-lived, revocable, read-only
credential of the organization instead (X-Export-Key).
"""
import sqlalchemy as sa
from alembic import op

revision = "e2f3a4b5c6d7"
down_revision = "d6e7f8a9b0c1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "export_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scope", sa.String(30), nullable=False, server_default="egress_events"),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("key_prefix", sa.String(16), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by", sa.Integer(), sa.ForeignKey("users.id")),
    )
    op.create_index("ix_export_keys_org_id", "export_keys", ["org_id"])
    op.create_index("ix_export_keys_key_hash", "export_keys", ["key_hash"], unique=True)


def downgrade():
    op.drop_index("ix_export_keys_key_hash", table_name="export_keys")
    op.drop_index("ix_export_keys_org_id", table_name="export_keys")
    op.drop_table("export_keys")
