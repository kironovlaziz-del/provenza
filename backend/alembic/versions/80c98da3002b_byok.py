"""BYOK: organization keys and re-encryption jobs

Revision ID: 80c98da3002b
Revises: 091128c7be42
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "80c98da3002b"
down_revision = "091128c7be42"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "org_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(20), nullable=False),
        sa.Column("config_public", postgresql.JSONB(), nullable=False),
        sa.Column("config_secret_encrypted", sa.Text()),
        sa.Column("wrapped_dek", sa.Text()),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("last_check_at", sa.DateTime(timezone=True)),
        sa.Column("last_check_ok", sa.Boolean()),
        sa.Column("last_error", sa.String(500)),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("retired_at", sa.DateTime(timezone=True)),
        sa.Column("shredded_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_org_keys_id", "org_keys", ["id"])
    op.create_index("ix_org_keys_org_id", "org_keys", ["org_id"])
    # at most one active key per organization
    op.create_index("uq_org_keys_one_active", "org_keys", ["org_id"], unique=True,
                    postgresql_where=sa.text("status = 'active'"))

    op.create_table(
        "byok_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("target_key_id", sa.Integer(), sa.ForeignKey("org_keys.id", ondelete="SET NULL")),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("done", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.String(500)),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_byok_jobs_id", "byok_jobs", ["id"])
    op.create_index("ix_byok_jobs_org_id", "byok_jobs", ["org_id"])


def downgrade():
    op.drop_index("ix_byok_jobs_org_id", table_name="byok_jobs")
    op.drop_index("ix_byok_jobs_id", table_name="byok_jobs")
    op.drop_table("byok_jobs")
    op.drop_index("uq_org_keys_one_active", table_name="org_keys")
    op.drop_index("ix_org_keys_org_id", table_name="org_keys")
    op.drop_index("ix_org_keys_id", table_name="org_keys")
    op.drop_table("org_keys")
