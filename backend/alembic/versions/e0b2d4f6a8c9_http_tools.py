"""HTTP tools: APIs called through Provenza, their address and credential held here

Revision ID: e0b2d4f6a8c9
Revises: d9a1c3e5f7b8

  * http_tools - method, URL, input schema, encrypted credential, pinned digest
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e0b2d4f6a8c9"
down_revision = "d9a1c3e5f7b8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "http_tools",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("input_schema", postgresql.JSONB()),
        sa.Column("auth_header", sa.String(100), nullable=False, server_default="Authorization"),
        sa.Column("auth_secret_encrypted", sa.Text()),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("max_response_bytes", sa.Integer(), nullable=False, server_default=str(1024 * 1024)),
        sa.Column("send_permit", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("registry_entry_id", sa.Integer(),
                  sa.ForeignKey("tool_registry_entries.id", ondelete="SET NULL")),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "name", name="uq_http_tool_name"),
    )
    op.create_index("ix_http_tools_org_id", "http_tools", ["org_id"])


def downgrade():
    op.drop_index("ix_http_tools_org_id", table_name="http_tools")
    op.drop_table("http_tools")
