"""Intent guardrail: an organization's classifier model

Revision ID: a7d9f1b3c5e6
Revises: f6c8e0a2b4d5

  * guardrail_settings - the connection and model that classify prompts by
                         intent, the categories, monitor / enforce, surfaces
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a7d9f1b3c5e6"
down_revision = "f6c8e0a2b4d5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "guardrail_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("provider_id", sa.Integer(), sa.ForeignKey("ai_providers.id", ondelete="SET NULL")),
        sa.Column("model", sa.String(200), nullable=False, server_default="llama-guard3"),
        sa.Column("kind", sa.String(20), nullable=False, server_default="llama_guard"),
        sa.Column("mode", sa.String(10), nullable=False, server_default="monitor"),
        sa.Column("on_error", sa.String(10), nullable=False, server_default="allow"),
        sa.Column("categories", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("blocked_categories", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("timeout_ms", sa.Integer(), nullable=False, server_default="4000"),
        sa.Column("surfaces", postgresql.JSONB(), nullable=False,
                  server_default='["playground", "gateway", "requests"]'),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade():
    op.drop_table("guardrail_settings")
