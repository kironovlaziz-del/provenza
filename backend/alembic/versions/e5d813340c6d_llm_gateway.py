"""LLM gateway: settings, routes, calls

Revision ID: e5d813340c6d
Revises: c75c7e9a1d73
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "e5d813340c6d"
down_revision = "c75c7e9a1d73"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "gateway_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("rpm_per_agent", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("max_tokens_cap", sa.Integer(), nullable=False, server_default="4096"),
        sa.Column("blocked_terms", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("scan_output", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_gateway_settings_id", "gateway_settings", ["id"])

    op.create_table(
        "gateway_routes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("model", sa.String(200), nullable=False),
        sa.Column("provider_id", sa.Integer(), sa.ForeignKey("ai_providers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("upstream_model", sa.String(200)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_gateway_routes_id", "gateway_routes", ["id"])
    op.create_index("ix_gateway_routes_org_id", "gateway_routes", ["org_id"])

    op.create_table(
        "gateway_calls",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE")),
        sa.Column("ai_request_id", sa.Integer(), sa.ForeignKey("ai_requests.id", ondelete="SET NULL")),
        sa.Column("provider_id", sa.Integer(), sa.ForeignKey("ai_providers.id", ondelete="SET NULL")),
        sa.Column("model", sa.String(200)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("reason", sa.String(500)),
        sa.Column("flags", postgresql.JSONB(), nullable=False),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("prompt_tokens", sa.Integer()),
        sa.Column("completion_tokens", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    for ix in ("id", "org_id", "agent_id", "created_at"):
        op.create_index(f"ix_gateway_calls_{ix}", "gateway_calls", [ix])


def downgrade():
    for ix in ("created_at", "agent_id", "org_id", "id"):
        op.drop_index(f"ix_gateway_calls_{ix}", table_name="gateway_calls")
    op.drop_table("gateway_calls")
    op.drop_index("ix_gateway_routes_org_id", table_name="gateway_routes")
    op.drop_index("ix_gateway_routes_id", table_name="gateway_routes")
    op.drop_table("gateway_routes")
    op.drop_index("ix_gateway_settings_id", table_name="gateway_settings")
    op.drop_table("gateway_settings")
