"""OpenTelemetry export of PVP decisions, and the callers' trace context

Revision ID: 6c2e9a4d1f70
Revises: 5b8d1f3a7c9e

  * otel_export_settings           - an organization's OTLP/HTTP collector, its optional header
                                      (encrypted) and where the export has got to; no row means off
  * trace_id / span_id             - the caller's W3C trace context on agent_action_checks,
                                      agent_actions and gateway_calls (nullable; correlation only)
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "6c2e9a4d1f70"
down_revision = "5b8d1f3a7c9e"
branch_labels = None
depends_on = None

TRACED = ("agent_action_checks", "agent_actions", "gateway_calls")


def upgrade():
    op.create_table(
        "otel_export_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("endpoint", sa.String(500)),
        sa.Column("header_name", sa.String(100)),
        sa.Column("header_value_enc", sa.Text()),
        sa.Column("cursors", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(500)),
        sa.Column("last_error_at", sa.DateTime(timezone=True)),
        sa.Column("exported_total", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("config_rev", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    # nullable, no default: adding them does not rewrite the tables
    for table in TRACED:
        op.add_column(table, sa.Column("trace_id", sa.String(32)))
        op.add_column(table, sa.Column("span_id", sa.String(16)))


def downgrade():
    for table in TRACED:
        op.drop_column(table, "span_id")
        op.drop_column(table, "trace_id")
    op.drop_table("otel_export_settings")
