"""Egress proxy: routes to external APIs, proxy identities, redeemed checks

Revision ID: a7c9e1f3b5d8
Revises: f3c5e7a9b1d6

Agents reach external APIs only through a Provenza egress proxy (proxy/):
  * egress_routes      - the upstreams (admin-defined) and where their credential comes from
  * egress_proxies     - deployed proxies and their keys (hash only)
  * egress_redemptions - checks a proxy redeemed, from redeem to complete
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a7c9e1f3b5d8"
down_revision = "f3c5e7a9b1d6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "egress_routes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("slug", sa.String(40), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("upstream_url", sa.String(500), nullable=False),
        sa.Column("methods", postgresql.JSONB(), nullable=False),
        sa.Column("path_prefixes", postgresql.JSONB(), nullable=False),
        sa.Column("credential_source", sa.String(10), nullable=False, server_default="none"),
        sa.Column("auth_header", sa.String(100), nullable=False, server_default="Authorization"),
        sa.Column("secret_encrypted", sa.Text()),
        sa.Column("max_body_bytes", sa.Integer(), nullable=False, server_default=str(8 * 1024 * 1024)),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "slug", name="uq_egress_routes_slug"),
    )
    op.create_index("ix_egress_routes_org_id", "egress_routes", ["org_id"])
    op.create_table(
        "egress_proxies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("key_prefix", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_egress_proxies_org_id", "egress_proxies", ["org_id"])
    op.create_index("ix_egress_proxies_key_hash", "egress_proxies", ["key_hash"])
    op.create_table(
        "egress_redemptions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("check_id", sa.Integer(), sa.ForeignKey("agent_action_checks.id"), nullable=False, unique=True),
        sa.Column("proxy_id", sa.Integer(), sa.ForeignKey("egress_proxies.id"), nullable=False),
        sa.Column("route_id", sa.Integer(), sa.ForeignKey("egress_routes.id", ondelete="SET NULL")),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("descriptor", postgresql.JSONB(), nullable=False),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("action_id", sa.Integer(), sa.ForeignKey("agent_actions.id")),
    )
    op.create_index("ix_egress_redemptions_org_id", "egress_redemptions", ["org_id"])
    op.create_index("ix_egress_redemptions_proxy_id", "egress_redemptions", ["proxy_id"])


def downgrade():
    op.drop_index("ix_egress_redemptions_proxy_id", table_name="egress_redemptions")
    op.drop_index("ix_egress_redemptions_org_id", table_name="egress_redemptions")
    op.drop_table("egress_redemptions")
    op.drop_index("ix_egress_proxies_key_hash", table_name="egress_proxies")
    op.drop_index("ix_egress_proxies_org_id", table_name="egress_proxies")
    op.drop_table("egress_proxies")
    op.drop_index("ix_egress_routes_org_id", table_name="egress_routes")
    op.drop_table("egress_routes")
