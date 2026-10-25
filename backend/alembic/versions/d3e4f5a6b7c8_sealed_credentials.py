"""Credentials sealed to egress proxies

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7

docs/pvp/edge.md, section 4 (app/pvp/sealed.py): credentials are sealed in
the browser to each egress proxy's X25519 key (sealed_credentials); this
server stores ciphertext it cannot open. Connections, MCP servers, A2A
peers, HTTP tools and egress routes say where their credential lives
(credential_source: none, sealed, local). A credential the server held
before stays where it was, marked "sealed" but without envelopes, until an
administrator seals it to the proxies (POST /egress/credentials/seal-legacy),
which also erases it here. Until then nothing uses it.

A downgrade cannot give the server back credentials sealed since: it never
had them. Re-enter those (or keep them local to the proxies).
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None

LEGACY = (("ai_providers", "api_key_encrypted"), ("mcp_servers", "auth_secret_encrypted"),
          ("a2a_peers", "auth_secret_encrypted"), ("http_tools", "auth_secret_encrypted"))


def upgrade():
    op.create_table(
        "sealed_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("object_type", sa.String(20), nullable=False),
        sa.Column("object_id", sa.Integer(), nullable=False),
        sa.Column("proxy_id", sa.Integer(), sa.ForeignKey("egress_proxies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("envelope", postgresql.JSONB(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("object_type", "object_id", "proxy_id", name="uq_sealed_credential"),
    )
    op.create_index("ix_sealed_credentials_org_id", "sealed_credentials", ["org_id"])
    op.create_index("ix_sealed_credentials_proxy_id", "sealed_credentials", ["proxy_id"])
    op.add_column("egress_proxies", sa.Column("encryption_key", sa.Text()))
    op.add_column("egress_proxies", sa.Column("encryption_key_signature", sa.Text()))
    for table, legacy in LEGACY:
        op.add_column(table, sa.Column("credential_source", sa.String(10), nullable=False, server_default="none"))
        op.execute(f"UPDATE {table} SET credential_source = 'sealed' WHERE {legacy} IS NOT NULL")
    op.execute("UPDATE egress_routes SET credential_source = 'sealed' WHERE credential_source = 'server'")


def downgrade():
    op.execute("UPDATE egress_routes SET credential_source = 'server' WHERE credential_source = 'sealed'")
    for table, _ in LEGACY:
        op.drop_column(table, "credential_source")
    op.drop_column("egress_proxies", "encryption_key_signature")
    op.drop_column("egress_proxies", "encryption_key")
    op.drop_table("sealed_credentials")
