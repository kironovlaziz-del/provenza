"""The egress proxy's local kill switch and its reconciliation

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9

docs/pvp/edge.md, sections 6-7: a proxy that has not reached this server for
the signed policy's offline time stops (a local kill switch) and reports,
signed with its own key, what changed meanwhile; the quorum of the release
it held before the outage lifts it with their passkeys
(proxy_kill_switches, proxy_kill_switch_signatures). What a proxy did while
the server was unreachable comes back as ordinary actions.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f5a6b7c8d9e0"
down_revision = "e4f5a6b7c8d9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "proxy_kill_switches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("proxy_id", sa.Integer(), sa.ForeignKey("egress_proxies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engaged_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("release_before", sa.Integer(), nullable=False),
        sa.Column("report", postgresql.JSONB(), nullable=False),
        sa.Column("report_sha256", sa.String(64), nullable=False),
        sa.Column("receipt", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("lifted_at", sa.DateTime(timezone=True)),
        sa.Column("lifted_by", postgresql.JSONB()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_proxy_kill_switches_org_id", "proxy_kill_switches", ["org_id"])
    op.create_index("ix_proxy_kill_switches_proxy_id", "proxy_kill_switches", ["proxy_id"])
    op.create_table(
        "proxy_kill_switch_signatures",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("kill_switch_id", sa.Integer(), sa.ForeignKey("proxy_kill_switches.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("report_sha256", sa.String(64), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("credential_id", sa.String(1400), nullable=False),
        sa.Column("statement", postgresql.JSONB(), nullable=False),
        sa.Column("assertion", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("kill_switch_id", "report_sha256", "user_id", name="uq_kill_switch_signature"),
    )
    op.create_index("ix_proxy_kill_switch_signatures_org_id", "proxy_kill_switch_signatures", ["org_id"])
    op.create_index("ix_proxy_kill_switch_signatures_kill_switch_id", "proxy_kill_switch_signatures",
                    ["kill_switch_id"])


def downgrade():
    op.drop_table("proxy_kill_switch_signatures")
    op.drop_table("proxy_kill_switches")
