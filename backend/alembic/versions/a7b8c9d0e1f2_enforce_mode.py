"""Enforce mode: no action without the agent's signature and an enforcement point

Revision ID: a7b8c9d0e1f2
Revises: f5a6b7c8d9e0

docs/pvp/edge.md, section 4: the signed policy states the organization's
mode (policy_signing_settings.enforcement, observe | enforce, in the bundle).
In enforce mode an egress proxy executes an action only with the agent's
own signed request, the server's own gateways execute nothing, and the
REST check-then-act path only observes. A check records whether the
agent's signature was verified for it (agent_action_checks.agent_signed).
The egress proxy configurations a sensor lets out with the pinned binaries
(policy_signing_settings.proxy_configs, SHA-256 hex) go into the manifest.
Sealed credentials carry the sealing administrator's signature
(sealed_credentials.sealer): an enforcing proxy opens no other.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a7b8c9d0e1f2"
down_revision = "f5a6b7c8d9e0"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("policy_signing_settings", sa.Column("enforcement", sa.String(10), nullable=False,
                                                       server_default="observe"))
    op.add_column("agent_action_checks", sa.Column("agent_signed", sa.Boolean(), nullable=False,
                                                   server_default=sa.false()))
    op.add_column("policy_signing_settings", sa.Column("proxy_configs", postgresql.JSONB()))
    op.add_column("sealed_credentials", sa.Column("sealer", postgresql.JSONB()))


def downgrade():
    op.drop_column("sealed_credentials", "sealer")
    op.drop_column("policy_signing_settings", "proxy_configs")
    op.drop_column("agent_action_checks", "agent_signed")
    op.drop_column("policy_signing_settings", "enforcement")
