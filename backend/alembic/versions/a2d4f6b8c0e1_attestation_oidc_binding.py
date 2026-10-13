"""Runtime attestation: OIDC workload identity, an organization default policy, workload binding

Revision ID: a2d4f6b8c0e1
Revises: f1c3e5a7b9d0

  * attestation_policies.claim_rules                       - kind "oidc": {claim path: [patterns]}
  * agent_identity_settings.default_attestation_policy_id  - every agent attests under it
  * agents.attested_issuer / attested_subject / attested_bound_at
                                                           - the workload the agent is bound to
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a2d4f6b8c0e1"
down_revision = "f1c3e5a7b9d0"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("attestation_policies", sa.Column("claim_rules", postgresql.JSONB(), nullable=False,
                                                    server_default=sa.text("'{}'::jsonb")))
    op.add_column("agent_identity_settings", sa.Column(
        "default_attestation_policy_id", sa.Integer(),
        sa.ForeignKey("attestation_policies.id", ondelete="SET NULL", name="fk_identity_default_attestation_policy")))
    op.add_column("agents", sa.Column("attested_issuer", sa.String(500)))
    op.add_column("agents", sa.Column("attested_subject", sa.String(500)))
    op.add_column("agents", sa.Column("attested_bound_at", sa.DateTime(timezone=True)))
    # agents that already attested are bound to the workload of their latest passing attestation
    op.execute("""
        UPDATE agents a SET attested_issuer = x.identity->>'iss', attested_subject = x.identity->>'sub',
                            attested_bound_at = x.created_at
        FROM (SELECT DISTINCT ON (agent_id) agent_id, identity, created_at FROM agent_attestations
              WHERE ok AND identity ? 'sub' ORDER BY agent_id, id DESC) x
        WHERE a.id = x.agent_id
    """)


def downgrade():
    op.drop_column("agents", "attested_bound_at")
    op.drop_column("agents", "attested_subject")
    op.drop_column("agents", "attested_issuer")
    op.drop_constraint("fk_identity_default_attestation_policy", "agent_identity_settings", type_="foreignkey")
    op.drop_column("agent_identity_settings", "default_attestation_policy_id")
    op.drop_column("attestation_policies", "claim_rules")
