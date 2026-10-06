"""workload attestation (Kubernetes ServiceAccount tokens)

Revision ID: d7f9b1c3e5a8
Revises: c6e8a0b2d4f7

Roles that already have require_attestation on but no policy: their agents
are refused (agent.attestation_policy_missing) until an admin names a policy
or switches the requirement off.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d7f9b1c3e5a8"
down_revision = "c6e8a0b2d4f7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "attestation_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("kind", sa.String(20), nullable=False, server_default="k8s_sa"),
        sa.Column("issuer", sa.String(500), nullable=False),
        sa.Column("audience", sa.String(200), nullable=False, server_default="provenza"),
        sa.Column("jwks", postgresql.JSONB()),
        sa.Column("jwks_url", sa.String(500)),
        sa.Column("namespaces", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("service_accounts", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("require_pod_bound", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("validity_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("org_id", "name", name="uq_attestation_policies_org_name"),
    )
    op.create_index("ix_attestation_policies_org_id", "attestation_policies", ["org_id"])

    op.create_table(
        "agent_attestations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id"), nullable=False),
        sa.Column("policy_id", sa.Integer(), sa.ForeignKey("attestation_policies.id", ondelete="SET NULL")),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(80)),
        sa.Column("detail", sa.String(500)),
        sa.Column("identity", postgresql.JSONB()),
        sa.Column("evidence_sha256", sa.String(64)),
        sa.Column("signer_fingerprint", sa.String(200)),
        sa.Column("policy_version", sa.DateTime(timezone=True)),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_agent_attestations_org_id", "agent_attestations", ["org_id"])
    op.create_index("ix_agent_attestations_agent_id", "agent_attestations", ["agent_id"])
    op.create_index("ix_agent_attestations_policy_id", "agent_attestations", ["policy_id"])
    op.create_index("ix_agent_attestations_evidence_sha256", "agent_attestations", ["evidence_sha256"])

    op.add_column("role_templates", sa.Column("attestation_policy_id", sa.Integer(),
                                              sa.ForeignKey("attestation_policies.id")))
    op.add_column("agents", sa.Column("attest_challenge", sa.String(64)))
    op.add_column("agents", sa.Column("attest_challenge_expires_at", sa.DateTime(timezone=True)))


def downgrade():
    op.drop_column("agents", "attest_challenge_expires_at")
    op.drop_column("agents", "attest_challenge")
    op.drop_column("role_templates", "attestation_policy_id")
    op.drop_index("ix_agent_attestations_evidence_sha256", table_name="agent_attestations")
    op.drop_index("ix_agent_attestations_policy_id", table_name="agent_attestations")
    op.drop_index("ix_agent_attestations_agent_id", table_name="agent_attestations")
    op.drop_index("ix_agent_attestations_org_id", table_name="agent_attestations")
    op.drop_table("agent_attestations")
    op.drop_index("ix_attestation_policies_org_id", table_name="attestation_policies")
    op.drop_table("attestation_policies")
