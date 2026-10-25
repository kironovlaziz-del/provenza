"""Signed policy releases: the policy bundle and the key manifest

Revision ID: b1c2d3e4f5a6
Revises: a0b1c2d3e4f5

docs/pvp/edge.md, section 3: a release freezes everything that decides allow
or deny (the bundle) and the keys (the manifest); a quorum of administrators
signs it with their passkeys (policy_release_signatures); the working copy of
the quorum, validity and offline time is policy_signing_settings. Nothing is
signed by this migration: until the first release is signed, decisions are
made by the working copy alone, as before.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b1c2d3e4f5a6"
down_revision = "a0b1c2d3e4f5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "policy_releases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("bundle", postgresql.JSONB(), nullable=False),
        sa.Column("bundle_sha256", sa.String(64), nullable=False),
        sa.Column("manifest", postgresql.JSONB(), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("governed_by_id", sa.Integer(), sa.ForeignKey("policy_releases.id")),
        sa.Column("changes", postgresql.JSONB()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("in_force_at", sa.DateTime(timezone=True)),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("org_id", "number", name="uq_policy_releases_number"),
    )
    op.create_index("ix_policy_releases_org_id", "policy_releases", ["org_id"])
    op.create_table(
        "policy_release_signatures",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("release_id", sa.Integer(), sa.ForeignKey("policy_releases.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("credential_id", sa.String(1400), nullable=False),
        sa.Column("statement", postgresql.JSONB(), nullable=False),
        sa.Column("assertion", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("release_id", "user_id", name="uq_policy_release_signer"),
    )
    op.create_index("ix_policy_release_signatures_org_id", "policy_release_signatures", ["org_id"])
    op.create_index("ix_policy_release_signatures_release_id", "policy_release_signatures", ["release_id"])
    op.create_table(
        "policy_signing_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("quorum", sa.Integer(), nullable=False),
        sa.Column("validity_days", sa.Integer(), nullable=False),
        sa.Column("offline_seconds", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("org_id"),
    )


def downgrade():
    op.drop_table("policy_signing_settings")
    op.drop_table("policy_release_signatures")
    op.drop_table("policy_releases")
