"""hybrid post-quantum agent signatures (Ed25519 + ML-DSA-65)

Revision ID: b7e3f1a9c2d5
Revises: a4d2c7e9b1f3
"""
from alembic import op
import sqlalchemy as sa

revision = "b7e3f1a9c2d5"
down_revision = "a4d2c7e9b1f3"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("agents", sa.Column("pq_public_key", sa.Text()))
    op.add_column("agent_signing_keys", sa.Column("pq_public_key", sa.Text()))
    for table in ("delegation_hops", "agent_actions"):
        op.add_column(table, sa.Column("pq_signature", sa.Text()))
        op.add_column(table, sa.Column("signer_pq_public_key", sa.Text()))
    op.add_column("agent_identity_settings", sa.Column(
        "require_pq_signatures", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column("agent_identity_settings", "require_pq_signatures")
    for table in ("agent_actions", "delegation_hops"):
        op.drop_column(table, "signer_pq_public_key")
        op.drop_column(table, "pq_signature")
    op.drop_column("agent_signing_keys", "pq_public_key")
    op.drop_column("agents", "pq_public_key")
