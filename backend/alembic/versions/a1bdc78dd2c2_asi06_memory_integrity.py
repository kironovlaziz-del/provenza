"""ASI06 memory integrity: RAG trust status, memory attestation

Revision ID: a1bdc78dd2c2
Revises: e5ca8c6e23e4
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "a1bdc78dd2c2"
down_revision = "e5ca8c6e23e4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("rag_documents", sa.Column("trust_status", sa.String(20), nullable=False, server_default="trusted"))
    op.add_column("rag_documents", sa.Column("trust_details", postgresql.JSONB()))
    op.add_column("rag_documents", sa.Column("trust_changed_by", sa.Integer(), sa.ForeignKey("users.id")))
    op.add_column("rag_documents", sa.Column("trust_changed_at", sa.DateTime(timezone=True)))
    op.add_column("document_chunks", sa.Column("trust_status", sa.String(20), nullable=False, server_default="trusted"))

    op.create_table(
        "memory_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("mode", sa.String(20), nullable=False, server_default="monitor"),
        sa.Column("shared_namespaces", postgresql.JSONB(), nullable=False),
        sa.Column("default_ttl_days", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_memory_settings_id", "memory_settings", ["id"])

    op.create_table(
        "memory_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("agent_id", sa.Integer(), sa.ForeignKey("agents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("chain_id", sa.Integer(), sa.ForeignKey("delegation_chains.id", ondelete="SET NULL")),
        sa.Column("namespace", sa.String(200), nullable=False),
        sa.Column("key", sa.String(200)),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("source_ref", sa.String(300)),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("reasons", postgresql.JSONB(), nullable=False),
        sa.Column("findings", postgresql.JSONB(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("decided_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("decided_at", sa.DateTime(timezone=True)),
    )
    for ix in ("id", "org_id", "agent_id", "namespace", "sha256", "created_at"):
        op.create_index(f"ix_memory_entries_{ix}", "memory_entries", [ix])


def downgrade():
    for ix in ("created_at", "sha256", "namespace", "agent_id", "org_id", "id"):
        op.drop_index(f"ix_memory_entries_{ix}", table_name="memory_entries")
    op.drop_table("memory_entries")
    op.drop_index("ix_memory_settings_id", table_name="memory_settings")
    op.drop_table("memory_settings")
    op.drop_column("document_chunks", "trust_status")
    for col in ("trust_changed_at", "trust_changed_by", "trust_details", "trust_status"):
        op.drop_column("rag_documents", col)
