"""RAG query log (no question text)

Revision ID: 56f51dfda9f7
Revises: 80c98da3002b
"""
from alembic import op
import sqlalchemy as sa

revision = "56f51dfda9f7"
down_revision = "80c98da3002b"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "rag_query_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("collection_id", sa.Integer(), sa.ForeignKey("document_collections.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("provider_id", sa.Integer(), sa.ForeignKey("ai_providers.id", ondelete="SET NULL")),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("question_sha256", sa.String(64), nullable=False),
        sa.Column("question_chars", sa.Integer(), nullable=False),
        sa.Column("top_k", sa.Integer()),
        sa.Column("matches", sa.Integer(), nullable=False),
        sa.Column("top_score", sa.Float()),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    for ix in ("id", "org_id", "collection_id", "created_at"):
        op.create_index(f"ix_rag_query_logs_{ix}", "rag_query_logs", [ix])


def downgrade():
    for ix in ("created_at", "collection_id", "org_id", "id"):
        op.drop_index(f"ix_rag_query_logs_{ix}", table_name="rag_query_logs")
    op.drop_table("rag_query_logs")
