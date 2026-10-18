"""AI systems: assurance records (evaluations, bias tests, red teaming)

Revision ID: c6d7e8f9a0b1
Revises: b5c6d7e8f9a0

What tests an AI system went through, by whom, when and with what result;
append-only.
"""
import sqlalchemy as sa
from alembic import op

revision = "c6d7e8f9a0b1"
down_revision = "b5c6d7e8f9a0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_assurance_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("system_id", sa.Integer(), sa.ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("performed_on", sa.Date(), nullable=False),
        sa.Column("performed_by", sa.String(255)),
        sa.Column("result", sa.String(30), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("findings", sa.Text()),
        sa.Column("evidence_url", sa.String(500)),
        sa.Column("next_due", sa.Date()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ai_assurance_records_org_id", "ai_assurance_records", ["org_id"])
    op.create_index("ix_ai_assurance_records_system_id", "ai_assurance_records", ["system_id"])


def downgrade():
    op.drop_index("ix_ai_assurance_records_system_id", table_name="ai_assurance_records")
    op.drop_index("ix_ai_assurance_records_org_id", table_name="ai_assurance_records")
    op.drop_table("ai_assurance_records")
