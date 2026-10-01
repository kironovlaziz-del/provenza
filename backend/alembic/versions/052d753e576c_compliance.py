"""compliance: attestations and reports

Revision ID: 052d753e576c
Revises: 56f51dfda9f7
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "052d753e576c"
down_revision = "56f51dfda9f7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "compliance_attestations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("requirement_id", sa.String(60), nullable=False),
        sa.Column("system_id", sa.Integer(), sa.ForeignKey("ai_systems.id", ondelete="CASCADE")),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("note", sa.Text()),
        sa.Column("evidence_url", sa.String(500)),
        sa.Column("attested_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("attested_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
    )
    for ix in ("id", "org_id", "requirement_id"):
        op.create_index(f"ix_compliance_attestations_{ix}", "compliance_attestations", [ix])

    op.create_table(
        "compliance_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("frameworks", postgresql.JSONB(), nullable=False),
        sa.Column("summary", postgresql.JSONB(), nullable=False),
        sa.Column("content", postgresql.JSONB(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    for ix in ("id", "org_id"):
        op.create_index(f"ix_compliance_reports_{ix}", "compliance_reports", [ix])


def downgrade():
    for ix in ("org_id", "id"):
        op.drop_index(f"ix_compliance_reports_{ix}", table_name="compliance_reports")
    op.drop_table("compliance_reports")
    for ix in ("requirement_id", "org_id", "id"):
        op.drop_index(f"ix_compliance_attestations_{ix}", table_name="compliance_attestations")
    op.drop_table("compliance_attestations")
