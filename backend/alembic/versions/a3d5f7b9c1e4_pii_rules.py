"""PII rules: built-in detectors on/off with mask or block, and custom patterns

Revision ID: a3d5f7b9c1e4
Revises: f1c3e5a7b9d2

Nothing changes after upgrading: with no settings row every built-in
detector stays on and masks, as before, and there are no custom rules.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a3d5f7b9c1e4"
down_revision = "f1c3e5a7b9d2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pii_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False, unique=True),
        sa.Column("builtin", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "pii_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("label", sa.String(32), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("ignore_case", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("action", sa.String(10), nullable=False, server_default="mask"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("timeouts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_timeout_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("action IN ('mask', 'block')", name="ck_pii_rules_action"),
    )
    op.create_index("ix_pii_rules_org_id", "pii_rules", ["org_id"])
    op.create_index("uq_pii_rules_label", "pii_rules", ["org_id", "label"], unique=True,
                    postgresql_where=sa.text("deleted_at IS NULL"))


def downgrade():
    op.drop_index("uq_pii_rules_label", table_name="pii_rules")
    op.drop_index("ix_pii_rules_org_id", table_name="pii_rules")
    op.drop_table("pii_rules")
    op.drop_table("pii_settings")
