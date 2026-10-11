"""PVP receipts: action evidence and seals in the signed audit log

Revision ID: f3c5e7a9b1d6
Revises: e1b3d5f7a9c4

  * agent_actions.evidence / evidence_sha256 - the action as PVP evidence at
    record time (ids, hashes, signatures - no content); set for new actions
    only: actions recorded before this revision have no receipt
  * agent_actions.seal_id + pvp_action_seals - batches of evidence hashes
    committed to the audit log as one record each (app/pvp/seal.py)
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f3c5e7a9b1d6"
down_revision = "e1b3d5f7a9c4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pvp_action_seals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("first_action_id", sa.Integer(), nullable=False),
        sa.Column("last_action_id", sa.Integer(), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("root", sa.String(64), nullable=False),
        sa.Column("audit_log_id", sa.Integer()),  # no FK to the append-only log (see the model)
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_pvp_action_seals_org_id", "pvp_action_seals", ["org_id"])
    op.add_column("agent_actions", sa.Column("evidence", postgresql.JSONB()))
    op.add_column("agent_actions", sa.Column("evidence_sha256", sa.String(64)))
    op.add_column("agent_actions", sa.Column("seal_id", sa.Integer(), sa.ForeignKey("pvp_action_seals.id")))
    # agent_actions can be large and is written on every agent action: build
    # its indexes without blocking writes (CONCURRENTLY runs outside a transaction)
    with op.get_context().autocommit_block():
        op.create_index("ix_agent_actions_seal_id", "agent_actions", ["seal_id"], postgresql_concurrently=True)
        # what the sealer looks for: evidence present, not sealed yet
        op.create_index("ix_agent_actions_unsealed", "agent_actions", ["org_id", "id"], postgresql_concurrently=True,
                        postgresql_where=sa.text("evidence_sha256 IS NOT NULL AND seal_id IS NULL"))


def downgrade():
    op.drop_index("ix_agent_actions_unsealed", table_name="agent_actions")
    op.drop_index("ix_agent_actions_seal_id", table_name="agent_actions")
    op.drop_column("agent_actions", "seal_id")
    op.drop_column("agent_actions", "evidence_sha256")
    op.drop_column("agent_actions", "evidence")
    op.drop_index("ix_pvp_action_seals_org_id", table_name="pvp_action_seals")
    op.drop_table("pvp_action_seals")
