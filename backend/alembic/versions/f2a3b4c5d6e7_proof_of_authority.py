"""Proof of Authority: the release and the agent's signed request on a check; seals chained

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_action_checks", sa.Column("release_number", sa.Integer(), nullable=True))
    op.add_column("agent_action_checks", sa.Column("release_bundle_sha256", sa.String(64), nullable=True))
    op.add_column("agent_action_checks", sa.Column("requested", postgresql.JSONB(), nullable=True))
    op.add_column("pvp_action_seals", sa.Column(
        "prev_seal_id", sa.Integer(), sa.ForeignKey("pvp_action_seals.id"), nullable=True))
    op.add_column("pvp_action_seals", sa.Column("prev_root", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("pvp_action_seals", "prev_root")
    op.drop_column("pvp_action_seals", "prev_seal_id")
    op.drop_column("agent_action_checks", "requested")
    op.drop_column("agent_action_checks", "release_bundle_sha256")
    op.drop_column("agent_action_checks", "release_number")
