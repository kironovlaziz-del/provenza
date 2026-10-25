"""Sensor commands signed by an administrator; pinned egress proxy binaries

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8

docs/pvp/edge.md, section 5: a command to a sensor carries the proof an
administrator signed with a passkey-certified session key
(egress_sensor_commands.proof); a sensor that follows the signed policy
runs nothing else. The manifest names the egress proxy binaries a proxy
host lets out (policy_signing_settings.proxy_binaries, SHA-256 hex). A
sensor reports what it verified itself (egress_sensors.trust).

A downgrade drops all three: commands go back to the organization's key
only, and the next release no longer names proxy binaries.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "e4f5a6b7c8d9"
down_revision = "d3e4f5a6b7c8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("egress_sensor_commands", sa.Column("proof", postgresql.JSONB()))
    op.add_column("policy_signing_settings", sa.Column("proxy_binaries", postgresql.JSONB()))
    op.add_column("egress_sensors", sa.Column("trust", postgresql.JSONB()))


def downgrade():
    op.drop_column("egress_sensors", "trust")
    op.drop_column("policy_signing_settings", "proxy_binaries")
    op.drop_column("egress_sensor_commands", "proof")
