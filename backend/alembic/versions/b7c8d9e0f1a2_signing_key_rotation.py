"""Egress sensor: previous signing key during rotation

Revision ID: b7c8d9e0f1a2
Revises: a6b7c8d9e0f1

Adds the three columns that make a rotation of the command signing key
possible without taking every sensor offline: the previous public key,
its fingerprint, and the moment it stops being valid on sensors. The
sensor keeps both keys on disk and verifies a command against either.
"""
import sqlalchemy as sa
from alembic import op

revision = "b7c8d9e0f1a2"
down_revision = "a6b7c8d9e0f1"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("egress_sensor_signing_keys", sa.Column("previous_public_key", sa.Text()))
    op.add_column("egress_sensor_signing_keys", sa.Column("previous_fingerprint", sa.String(60)))
    op.add_column("egress_sensor_signing_keys",
                  sa.Column("previous_valid_until", sa.DateTime(timezone=True)))


def downgrade():
    op.drop_column("egress_sensor_signing_keys", "previous_valid_until")
    op.drop_column("egress_sensor_signing_keys", "previous_fingerprint")
    op.drop_column("egress_sensor_signing_keys", "previous_public_key")
