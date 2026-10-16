"""Egress sensor: command queue and the signing key that protects it

Revision ID: a6b7c8d9e0f1
Revises: f5c7d9e1b3a5

Two tables:

  * egress_sensor_signing_keys - one Ed25519 keypair per organization,
    whose private half is Fernet-encrypted with ENCRYPTION_KEY; sensors
    get the public half and verify every command against it.
  * egress_sensor_commands - a small queue of commands (detach, restart,
    dump-state) an admin can issue for one sensor; each is delivered at
    most once, acked by the sensor, and expires in five minutes.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a6b7c8d9e0f1"
down_revision = "f5c7d9e1b3a5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "egress_sensor_signing_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"),
                  nullable=False, unique=True),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("private_key_encrypted", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(60), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("rotated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_egress_sensor_signing_keys_org_id",
                    "egress_sensor_signing_keys", ["org_id"], unique=True)

    op.create_table(
        "egress_sensor_commands",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("sensor_id", sa.Integer(),
                  sa.ForeignKey("egress_sensors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("issued_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("acked_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("result", postgresql.JSONB()),
        sa.Column("error", sa.String(500)),
    )
    op.create_index("ix_egress_sensor_commands_org_id", "egress_sensor_commands", ["org_id"])
    op.create_index("ix_egress_sensor_commands_sensor_id", "egress_sensor_commands", ["sensor_id"])
    op.create_index("ix_egress_sensor_commands_status_expires",
                    "egress_sensor_commands", ["status", "expires_at"])


def downgrade():
    op.drop_index("ix_egress_sensor_commands_status_expires", table_name="egress_sensor_commands")
    op.drop_index("ix_egress_sensor_commands_sensor_id", table_name="egress_sensor_commands")
    op.drop_index("ix_egress_sensor_commands_org_id", table_name="egress_sensor_commands")
    op.drop_table("egress_sensor_commands")

    op.drop_index("ix_egress_sensor_signing_keys_org_id", table_name="egress_sensor_signing_keys")
    op.drop_table("egress_sensor_signing_keys")
