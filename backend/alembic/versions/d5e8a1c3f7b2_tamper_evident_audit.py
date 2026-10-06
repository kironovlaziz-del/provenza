"""tamper-evident audit log: hash chain, signed checkpoints, append-only triggers

Revision ID: d5e8a1c3f7b2
Revises: c1d4e7a2b9f6

Existing records are chained in the order they were written (id), per
organization. The hashing below is a frozen copy of app/core/audit_chain.py
(record version 1) so this migration keeps producing the same hashes even if
the application code changes later; tests/test_audit_proofs.py checks the
two agree.
"""
import hashlib
import json
from datetime import timezone

import sqlalchemy as sa
from alembic import op

revision = "d5e8a1c3f7b2"
down_revision = "c1d4e7a2b9f6"
branch_labels = None
depends_on = None

GENESIS_HASH = "0" * 64

# No percent signs in this SQL (DBAPI drivers treat them as format markers).
APPEND_ONLY_FUNCTION = """
CREATE OR REPLACE FUNCTION provenza_audit_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE')
       AND coalesce(current_setting('provenza.allow_purge', true), '') = 'on' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NULL;
    END IF;
    RAISE EXCEPTION USING
        MESSAGE = 'provenza: ' || TG_TABLE_NAME || ' is append-only (' || TG_OP || ' refused)',
        ERRCODE = 'insufficient_privilege';
END
$$ LANGUAGE plpgsql
"""


def _ts(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def record_hash_v1(org_id, seq, prev_hash, created_at, actor_user_id, entity_type, entity_id, action, metadata):
    payload = {
        "v": 1,
        "org_id": int(org_id),
        "seq": int(seq),
        "prev_hash": prev_hash,
        "created_at": _ts(created_at),
        "actor_user_id": actor_user_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "action": action,
        "metadata": metadata,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _triggers(table):
    op.execute(f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
               f"FOR EACH ROW EXECUTE FUNCTION provenza_audit_append_only()")
    op.execute(f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
               f"FOR EACH STATEMENT EXECUTE FUNCTION provenza_audit_append_only()")


def upgrade():
    op.add_column("ai_audit_logs", sa.Column("seq", sa.BigInteger()))
    op.add_column("ai_audit_logs", sa.Column("prev_hash", sa.String(64)))
    op.add_column("ai_audit_logs", sa.Column("record_hash", sa.String(64)))

    conn = op.get_bind()
    # rows without a timestamp would hash with created_at = null; give them
    # the time of the migration instead, explicitly, before anything is chained
    conn.execute(sa.text("UPDATE ai_audit_logs SET created_at = now() WHERE created_at IS NULL"))
    org_ids = [r[0] for r in conn.execute(sa.text("SELECT DISTINCT org_id FROM ai_audit_logs ORDER BY org_id"))]
    upd = sa.text("UPDATE ai_audit_logs SET seq = :seq, prev_hash = :prev, record_hash = :h WHERE id = :id")
    for org_id in org_ids:
        rows = conn.execute(sa.text(
            "SELECT id, org_id, actor_user_id, entity_type, entity_id, action, metadata_json, created_at "
            "FROM ai_audit_logs WHERE org_id = :org ORDER BY id"), {"org": org_id}).mappings().all()
        prev, batch = GENESIS_HASH, []
        for seq, r in enumerate(rows, start=1):
            h = record_hash_v1(r["org_id"], seq, prev, r["created_at"], r["actor_user_id"], r["entity_type"],
                               r["entity_id"], r["action"], r["metadata_json"])
            batch.append({"seq": seq, "prev": prev, "h": h, "id": r["id"]})
            prev = h
            if len(batch) >= 1000:
                conn.execute(upd, batch)
                batch = []
        if batch:
            conn.execute(upd, batch)

    op.alter_column("ai_audit_logs", "seq", nullable=False)
    op.alter_column("ai_audit_logs", "prev_hash", nullable=False)
    op.alter_column("ai_audit_logs", "record_hash", nullable=False)
    op.create_unique_constraint("uq_ai_audit_logs_org_seq", "ai_audit_logs", ["org_id", "seq"])

    op.create_table(
        "audit_signing_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("algorithm", sa.String(30), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("pq_public_key", sa.Text()),
        sa.Column("private_key_enc", sa.Text(), nullable=False),
        sa.Column("pq_seed_enc", sa.Text()),
        sa.Column("fingerprint", sa.String(80), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
    )
    op.create_index("uq_audit_signing_keys_active", "audit_signing_keys", ["active"], unique=True,
                    postgresql_where=sa.text("active"))

    op.create_table(
        "audit_checkpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("org_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("tree_size", sa.BigInteger(), nullable=False),
        sa.Column("root_hash", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.String(30), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("pq_signature", sa.Text()),
        sa.Column("key_id", sa.Integer(), sa.ForeignKey("audit_signing_keys.id"), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("pq_public_key", sa.Text()),
        sa.Column("key_fingerprint", sa.String(80), nullable=False),
        sa.UniqueConstraint("org_id", "tree_size", name="uq_audit_checkpoints_org_size"),
    )
    op.create_index("ix_audit_checkpoints_org_id", "audit_checkpoints", ["org_id"])

    op.execute(APPEND_ONLY_FUNCTION)
    _triggers("ai_audit_logs")
    _triggers("audit_checkpoints")


def downgrade():
    # Removing the protection is a deliberate act: the chain columns and the
    # checkpoints go with it.
    for table in ("audit_checkpoints", "ai_audit_logs"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_append_only ON {table}")
        op.execute(f"DROP TRIGGER IF EXISTS {table}_no_truncate ON {table}")
    op.execute("DROP FUNCTION IF EXISTS provenza_audit_append_only()")
    op.drop_table("audit_checkpoints")
    op.drop_index("uq_audit_signing_keys_active", table_name="audit_signing_keys")
    op.drop_table("audit_signing_keys")
    op.drop_constraint("uq_ai_audit_logs_org_seq", "ai_audit_logs", type_="unique")
    op.drop_column("ai_audit_logs", "record_hash")
    op.drop_column("ai_audit_logs", "prev_hash")
    op.drop_column("ai_audit_logs", "seq")
