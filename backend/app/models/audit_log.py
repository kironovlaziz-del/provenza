from sqlalchemy import (DDL, BigInteger, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text,
                        UniqueConstraint, event, text)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from app.core.database import Base


class AIAuditLog(Base):
    """One audit record. Append-only: a database trigger refuses UPDATE and
    DELETE (docs/audit-proofs.md), and every record is chained to the one
    before it in its organization (seq, prev_hash, record_hash -
    app/core/audit_chain.py). Written only through AuditService.log."""

    __tablename__ = "ai_audit_logs"
    __table_args__ = (UniqueConstraint("org_id", "seq", name="uq_ai_audit_logs_org_seq"),)

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    actor_user_id = Column(Integer, ForeignKey("users.id"))
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(Integer)
    action = Column(String(50), nullable=False)
    metadata_json = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    seq = Column(BigInteger, nullable=False)
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)


class AuditSigningKey(Base):
    """An audit key: signs checkpoints. Ed25519 always, ML-DSA-65 when the
    server's `cryptography` supports it. Private halves are stored encrypted
    with the server ENCRYPTION_KEY (scripts/rotate_encryption_key.py covers
    them). Each organization gets its own key (org_id); keys created before
    per-organization keys existed have org_id NULL and stay in use by the
    organizations whose checkpoints they signed until those rotate.
    Which key signs for an organization: audit_proofs.current_key()."""

    __tablename__ = "audit_signing_keys"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    algorithm = Column(String(30), nullable=False)
    public_key = Column(Text, nullable=False)
    pq_public_key = Column(Text)
    private_key_enc = Column(Text, nullable=False)
    pq_seed_enc = Column(Text)
    fingerprint = Column(String(80), nullable=False)
    active = Column(Boolean, nullable=False, server_default="true")  # unused since per-organization keys


class AuditKeyRotation(Base):
    """A proposed change of an organization's audit key. Takes effect only
    after a quorum of admins approved it - each typing the new key's
    fingerprint as published outside Provenza - and a notice period passed.
    At most one pending rotation per organization."""

    __tablename__ = "audit_key_rotations"
    __table_args__ = (
        Index("uq_audit_key_rotations_pending", "org_id", unique=True, postgresql_where=text("status = 'pending'")),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    old_key_id = Column(Integer, ForeignKey("audit_signing_keys.id"), nullable=False)
    new_key_id = Column(Integer, ForeignKey("audit_signing_keys.id"), nullable=False)
    proposed_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    proposed_at = Column(DateTime(timezone=True), nullable=False)
    activate_after = Column(DateTime(timezone=True), nullable=False)
    quorum = Column(Integer, nullable=False)
    # the organization's active admins when it was proposed: only they can
    # approve, so promoting or creating an admin afterwards cannot make a quorum
    eligible_admins = Column(JSONB, nullable=False)
    reason = Column(String(500))
    status = Column(String(20), nullable=False, server_default="pending")  # pending / completed / cancelled
    decided_by = Column(Integer, ForeignKey("users.id"))
    decided_at = Column(DateTime(timezone=True))


class AuditKeyRotationApproval(Base):
    __tablename__ = "audit_key_rotation_approvals"
    __table_args__ = (UniqueConstraint("rotation_id", "user_id", name="uq_audit_key_rotation_approvals_user"),)

    id = Column(Integer, primary_key=True)
    rotation_id = Column(Integer, ForeignKey("audit_key_rotations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    approved_at = Column(DateTime(timezone=True), nullable=False)


class AuditKeyHandover(Base):
    """The old key's signed consent to the new one, countersigned by the new
    key (proof it exists). Append-only. Verifiers still require the new
    fingerprint from an independent source - this links it to the old one."""

    __tablename__ = "audit_key_handovers"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    rotation_id = Column(Integer, ForeignKey("audit_key_rotations.id"), nullable=False, unique=True)
    tree_size = Column(BigInteger, nullable=False)
    root_hash = Column(String(64), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    statement = Column(Text, nullable=False)
    old_key_id = Column(Integer, ForeignKey("audit_signing_keys.id"), nullable=False)
    new_key_id = Column(Integer, ForeignKey("audit_signing_keys.id"), nullable=False)
    old_fingerprint = Column(String(80), nullable=False)
    new_fingerprint = Column(String(80), nullable=False)
    old_public_key = Column(Text, nullable=False)
    old_pq_public_key = Column(Text)
    new_public_key = Column(Text, nullable=False)
    new_pq_public_key = Column(Text)
    old_signature = Column(Text, nullable=False)
    old_pq_signature = Column(Text)
    new_signature = Column(Text, nullable=False)
    new_pq_signature = Column(Text)


class AuditCheckpoint(Base):
    """A signed Merkle root over the first tree_size records of one
    organization's audit log. Append-only, like the log."""

    __tablename__ = "audit_checkpoints"
    __table_args__ = (UniqueConstraint("org_id", "tree_size", name="uq_audit_checkpoints_org_size"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    tree_size = Column(BigInteger, nullable=False)
    root_hash = Column(String(64), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False)
    statement = Column(Text, nullable=False)  # the exact canonical text that was signed
    algorithm = Column(String(30), nullable=False)
    signature = Column(Text, nullable=False)
    pq_signature = Column(Text)
    key_id = Column(Integer, ForeignKey("audit_signing_keys.id"), nullable=False)
    public_key = Column(Text, nullable=False)
    pq_public_key = Column(Text)
    key_fingerprint = Column(String(80), nullable=False)


# --- append-only enforcement ------------------------------------------------
# No percent signs in this SQL: DDL() and DBAPI drivers treat them as
# format markers. Same SQL as migration d5e8a1c3f7b2; attached here too so test databases
# built with metadata.create_all get it. Only DELETE / TRUNCATE can be let
# through, and only in a transaction that set provenza.allow_purge = 'on'
# (scripts/delete_org.py). UPDATE is never allowed.
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

APPEND_ONLY_TABLES = ("ai_audit_logs", "audit_checkpoints", "audit_key_handovers")


def append_only_triggers(table: str):
    return (
        f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
        f"FOR EACH ROW EXECUTE FUNCTION provenza_audit_append_only()",
        f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON {table} "
        f"FOR EACH STATEMENT EXECUTE FUNCTION provenza_audit_append_only()",
    )


for _table in (AIAuditLog.__table__, AuditCheckpoint.__table__, AuditKeyHandover.__table__):
    event.listen(_table, "after_create", DDL(APPEND_ONLY_FUNCTION).execute_if(dialect="postgresql"))
    for _stmt in append_only_triggers(_table.name):
        event.listen(_table, "after_create", DDL(_stmt).execute_if(dialect="postgresql"))
