# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func

from app.core.database import Base


class PVPActionSeal(Base):
    """
    A batch of recorded actions committed to the signed audit log
    (app/pvp/seal.py): the Merkle root (RFC 9162) over the evidence hashes of
    the organization's actions first_action_id..last_action_id, in id order,
    written as ONE audit record. With that record's inclusion proof and a
    signed checkpoint, every action in the batch is provable offline, while
    the audit log grows by one record per batch - not per action.
    """

    __tablename__ = "pvp_action_seals"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    first_action_id = Column(Integer, nullable=False)
    last_action_id = Column(Integer, nullable=False)
    size = Column(Integer, nullable=False)
    root = Column(String(64), nullable=False)               # hex Merkle root over the evidence hashes
    # the audit record of the seal - deliberately not a foreign key: nothing
    # may reference the append-only log in a way that changes how the
    # database guards it (a FK would answer TRUNCATE before its trigger does)
    audit_log_id = Column(Integer)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
