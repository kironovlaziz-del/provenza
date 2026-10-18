# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, func

from app.core.database import Base


class ExportKey(Base):
    """A read-only machine credential an organization gives its SIEM/SOAR to
    pull events (X-Export-Key). A user JWT does not fit: it expires in 30
    minutes, needs a person's password and second factor, and would make the
    audit log attribute machine reads to that person.

    Only the SHA-256 of the key is stored; key_prefix is its first characters,
    so an operator can tell keys apart. Revoked, never deleted: the audit log
    refers to it.
    """

    __tablename__ = "export_keys"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    # what the key may read; one scope today
    scope = Column(String(30), nullable=False, default="egress_events", server_default="egress_events")
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_prefix = Column(String(16), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_used_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))
    revoked_by = Column(Integer, ForeignKey("users.id"))
