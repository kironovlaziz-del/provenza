# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class SealedCredential(Base):
    """A credential sealed in the browser to one egress proxy's key
    (app/pvp/sealed.py). This server cannot open it."""

    __tablename__ = "sealed_credentials"
    __table_args__ = (UniqueConstraint("object_type", "object_id", "proxy_id", name="uq_sealed_credential"),)

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    object_type = Column(String(20), nullable=False)      # route, provider, mcp_server, a2a_peer, http_tool
    object_id = Column(Integer, nullable=False)
    proxy_id = Column(Integer, ForeignKey("egress_proxies.id", ondelete="CASCADE"), nullable=False, index=True)
    envelope = Column(JSONB, nullable=False)
    # the administrator's session-key signature over the object's envelopes
    # (provenza.credential.sealed, app/services/credentials.py): an enforcing
    # proxy opens only an envelope a signer of its signed manifest vouched for
    sealer = Column(JSONB)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
