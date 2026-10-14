# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, func

from app.core.database import Base


class ScimSettings(Base):
    """An organization's SCIM 2.0 provisioning (app/api/scim.py): the identity
    provider (Okta, Entra ID, ...) creates, updates and deactivates users with
    this bearer token. Only its hash is kept."""

    __tablename__ = "scim_settings"

    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, server_default="false")
    token_hash = Column(String(64), unique=True)
    token_prefix = Column(String(20))
    default_role = Column(String(20), nullable=False, server_default="user")   # new users from the IdP
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True))
