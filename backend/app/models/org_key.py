# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class OrgKey(Base):
    """An organization's data-encryption key (DEK), stored only wrapped by a
    key-encryption key (KEK): the server master key ("local"), a HashiCorp
    Vault Transit key or an AWS KMS key. See app/core/keyring.py."""

    __tablename__ = "org_keys"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    provider = Column(String(20), nullable=False)        # local, vault_transit, aws_kms
    config_public = Column(JSONB, nullable=False)         # non-secret KEK settings (shown in the UI)
    config_secret_encrypted = Column(Text)                # secret KEK settings, master-key Fernet
    wrapped_dek = Column(Text)                            # NULL once shredded
    status = Column(String(20), nullable=False)           # active, retired, shredded
    last_check_at = Column(DateTime(timezone=True))
    last_check_ok = Column(Boolean)
    last_error = Column(String(500))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    retired_at = Column(DateTime(timezone=True))
    shredded_at = Column(DateTime(timezone=True))


class ByokJob(Base):
    """A re-encryption run (enable / rotate / disable)."""

    __tablename__ = "byok_jobs"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    kind = Column(String(20), nullable=False)             # enable, rotate, disable
    target_key_id = Column(Integer, ForeignKey("org_keys.id", ondelete="SET NULL"))
    status = Column(String(20), nullable=False)           # queued, running, done, failed
    total = Column(Integer, nullable=False, default=0)
    done = Column(Integer, nullable=False, default=0)
    failed = Column(Integer, nullable=False, default=0)
    error = Column(String(500))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True))
