# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, func

from app.core.database import Base


class AgentIdentitySettings(Base):
    """Per-organization agent-authentication settings."""

    __tablename__ = "agent_identity_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    # when on, agent-acting endpoints accept only an agent key (X-Agent-Key);
    # a user session can no longer act in an agent's name
    require_agent_key = Column(Boolean, nullable=False, default=False)
    # after a rotation the previous key keeps working this long (0 = immediately invalid)
    rotation_grace_minutes = Column(Integer, nullable=False, default=60)
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
