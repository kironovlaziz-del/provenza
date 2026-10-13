# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, false, func

from app.core.database import Base


class AgentIdentitySettings(Base):
    """Per-organization agent-authentication settings."""

    __tablename__ = "agent_identity_settings"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    # when on, agent-acting endpoints accept only an agent key (X-Agent-Key);
    # a user session can no longer act in an agent's name
    require_agent_key = Column(Boolean, nullable=False, default=True)
    # after a rotation the previous key keeps working this long (0 = immediately invalid)
    rotation_grace_minutes = Column(Integer, nullable=False, default=60)
    # when on, agents must have a hybrid key (Ed25519 + ML-DSA-65): no new
    # agent or key change without the post-quantum half
    require_pq_signatures = Column(Boolean, nullable=False, default=False)
    # off (default): agents join only with an admin-issued enrollment token and
    # prove possession of their key; signing keys change only with proof.
    # On: the legacy direct registration and key replacement by an admin.
    allow_direct_registration = Column(Boolean, nullable=False, default=False, server_default=false())
    # when on, an agent acts only while its latest egress check (app/services/egress_check.py)
    # found its network confined to Provenza, and is no older than egress_check_max_age_hours
    require_confined_egress = Column(Boolean, nullable=False, default=False, server_default=false())
    egress_check_max_age_hours = Column(Integer, nullable=False, default=24, server_default="24")
    updated_by = Column(Integer, ForeignKey("users.id"))
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
