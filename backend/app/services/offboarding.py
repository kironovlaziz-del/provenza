# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Offboarding: a person leaves, and so does everything acting in their name.

Called when a user is deactivated - by an admin (Settings -> Users) or by the
identity provider through SCIM (app/api/scim.py):

  the user      disabled; every session ends (sessions_valid_after)
  their agents  every agent they own (owner_user_id): its API key revoked at
                once - the key stops authenticating everywhere, the egress
                proxy and permits included - and the agent suspended
  enrollments   the enrollment tokens they issued and nobody used: closed

Reactivating the user does not bring the agents back: an admin decides,
agent by agent (a new key, then reactivate). Each step is audited.
"""

import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_api_key
from app.models.agent import Agent
from app.models.enrollment import AgentEnrollment
from app.models.user import User
from app.services.audit_service import AuditService


async def offboard(db: AsyncSession, user: User, *, actor_id: Optional[int], via: str) -> Dict[str, Any]:
    """Deactivate `user` and disarm what acts for them. `via`: "admin" | "scim".
    Commits."""
    now = datetime.now(timezone.utc)
    org_id, user_id = user.org_id, user.id
    before = user.status
    user.status = "disabled"
    user.sessions_valid_after = now

    agents = (await db.execute(select(Agent).where(
        Agent.org_id == org_id, Agent.owner_user_id == user_id, Agent.status != "retired"))).scalars().all()
    disarmed: List[int] = []
    for a in agents:
        if a.api_key_revoked_at is None:
            # api_key_hash is NOT NULL + unique: the hash of a secret nobody holds
            a.api_key_hash = hash_api_key(secrets.token_urlsafe(48))
            a.previous_api_key_hash = None
            a.previous_key_expires_at = None
            a.api_key_revoked_at = now
        if a.status == "active":
            a.status = "suspended"
        disarmed.append(a.id)

    open_tokens = (await db.execute(select(AgentEnrollment).where(
        AgentEnrollment.org_id == org_id, AgentEnrollment.created_by == user_id,
        AgentEnrollment.used_at.is_(None), AgentEnrollment.revoked_at.is_(None)))).scalars().all()
    for e in open_tokens:
        e.revoked_at, e.challenge = now, None
    closed = [e.id for e in open_tokens]
    await db.commit()

    audit = AuditService(db)
    await audit.log(org_id, actor_id, "user", user_id, "offboarded",
                    {"via": via, "from": before, "agents_suspended": disarmed, "enrollments_closed": closed})
    for agent_id in disarmed:
        await audit.log(org_id, actor_id, "agent", agent_id, "suspended_with_owner",
                        {"owner_user_id": user_id, "via": via, "api_key_revoked": True})
    return {"user_id": user_id, "agents_suspended": disarmed, "enrollments_closed": closed}
