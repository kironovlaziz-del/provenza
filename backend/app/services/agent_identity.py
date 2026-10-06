# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent identity - agents authenticate as themselves.

Every agent gets an API key at registration (only its hash is stored). An
agent sends it as the X-Agent-Key header instead of a user's Bearer token:

  * the key is accepted only on agent-acting endpoints (AGENT_ROUTES) - an
    agent key never opens an admin or UI endpoint, and never passes
    require_role();
  * the agent may act only as itself: the agent id the request names
    (body "agent_id", a2a envelope "from_agent_id", the id in
    /agents/{id}/delegate) must be the key's agent - otherwise 403 and an
    agent_impersonation_attempt incident;
  * the request runs on behalf of the agent's accountable human: its owner
    (owner_user_id) if active, else the organization's first active admin.
    request.state.agent carries the agent for anything that needs it;
  * keys rotate with a grace period (both keys work until it ends) and can
    be revoked (the agent cannot authenticate until a new key is issued);
  * with require_agent_key on, a user session can no longer call the
    agent-acting endpoints in an agent's name.
"""

import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from fastapi import HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import generate_api_key, hash_api_key
from app.models.agent import Agent
from app.models.agent_action import AgentIncident
from app.models.agent_identity import AgentIdentitySettings
from app.models.user import User

# Strict by default: agents act only with their own key, and only agents that
# can sign may act. An admin can relax either per organization (the UI warns).
DEFAULTS = {"require_agent_key": True, "rotation_grace_minutes": 60, "require_pq_signatures": False,
            "allow_keyless_agents": False, "allow_direct_registration": False}
LAST_USED_RESOLUTION = timedelta(minutes=1)
IMPERSONATION_INCIDENT = "agent_impersonation_attempt"

_P = re.escape(settings.API_V1_STR.rstrip("/"))


def _body(key: str) -> Callable[[Request, Any], Any]:
    return lambda req, body: body.get(key) if isinstance(body, dict) else None


def _envelope_from(req: Request, body: Any) -> Any:
    env = body.get("envelope") if isinstance(body, dict) else None
    return env.get("from_agent_id") if isinstance(env, dict) else None


def _path_id(req: Request, body: Any) -> Any:
    m = re.match(_P + r"/agents/(\d+)/(?:delegate|signing-key/challenge|signing-key/rotate"
                      r"|attestation/challenge|attestation)/?$", req.url.path)
    return m.group(1) if m else None


# (method, path regex, how to read the agent id the request claims to act as;
#  None = no claimed id, the key's agent is implied). bound=True routes are the
#  "agent-acting" ones a user session loses when require_agent_key is on.
AGENT_ROUTES = [
    ("POST", _P + r"/agents/actions/check/?$", _body("agent_id"), True),
    ("POST", _P + r"/agents/actions/record/?$", _body("agent_id"), True),
    ("POST", _P + r"/agents/\d+/delegate/?$", _path_id, True),
    # an agent rotating its own signing key (proof with the old and the new key)
    ("POST", _P + r"/agents/\d+/signing-key/(?:challenge|rotate)/?$", _path_id, True),
    # an agent proving where it runs (services/attestation.py)
    ("POST", _P + r"/agents/\d+/attestation(?:/challenge)?/?$", _path_id, True),
    ("POST", _P + r"/a2a/send/?$", _envelope_from, True),
    ("POST", _P + r"/a2a/receive/?$", _body("agent_id"), True),
    ("POST", _P + r"/memory/write/?$", _body("agent_id"), True),
    ("POST", _P + r"/memory/verify/?$", _body("agent_id"), True),
    ("POST", _P + r"/injection/scan/?$", None, False),
    ("POST", _P + r"/code-exec/scan/?$", None, False),
    ("GET", _P + r"/agent-identity/me/?$", None, False),
    ("POST", _P + r"/gateway/v1/.*$", None, True),
    ("GET", _P + r"/gateway/v1/.*$", None, True),
]


def claimed_id(value: Any) -> Optional[int]:
    """The agent id a request names, read the way the endpoint's int field
    will read it (pydantic's lax mode takes 5, 5.0, "5", true): checks made
    here on the raw body must not be dodged by another spelling of the id."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        try:
            f = float(value.strip())
        except ValueError:
            return None
        return int(f) if f.is_integer() else None
    return None


# routes an agent can use before it has attested: attesting itself, keeping
# its key, and asking who it is - everything else waits for the attestation
_ATTESTATION_EXEMPT = re.compile(
    _P + r"/(?:agents/\d+/attestation(?:/challenge)?|agents/\d+/signing-key/(?:challenge|rotate)"
    r"|agent-identity/me)/?$")


def match_route(request: Request):
    for method, rx, getter, bound in AGENT_ROUTES:
        if request.method == method and re.match(rx, request.url.path):
            return getter, bound
    return None


async def _json(request: Request) -> Any:
    try:
        raw = await request.body()
        if not raw:
            return None
        import json
        return json.loads(raw)
    except Exception:  # noqa: BLE001 - a non-JSON body simply carries no claimed id
        return None


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def org_settings(db: AsyncSession, org_id: int) -> dict:
    row = (await db.execute(
        select(AgentIdentitySettings).where(AgentIdentitySettings.org_id == org_id)
    )).scalar_one_or_none()
    if not row:
        return {**DEFAULTS, "source": "default"}
    return {"require_agent_key": row.require_agent_key, "rotation_grace_minutes": row.rotation_grace_minutes,
            "require_pq_signatures": bool(row.require_pq_signatures),
            "allow_keyless_agents": bool(row.allow_keyless_agents),
            "allow_direct_registration": bool(row.allow_direct_registration), "source": "org"}


async def keyless_refused(db: AsyncSession, agent: Agent) -> bool:
    """True when the agent has no signing key and the organization does not
    allow keyless agents: whatever it did could never be verified."""
    from app.services.teams import role_requires_hybrid

    if agent.public_key:
        return False
    if await role_requires_hybrid(db, agent):  # the role's key requirement beats the org's leniency
        return True
    return not (await org_settings(db, agent.org_id)).get("allow_keyless_agents")


async def pq_signature_required(db: AsyncSession, agent: Agent) -> bool:
    """True when the organization - or the agent's role template - requires
    hybrid (Ed25519 + ML-DSA-65) signatures and this agent has no hybrid key:
    an Ed25519-only key, or no signing key at all (whose records would be
    unsigned)."""
    from app.services.teams import role_requires_hybrid

    if agent.public_key and agent.pq_public_key:
        return False
    if await role_requires_hybrid(db, agent):
        return True
    return bool((await org_settings(db, agent.org_id)).get("require_pq_signatures"))


async def _accountable_user(db: AsyncSession, agent: Agent) -> Optional[User]:
    if agent.owner_user_id:
        owner = await db.get(User, agent.owner_user_id)
        if owner is not None and owner.status == "active" and owner.org_id == agent.org_id:
            return owner
    return (await db.execute(
        select(User).where(User.org_id == agent.org_id, User.role == "admin", User.status == "active")
        .order_by(User.id).limit(1)
    )).scalar_one_or_none()


def _unauthorized(detail: str = "agent_identity.invalid_key") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


async def authenticate_agent_request(request: Request, db: AsyncSession, raw_key: str,
                                     allow_inactive: bool = False) -> User:
    """X-Agent-Key path of get_current_user. `allow_inactive`: the caller
    refuses non-active agents itself (the gateway, which answers in the
    OpenAI error format and logs the refused call)."""
    route = match_route(request)
    if route is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="agent_identity.endpoint_not_for_agents")
    now = datetime.now(timezone.utc)
    h = hash_api_key(raw_key.strip())
    agent = (await db.execute(
        select(Agent).where(or_(
            Agent.api_key_hash == h,
            (Agent.previous_api_key_hash == h) & (Agent.previous_key_expires_at > now),
        ))
    )).scalars().first()
    if agent is None or agent.api_key_revoked_at is not None or agent.status == "retired":
        raise _unauthorized()
    if agent.status != "active" and not allow_inactive:
        # suspended (kill switch) or any other non-active state: the key is valid, the agent may not act
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"agent_identity.agent_inactive: the agent is {agent.status}")

    getter, _bound = route
    if getter is not None:
        claimed = getter(request, await _json(request))
        if claimed is not None and claimed_id(claimed) != agent.id:
            db.add(AgentIncident(
                org_id=agent.org_id, agent_id=agent.id, incident_type=IMPERSONATION_INCIDENT, severity="critical",
                details={"claimed_agent_id": str(claimed)[:20], "path": request.url.path},
            ))
            await db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="agent_identity.agent_mismatch: an agent key can only act as its own agent")

    # after the impersonation check, so a borrowed key still leaves its incident
    if not _ATTESTATION_EXEMPT.match(request.url.path):
        from app.services.attestation import refusal

        code = await refusal(db, agent)
        if code:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=code)

    user = await _accountable_user(db, agent)
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="agent_identity.no_accountable_user: the agent has no active owner or admin")

    last = _aware(agent.api_key_last_used_at)
    if last is None or now - last > LAST_USED_RESOLUTION:
        agent.api_key_last_used_at = now
        await db.commit()
    request.state.agent = agent
    request.state.agent_id = agent.id
    return user


async def enforce_user_session_policy(request: Request, db: AsyncSession, user: User) -> None:
    """Bearer path of get_current_user: with require_agent_key on, a user
    session may not call agent-acting endpoints."""
    route = match_route(request)
    if route is None or not route[1]:
        return
    if (await org_settings(db, user.org_id))["require_agent_key"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="agent_identity.agent_key_required: this organization requires agents to "
                                   "authenticate with their own key (X-Agent-Key)")
    # relaxed organization: a user session may act in an agent's name - but
    # not in the name of one whose role requires attestation it does not have
    getter = route[0]
    claimed = getter(request, await _json(request)) if getter is not None else None
    if claimed is not None and not _ATTESTATION_EXEMPT.match(request.url.path):
        agent_id = claimed_id(claimed)
        if agent_id is None:
            # an id we cannot read is not one the endpoint should act on either
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="agent_identity.bad_agent_id")
        agent = (await db.execute(select(Agent).where(
            Agent.id == agent_id, Agent.org_id == user.org_id))).scalar_one_or_none()
        if agent is not None:
            from app.services.attestation import refusal

            code = await refusal(db, agent)
            if code:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=code)


# ---------------------------------------------------------------------- management
class AgentIdentityService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _agent(self, org_id: int, agent_id: int) -> Agent:
        agent = (await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
        )).scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return agent

    async def save_settings(self, org_id: int, values: dict, user_id: int) -> tuple:
        row = (await self.db.execute(
            select(AgentIdentitySettings).where(AgentIdentitySettings.org_id == org_id)
        )).scalar_one_or_none()
        before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
        if row is None:
            row = AgentIdentitySettings(org_id=org_id)
            self.db.add(row)
        current = before or DEFAULTS
        values = {k: (current[k] if values.get(k) is None else values[k]) for k in DEFAULTS}
        for k in DEFAULTS:
            setattr(row, k, values[k])
        row.updated_by = user_id
        await self.db.commit()
        return before, values

    async def rotate(self, org_id: int, agent_id: int) -> dict:
        agent = await self._agent(org_id, agent_id)
        if agent.status == "retired":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A retired agent gets no new key")
        cfg = await org_settings(self.db, org_id)
        now = datetime.now(timezone.utc)
        grace = timedelta(minutes=cfg["rotation_grace_minutes"])
        raw = generate_api_key()
        if agent.api_key_revoked_at is None and grace.total_seconds() > 0:
            agent.previous_api_key_hash = agent.api_key_hash
            agent.previous_key_expires_at = now + grace
        else:
            agent.previous_api_key_hash = None
            agent.previous_key_expires_at = None
        agent.api_key_hash = hash_api_key(raw)
        agent.api_key_rotated_at = now
        agent.api_key_revoked_at = None
        await self.db.commit()
        return {"agent_id": agent.id, "api_key": raw,
                "previous_key_valid_until": agent.previous_key_expires_at}

    async def revoke(self, org_id: int, agent_id: int) -> dict:
        agent = await self._agent(org_id, agent_id)
        if agent.api_key_revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The key is already revoked")
        # api_key_hash is NOT NULL + unique: replace it with the hash of a secret nobody holds
        agent.api_key_hash = hash_api_key(secrets.token_urlsafe(48))
        agent.previous_api_key_hash = None
        agent.previous_key_expires_at = None
        agent.api_key_revoked_at = datetime.now(timezone.utc)
        await self.db.commit()
        return {"agent_id": agent.id, "revoked": True}

    async def overview(self, org_id: int) -> dict:
        now = datetime.now(timezone.utc)
        agents = (await self.db.execute(
            select(Agent).where(Agent.org_id == org_id).order_by(Agent.name)
        )).scalars().all()
        owners = {u.id: u for u in (await self.db.execute(
            select(User).where(User.org_id == org_id)
        )).scalars().all()}
        rows = []
        for a in agents:
            owner = owners.get(a.owner_user_id) if a.owner_user_id else None
            prev_until = _aware(a.previous_key_expires_at)
            rows.append({
                "agent_id": a.id, "name": a.name, "status": a.status,
                "owner": (owner.email if owner is not None and hasattr(owner, "email") else None),
                "owner_active": owner is not None and owner.status == "active",
                "has_public_key": bool(a.public_key),
                "key_last_used_at": a.api_key_last_used_at, "key_rotated_at": a.api_key_rotated_at,
                "key_revoked_at": a.api_key_revoked_at,
                "previous_key_valid_until": prev_until if prev_until and prev_until > now else None,
            })
        return {"settings": await org_settings(self.db, org_id), "agents": rows}
