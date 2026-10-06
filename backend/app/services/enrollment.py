# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent enrollment and key rotation with proof of possession (PoP).

Enrollment (an agent joins, or gets a new key after losing / revoking one):
  1. an admin issues a one-time token - bound to the organization, a rights
     template (capabilities, tools, models, depth, team) or the agent to
     re-key, and an expiry; only its hash is stored;
  2. the agent generates its own key pair and asks for a challenge
     (POST /agent-enrollment/challenge with the token);
  3. it signs the enrollment statement - the challenge, the organization,
     the enrollment id, its public key(s) and name - with the new key, both
     halves for a hybrid key, and sends it (POST /agent-enrollment/enroll);
  4. the server checks the signature over exactly that statement, then
     creates the agent with the TEMPLATE's rights (nothing the agent asks
     for) and returns its API key once. The token is spent.

A challenge is single-use and short-lived; a wrong signature spends it, and
five failed proofs spend the token.

Rotation by the agent itself (it still holds its current key):
  POST /agents/{id}/signing-key/challenge, then /signing-key/rotate with the
  rotation statement signed by the OLD key (consent) and by the NEW key
  (possession). Both proofs are stored with the new key (AgentSigningKey.proof).

Direct registration and key replacement by an admin without proof remain
only where the organization allows them (allow_direct_registration).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import agent_signing as sig
from app.core.errors import api_error
from app.core.security import generate_api_key, hash_api_key
from app.models.agent import Agent, AgentSigningKey
from app.models.enrollment import AgentEnrollment

TOKEN_PREFIX = "pvz_enr_"
CHALLENGE_TTL = timedelta(minutes=5)
MAX_FAILED_PROOFS = 5
ENROLL_TYPE = "provenza.agent.enroll"
ROTATE_TYPE = "provenza.agent.key_rotation"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def token_hash(raw: str) -> str:
    return hashlib.sha256((raw or "").strip().encode()).hexdigest()


def enroll_statement(*, challenge: str, org_id: int, enrollment_id: int, public_key: str,
                     pq_public_key: Optional[str], name: str) -> Dict[str, Any]:
    """What the new key signs to prove possession (canonical JSON)."""
    return {"type": ENROLL_TYPE, "v": 1, "challenge": challenge, "org_id": int(org_id),
            "enrollment_id": int(enrollment_id), "public_key": public_key, "pq_public_key": pq_public_key,
            "name": name}


def rotation_statement(*, challenge: str, agent_id: int, old_fingerprint: str, new_public_key: str,
                       new_pq_public_key: Optional[str]) -> Dict[str, Any]:
    """What BOTH the old key (consent) and the new key (possession) sign."""
    return {"type": ROTATE_TYPE, "v": 1, "challenge": challenge, "agent_id": int(agent_id),
            "old_key_fingerprint": old_fingerprint,
            "new_key_fingerprint": sig.key_fingerprint(new_public_key, new_pq_public_key),
            "new_public_key": new_public_key, "new_pq_public_key": new_pq_public_key}


def out(e: AgentEnrollment) -> Dict[str, Any]:
    now = _now()
    state = ("used" if e.used_at else "revoked" if e.revoked_at else
             "expired" if _aware(e.expires_at) <= now else "open")
    return {
        "id": e.id, "purpose": e.purpose, "token_prefix": e.token_prefix, "state": state,
        "created_by": e.created_by, "created_at": _aware(e.created_at).isoformat() if e.created_at else None,
        "expires_at": _aware(e.expires_at).isoformat(), "used_at": _aware(e.used_at).isoformat() if e.used_at else None,
        "agent_id": e.agent_id, "name": e.name, "owner_team": e.owner_team, "team_id": e.team_id,
        "role_id": e.role_id, "agent_type": e.agent_type,
        "capabilities": e.capabilities or [], "allowed_tools": e.allowed_tools or [],
        "allowed_models": e.allowed_models or [], "max_delegation_depth": e.max_delegation_depth,
        "require_hybrid": e.require_hybrid, "discovered_agent_id": e.discovered_agent_id,
    }


# ---------------------------------------------------------------------------
# admin side
# ---------------------------------------------------------------------------

async def issue(db: AsyncSession, org_id: int, user_id: int, values: Dict[str, Any]) -> Tuple[AgentEnrollment, str]:
    """Create a token. Returns (enrollment, raw token - shown once)."""
    purpose = values.get("purpose") or "new"
    if purpose == "new":
        from app.services.teams import template_for_enrollment

        values = await template_for_enrollment(db, org_id, values)
    if purpose == "rekey":
        agent = (await db.execute(
            select(Agent).where(Agent.id == values.get("agent_id"), Agent.org_id == org_id)
        )).scalar_one_or_none()
        if agent is None:
            raise api_error(status.HTTP_404_NOT_FOUND, "agent.not_found")
        if agent.status == "retired":
            raise api_error(status.HTTP_409_CONFLICT, "enrollment.agent_retired")
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    e = AgentEnrollment(
        org_id=org_id, purpose=purpose, token_hash=token_hash(raw), token_prefix=raw[:len(TOKEN_PREFIX) + 6],
        created_by=user_id, created_at=_now(),
        expires_at=_now() + timedelta(hours=float(values.get("ttl_hours") or 24)),
        agent_id=values.get("agent_id") if purpose == "rekey" else None,
        name=(values.get("name") or "").strip() or None, description=values.get("description"), agent_type=values.get("agent_type"),
        owner_team=values.get("owner_team"), team_id=values.get("team_id") if purpose == "new" else None,
        role_id=values.get("role_id") if purpose == "new" else None, capabilities=values.get("capabilities") or [],
        allowed_tools=values.get("allowed_tools") or [], allowed_models=values.get("allowed_models") or [],
        max_delegation_depth=3 if values.get("max_delegation_depth") is None else int(values["max_delegation_depth"]),
        require_hybrid=bool(values.get("require_hybrid")), discovered_agent_id=values.get("discovered_agent_id"),
        failed_attempts=0,
    )
    db.add(e)
    await db.flush()
    return e, raw


async def list_for(db: AsyncSession, org_id: int) -> List[AgentEnrollment]:
    return list((await db.execute(
        select(AgentEnrollment).where(AgentEnrollment.org_id == org_id).order_by(AgentEnrollment.id.desc())
    )).scalars())


async def revoke(db: AsyncSession, org_id: int, enrollment_id: int) -> AgentEnrollment:
    e = (await db.execute(
        select(AgentEnrollment).where(AgentEnrollment.id == enrollment_id, AgentEnrollment.org_id == org_id)
    )).scalar_one_or_none()
    if e is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "enrollment.not_found")
    if e.used_at is None and e.revoked_at is None:
        e.revoked_at = _now()
        e.challenge = None
    return e


# ---------------------------------------------------------------------------
# agent side (unauthenticated: the token is the credential)
# ---------------------------------------------------------------------------

async def _usable(db: AsyncSession, raw: str, lock: bool = False) -> AgentEnrollment:
    q = select(AgentEnrollment).where(AgentEnrollment.token_hash == token_hash(raw))
    if lock:
        q = q.with_for_update()
    e = (await db.execute(q)).scalar_one_or_none()
    # one answer for unknown, used, revoked and expired: nothing to probe
    if e is None or e.used_at or e.revoked_at or _aware(e.expires_at) <= _now():
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enrollment.invalid_token")
    return e


async def challenge(db: AsyncSession, raw: str) -> Dict[str, Any]:
    e = await _usable(db, raw, lock=True)
    e.challenge = secrets.token_hex(32)
    e.challenge_expires_at = _now() + CHALLENGE_TTL
    hybrid = await _pq_required(db, e.org_id, e)
    attestation = await attestation_hint(db, e)
    await db.commit()
    return {"enrollment_id": e.id, "org_id": e.org_id, "purpose": e.purpose, "challenge": e.challenge,
            "expires_at": e.challenge_expires_at.isoformat(), "name": e.name, "require_hybrid": hybrid,
            "agent_id": e.agent_id, "attestation": attestation}


async def attestation_hint(db: AsyncSession, e: AgentEnrollment) -> Optional[Dict[str, Any]]:
    """When the agent will have to attest (its role requires it): the policy
    and the audience its projected ServiceAccount token must be issued for -
    the same value in the pod spec, here and in the verifier."""
    from app.models.attestation import AttestationPolicy
    from app.models.team import RoleTemplate

    role_id = e.role_id
    if e.purpose == "rekey" and e.agent_id:
        agent = await db.get(Agent, e.agent_id)
        role_id = agent.role_id if agent is not None else None
    role = await db.get(RoleTemplate, role_id) if role_id else None
    if role is None or not role.require_attestation:
        return None
    p = await db.get(AttestationPolicy, role.attestation_policy_id) if role.attestation_policy_id else None
    return {"required": True, "policy": p.name if p else None, "kind": p.kind if p else None,
            "audience": p.audience if p else None, "validity_minutes": p.validity_minutes if p else None}


async def _pq_required(db: AsyncSession, org_id: int, e: AgentEnrollment) -> bool:
    """A hybrid key is required by the template, the organization, or - for a
    re-key - because the agent has one now (never a silent downgrade)."""
    from app.services.agent_identity import org_settings

    from app.models.team import RoleTemplate

    if e.require_hybrid or (await org_settings(db, org_id)).get("require_pq_signatures"):
        return True
    role_id = e.role_id
    if e.purpose == "rekey" and e.agent_id:
        agent = await db.get(Agent, e.agent_id)
        if agent is not None and agent.pq_public_key:
            return True
        role_id = agent.role_id if agent is not None else None
    if role_id:
        # the role as it is now (it may have changed since the token was issued)
        role = await db.get(RoleTemplate, role_id)
        return bool(role is not None and role.require_hybrid)
    return False


def _same(expected: Optional[str], given: Optional[str]) -> bool:
    """Constant-time compare that never raises on odd input."""
    if not expected or not given:
        return False
    return secrets.compare_digest(expected.encode("utf-8", "replace"), given.encode("utf-8", "replace"))


async def enroll(db: AsyncSession, raw: str, *, public_key: str, pq_public_key: Optional[str], name: Optional[str],
                 challenge_value: str, signature: str, pq_signature: Optional[str]) -> Dict[str, Any]:
    from app.services.agent_registry import AgentRegistry
    from app.services.audit_service import AuditService

    e = await _usable(db, raw, lock=True)
    # the template's name wins; otherwise the agent's (and it is part of what is signed)
    final_name = (e.name or name or "").strip()[:255]
    if e.purpose == "new" and not final_name:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "enrollment.name_required")
    # the challenge is spent by any attempt, right or wrong
    expected, expires = e.challenge, _aware(e.challenge_expires_at)
    e.challenge, e.challenge_expires_at = None, None
    if not _same(expected, challenge_value) or expires is None or expires <= _now():
        await db.commit()
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enrollment.bad_challenge")
    target = None
    if e.purpose == "rekey":
        target = (await db.execute(
            select(Agent).where(Agent.id == e.agent_id, Agent.org_id == e.org_id).with_for_update()
        )).scalar_one_or_none()
        if target is None or target.status == "retired":
            await db.commit()
            raise api_error(status.HTTP_409_CONFLICT, "enrollment.agent_retired")
    if e.role_id:
        # held until commit: the role (its rights, require_hybrid) cannot change
        # between the checks below and the agent being created with it
        from app.services.teams import get_role

        await get_role(db, e.org_id, e.role_id, lock="share")
    if await _pq_required(db, e.org_id, e) and not pq_public_key:
        await db.commit()
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "agent.pq_required")
    statement = enroll_statement(challenge=expected, org_id=e.org_id, enrollment_id=e.id, public_key=public_key,
                                 pq_public_key=pq_public_key, name=final_name)
    if not sig.verify_agent_signature(statement, signature, pq_signature, public_key, pq_public_key):
        e.failed_attempts = (e.failed_attempts or 0) + 1
        if e.failed_attempts >= MAX_FAILED_PROOFS:
            e.revoked_at = _now()
        await db.commit()
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enrollment.bad_proof")

    proof = {"kind": "enrollment" if e.purpose == "new" else "rekey", "enrollment_id": e.id,
             "statement": sig.canonical_text(statement), "signature": signature, "pq_signature": pq_signature}
    reg = AgentRegistry(db)
    try:  # a key that was ever used before is refused; the spent challenge is kept spent
        await reg.check_new_key(e.org_id, public_key, pq_public_key, agent_id=e.agent_id, allow_reuse=False)
    except Exception:
        await db.commit()
        raise
    now = _now()
    api_key = None
    if e.purpose == "new":
        api_key = generate_api_key()
        agent = Agent(
            org_id=e.org_id, name=final_name, description=e.description, agent_type=e.agent_type,
            owner_user_id=e.created_by, owner_team=e.owner_team, team_id=e.team_id, role_id=e.role_id,
            capabilities=list(e.capabilities or []),
            allowed_tools=list(e.allowed_tools or []), allowed_models=list(e.allowed_models or []),
            max_delegation_depth=e.max_delegation_depth, status="active", api_key_hash=hash_api_key(api_key),
            public_key=public_key, pq_public_key=pq_public_key, key_origin="agent",
        )
        if e.team_id:
            from app.models.team import Team

            team = await db.get(Team, e.team_id)
            if team is not None:
                agent.owner_team = team.name  # its name now, if renamed since
        if e.role_id:
            # the role as it is now: a role changed since the token was issued applies
            from app.services.teams import get_role

            role = await get_role(db, e.org_id, e.role_id)  # locked above
            if role is not None:
                agent.capabilities = list(role.capabilities or [])
                agent.allowed_tools = list(role.allowed_tools or [])
                agent.allowed_models = list(role.allowed_models or [])
                agent.max_delegation_depth = role.max_delegation_depth
        db.add(agent)
        await db.flush()
        db.add(AgentSigningKey(
            org_id=e.org_id, agent_id=agent.id, public_key=public_key, pq_public_key=pq_public_key,
            fingerprint=sig.key_fingerprint(public_key, pq_public_key), origin="agent",
            created_by=e.created_by, proof=proof,
        ))
        from app.services import kill_switch

        await kill_switch.hold_new_agent(db, agent)  # a stop covering its team or the organization holds it
        e.agent_id = agent.id
    else:
        agent = await reg.replace_key(e.agent_id, e.org_id, public_key, pq_public_key, e.created_by, proof=proof,
                                      commit=False)
        # a lost key is usually lost with the machine that held the API key too:
        # re-keying issues a new API key and the old one stops at once
        api_key = generate_api_key()
        agent.api_key_hash = hash_api_key(api_key)
        agent.previous_api_key_hash = None
        agent.previous_key_expires_at = None
        agent.api_key_revoked_at = None
        agent.api_key_rotated_at = now
    e.used_at = now
    await db.flush()
    if e.discovered_agent_id and e.purpose == "new":
        await _link_found(db, e)
    fp = sig.key_fingerprint(public_key, pq_public_key)
    await AuditService(db).log(e.org_id, e.created_by, "agent", agent.id,
                               "agent_enrolled" if e.purpose == "new" else "agent_rekeyed",
                               {"enrollment_id": e.id, "key_fingerprint": fp, "proof": "signed_challenge"})
    return {"agent_id": agent.id, "name": agent.name, "api_key": api_key, "key_fingerprint": fp,
            "algorithm": sig.scheme_of(pq_public_key), "purpose": e.purpose}


async def _link_found(db: AsyncSession, e: AgentEnrollment) -> None:
    from app.models.endpoint_device import DiscoveredAgent

    found = (await db.execute(
        select(DiscoveredAgent).where(DiscoveredAgent.id == e.discovered_agent_id,
                                      DiscoveredAgent.org_id == e.org_id)
    )).scalar_one_or_none()
    if found is not None:
        found.status, found.registered_agent_id = "registered", e.agent_id
        found.decided_by, found.decided_at = e.created_by, _now()


# ---------------------------------------------------------------------------
# rotation by the agent itself
# ---------------------------------------------------------------------------

async def _locked(db: AsyncSession, agent: Agent) -> Agent:
    """The agent row, locked and re-read: the challenge and the current key are
    judged on what the database holds now, not on an earlier read."""
    return (await db.execute(
        select(Agent).where(Agent.id == agent.id).with_for_update().execution_options(populate_existing=True)
    )).scalar_one()


async def rotation_challenge(db: AsyncSession, agent: Agent) -> Dict[str, Any]:
    agent = await _locked(db, agent)
    if agent.status != "active":
        raise api_error(status.HTTP_409_CONFLICT, "delegation.agent_not_active")
    if not agent.public_key:
        raise api_error(status.HTTP_409_CONFLICT, "agent.no_key_to_rotate")
    agent.key_challenge = secrets.token_hex(32)
    agent.key_challenge_expires_at = _now() + CHALLENGE_TTL
    await db.commit()
    return {"agent_id": agent.id, "challenge": agent.key_challenge,
            "expires_at": agent.key_challenge_expires_at.isoformat(),
            "old_key_fingerprint": sig.key_fingerprint(agent.public_key, agent.pq_public_key)}


async def rotate(db: AsyncSession, agent: Agent, *, new_public_key: str, new_pq_public_key: Optional[str],
                 challenge_value: str, old_signature: str, old_pq_signature: Optional[str],
                 new_signature: str, new_pq_signature: Optional[str]) -> Agent:
    from app.services.agent_identity import org_settings
    from app.services.agent_registry import AgentRegistry
    from app.services.audit_service import AuditService

    agent = await _locked(db, agent)
    expected, expires = agent.key_challenge, _aware(agent.key_challenge_expires_at)
    agent.key_challenge, agent.key_challenge_expires_at = None, None  # spent by any attempt
    if not _same(expected, challenge_value) or expires is None or expires <= _now():
        await db.commit()
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enrollment.bad_challenge")
    if not agent.public_key or agent.status != "active":
        await db.commit()
        raise api_error(status.HTTP_409_CONFLICT, "agent.no_key_to_rotate")
    pq_needed = bool(agent.pq_public_key) or (await org_settings(db, agent.org_id)).get("require_pq_signatures")
    if pq_needed and not new_pq_public_key:  # never a silent downgrade from hybrid
        await db.commit()
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "agent.pq_required")
    old_fp = sig.key_fingerprint(agent.public_key, agent.pq_public_key)
    statement = rotation_statement(challenge=expected, agent_id=agent.id, old_fingerprint=old_fp,
                                   new_public_key=new_public_key, new_pq_public_key=new_pq_public_key)
    old_ok = sig.verify_agent_signature(statement, old_signature, old_pq_signature, agent.public_key,
                                        agent.pq_public_key)
    new_ok = sig.verify_agent_signature(statement, new_signature, new_pq_signature, new_public_key,
                                        new_pq_public_key)
    if not (old_ok and new_ok):
        await db.commit()
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enrollment.bad_proof",
                        failed=[n for n, ok in (("old_key", old_ok), ("new_key", new_ok)) if not ok])
    proof = {"kind": "rotation", "statement": sig.canonical_text(statement), "old_key_fingerprint": old_fp,
             "old_signature": old_signature, "old_pq_signature": old_pq_signature,
             "signature": new_signature, "pq_signature": new_pq_signature}
    reg = AgentRegistry(db)
    try:
        await reg.check_new_key(agent.org_id, new_public_key, new_pq_public_key, agent_id=agent.id, allow_reuse=False)
    except Exception:
        await db.commit()
        raise
    agent = await reg.replace_key(agent.id, agent.org_id, new_public_key, new_pq_public_key, None, proof=proof,
                                  commit=False)
    await AuditService(db).log(agent.org_id, None, "agent", agent.id, "signing_key_rotated", {
        "old_key_fingerprint": old_fp, "new_key_fingerprint": sig.key_fingerprint(new_public_key, new_pq_public_key),
        "proof": "old_and_new_key_signatures",
    })
    await db.refresh(agent)  # columns updated on flush (updated_at) are reloaded for the response
    return agent
