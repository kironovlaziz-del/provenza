# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Revoking agent signing keys, and what revocation means for signatures.

A revocation is final and public: a row in the append-only revocation list
(agent_key_revocations) written in the same transaction as an audit record
(entity "agent_key_revocation"), so the list is covered by the signed audit
checkpoints and can be proven complete offline.

Trust over time: a signature made with a revoked key is trusted only if it
was received before `untrusted_from` - the revocation time, or earlier when
the admin states the key was compromised since an earlier moment. Signatures
made before that keep verifying: retiring a key does not void its past, and
a compromise voids exactly what came after it.

Revoking the agent's current key leaves it without a signing key: under the
default (allow_keyless_agents off) it cannot act until it gets a new one.
A revoked key can never be registered again.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import key_fingerprint
from app.core.errors import api_error
from app.models.agent import Agent, AgentKeyRevocation, AgentSigningKey


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def out(r: AgentKeyRevocation) -> Dict[str, Any]:
    return {
        "id": r.id, "agent_id": r.agent_id, "signing_key_id": r.signing_key_id, "fingerprint": r.fingerprint,
        "public_key": r.public_key, "pq_public_key": r.pq_public_key,
        "revoked_at": _aware(r.revoked_at).isoformat(), "untrusted_from": _aware(r.untrusted_from).isoformat(),
        "reason": r.reason, "revoked_by": r.revoked_by,
    }


async def revoke(db: AsyncSession, org_id: int, agent_id: int, key_id: int, user_id: int, reason: str,
                 compromised_since: Optional[datetime] = None) -> AgentKeyRevocation:
    agent = (await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id).with_for_update()
    )).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    key = (await db.execute(
        select(AgentSigningKey).where(AgentSigningKey.id == key_id, AgentSigningKey.agent_id == agent_id,
                                      AgentSigningKey.org_id == org_id)
    )).scalar_one_or_none()
    if key is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "agent.signing_key_not_found")
    fp = key_fingerprint(key.public_key, key.pq_public_key)
    if await by_fingerprint(db, org_id, fp) is not None:
        raise api_error(status.HTTP_409_CONFLICT, "agent.key_already_revoked")
    # the database's wall clock - the same clock that stamps records'
    # created_at (signed_at) - so both sides of untrusted_from agree
    now = _aware((await db.execute(select(func.clock_timestamp()))).scalar_one())
    since = _aware(compromised_since)
    if since is not None and since > now:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "agent.compromised_since_in_future")
    rev = AgentKeyRevocation(
        org_id=org_id, agent_id=agent_id, signing_key_id=key.id, fingerprint=fp, public_key=key.public_key,
        pq_public_key=key.pq_public_key, revoked_at=now, untrusted_from=min(since, now) if since else now,
        reason=reason.strip()[:500], revoked_by=user_id,
    )
    db.add(rev)
    if key.retired_at is None:
        key.retired_at = now
    # either half in use is enough: an agent may hold this Ed25519 key again
    # with a new ML-DSA half (or the other way round) - revoked means unusable
    was_current = (agent.public_key == key.public_key
                   or (key.pq_public_key is not None and agent.pq_public_key == key.pq_public_key))
    if was_current:
        agent.public_key = None
        agent.pq_public_key = None
        agent.key_origin = None
    await db.flush()
    from app.services.audit_service import AuditService

    await AuditService(db).log(org_id, user_id, "agent_key_revocation", rev.id, "signing_key_revoked", {
        "agent_id": agent_id, "fingerprint": fp, "untrusted_from": rev.untrusted_from.isoformat(),
        "reason": rev.reason, "was_current_key": was_current,
    })  # commits the revocation, the key change and the audit record together
    return rev


async def by_fingerprint(db: AsyncSession, org_id: int, fingerprint: Optional[str]) -> Optional[AgentKeyRevocation]:
    if not fingerprint:
        return None
    return (await db.execute(
        select(AgentKeyRevocation).where(AgentKeyRevocation.org_id == org_id,
                                         AgentKeyRevocation.fingerprint == fingerprint)
    )).scalar_one_or_none()


async def for_signer(db: AsyncSession, org_id: int, public_key: Optional[str],
                     pq_public_key: Optional[str] = None) -> Optional[AgentKeyRevocation]:
    """The revocation that covers a signature made with these keys: a match on
    either half counts (a revoked Ed25519 key paired with a new ML-DSA key is
    still a revoked key). Earliest untrusted_from first."""
    if not public_key:
        return None
    cond = AgentKeyRevocation.public_key == public_key
    if pq_public_key:
        cond = or_(cond, AgentKeyRevocation.pq_public_key == pq_public_key)
    return (await db.execute(
        select(AgentKeyRevocation).where(AgentKeyRevocation.org_id == org_id, cond)
        .order_by(AgentKeyRevocation.untrusted_from).limit(1)
    )).scalar_one_or_none()


async def list_for(db: AsyncSession, org_id: int, agent_id: Optional[int] = None) -> List[AgentKeyRevocation]:
    q = select(AgentKeyRevocation).where(AgentKeyRevocation.org_id == org_id)
    if agent_id is not None:
        q = q.where(AgentKeyRevocation.agent_id == agent_id)
    return list((await db.execute(q.order_by(AgentKeyRevocation.id.desc()))).scalars())


def trusted_at(rev: Optional[AgentKeyRevocation], signed_at: Optional[datetime]) -> bool:
    """Is a signature received at `signed_at` still trusted under this revocation?"""
    if rev is None:
        return True
    if signed_at is None:
        return False
    return _aware(signed_at) < _aware(rev.untrusted_from)
