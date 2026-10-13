# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Workload attestation: an agent proves WHERE it runs, and agents of a role
that requires it cannot act without a fresh proof.

    agent                                   server
    -----                                   ------
    POST /agents/{id}/attestation/challenge  -> challenge (5 min, one use)
    read its projected ServiceAccount token
    sign {challenge, agent_id, sha256(token)}
      with its own signing key
    POST /agents/{id}/attestation           -> verify: the agent's signature (current,
                                               unrevoked key), then the token under
                                               the role's policy; record the result

The agent signature binds the token to this agent and this moment: a token
copied off the pod is useless without the agent's private key, and a valid
token from another workload does not pass the policy's namespace /
service-account rules. A passing attestation counts until valid_until, and
only for the policy it was made under, as that policy stood then.
"""

from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from fastapi import status
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import agent_signing as sig
from app.core import k8s_attest, oidc_attest
from app.core.errors import api_error
from app.core.outbound import guarded_async_client
from app.core.k8s_attest import AttestationError
from app.models.agent import Agent
from app.models.attestation import AgentAttestation, AttestationPolicy
from app.models.team import RoleTemplate

CHALLENGE_TTL = timedelta(minutes=5)
STATEMENT_TYPE = "provenza.agent.attestation"
KINDS = ("k8s_sa", "oidc")
BINDING_INCIDENT = "attestation_workload_changed"
JWKS_TTL_SECONDS = 3600  # discovery documents and keys: not fetched per request
_jwks_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def statement(challenge: str, agent_id: int, evidence_sha256: str, kind: str) -> Dict[str, Any]:
    """What the agent signs. Mirrors tools/provenza_sign.py attest."""
    return {"type": STATEMENT_TYPE, "v": 1, "challenge": challenge, "agent_id": agent_id, "kind": kind,
            "evidence_sha256": evidence_sha256}


# --------------------------------------------------------------------------- policies
def policy_out(p: AttestationPolicy, roles: int = 0) -> Dict[str, Any]:
    keys = (p.jwks or {}).get("keys") or []
    return {"id": p.id, "name": p.name, "description": p.description, "kind": p.kind, "issuer": p.issuer,
            "audience": p.audience, "jwks_keys": [k.get("kid") for k in keys if isinstance(k, dict)],
            "jwks_url": p.jwks_url, "namespaces": list(p.namespaces or []),
            "service_accounts": list(p.service_accounts or []), "require_pod_bound": p.require_pod_bound,
            "claim_rules": dict(p.claim_rules or {}),
            "validity_minutes": p.validity_minutes, "roles": roles,
            "updated_at": _aware(p.updated_at).isoformat() if p.updated_at else None}


def _bad(e: AttestationError):
    return api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, e.code, detail=e.detail[:200]) if e.detail \
        else api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, e.code)


def _validated(values: Dict[str, Any], current: Optional[AttestationPolicy] = None) -> Dict[str, Any]:
    out = dict(values)
    kind = out.get("kind", current.kind if current else "k8s_sa")
    if kind not in KINDS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "attestation.unsupported_kind")
    try:
        if "claim_rules" in out or (current is None and kind == "oidc"):
            out["claim_rules"] = oidc_attest.normalize_rules(out.get("claim_rules")) if kind == "oidc" else {}
        if "namespaces" in out:
            out["namespaces"] = k8s_attest.normalize_patterns(out["namespaces"], with_slash=False)
        if "service_accounts" in out:
            out["service_accounts"] = k8s_attest.normalize_patterns(out["service_accounts"], with_slash=True)
        if out.get("jwks") is not None:
            out["jwks"] = k8s_attest.check_jwks(out["jwks"])
    except AttestationError as e:
        raise _bad(e)
    if current is None:
        out["audience"] = out.get("audience") or "provenza"
        if not out.get("issuer"):
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "attestation.issuer_required")
    if kind == "k8s_sa":
        ns = out.get("namespaces", current.namespaces if current else [])
        sas = out.get("service_accounts", current.service_accounts if current else [])
        if not ns and not sas:
            # without either rule, any workload of the cluster would pass
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "attestation.no_workload_rule")
        try:
            k8s_attest.check_audience(out.get("audience", current.audience if current else "provenza"),
                                      out.get("issuer", current.issuer if current else ""))
        except AttestationError as e:
            raise _bad(e)
    for k in ("issuer", "jwks_url"):
        v = out.get(k)
        if v and not str(v).startswith("https://"):
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "attestation.https_required", field=k)
    return out


async def list_policies(db: AsyncSession, org_id: int) -> List[Dict[str, Any]]:
    rows = list((await db.execute(
        select(AttestationPolicy).where(AttestationPolicy.org_id == org_id).order_by(AttestationPolicy.name)
    )).scalars())
    counts = dict((await db.execute(
        select(RoleTemplate.attestation_policy_id, func.count()).where(
            RoleTemplate.org_id == org_id, RoleTemplate.attestation_policy_id.is_not(None))
        .group_by(RoleTemplate.attestation_policy_id))).all())
    return [policy_out(p, counts.get(p.id, 0)) for p in rows]


async def get_policy(db: AsyncSession, org_id: int, policy_id: Optional[int],
                     lock=False) -> Optional[AttestationPolicy]:
    """lock: True (changing it) or "share" (a role is being pointed at it)."""
    if policy_id is None:
        return None
    q = select(AttestationPolicy).where(AttestationPolicy.id == policy_id, AttestationPolicy.org_id == org_id)
    if lock:
        q = q.with_for_update(read=lock == "share").execution_options(populate_existing=True)
    p = (await db.execute(q)).scalar_one_or_none()
    if p is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "attestation.policy_not_found")
    return p


async def create_policy(db: AsyncSession, org_id: int, user_id: int, values: Dict[str, Any]) -> AttestationPolicy:
    values = _validated(values)
    now = _now()
    p = AttestationPolicy(org_id=org_id, created_by=user_id, created_at=now, updated_at=now, **values)
    try:
        async with db.begin_nested():  # added inside: begin_nested() flushes first
            db.add(p)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "attestation.name_taken")
    return p


async def update_policy(db: AsyncSession, org_id: int, policy_id: int, values: Dict[str, Any]) -> AttestationPolicy:
    p = await get_policy(db, org_id, policy_id, lock=True)
    # null clears only what may be empty
    values = {k: v for k, v in values.items() if v is not None or k in ("description", "jwks", "jwks_url")}
    values = _validated(values, p)
    try:
        async with db.begin_nested():
            for k, v in values.items():
                setattr(p, k, v)
            # every change re-opens the question: attestations made before no longer count
            p.updated_at = _now()
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "attestation.name_taken")
    return p


async def delete_policy(db: AsyncSession, org_id: int, policy_id: int) -> Dict[str, Any]:
    p = await get_policy(db, org_id, policy_id, lock=True)
    roles = (await db.execute(select(func.count()).select_from(RoleTemplate).where(
        RoleTemplate.org_id == org_id, RoleTemplate.attestation_policy_id == p.id))).scalar_one()
    if roles:
        raise api_error(status.HTTP_409_CONFLICT, "attestation.policy_in_use", roles=roles)
    if await _org_default_id(db, org_id) == p.id:
        raise api_error(status.HTTP_409_CONFLICT, "attestation.policy_is_default")
    snapshot = policy_out(p)
    await db.delete(p)
    return snapshot


# --------------------------------------------------------------------------- evidence
MAX_DOCUMENT_BYTES = 256 * 1024
MIN_REFETCH_SECONDS = 60  # an unknown key id refetches at most this often per URL
_last_refetch: Dict[str, float] = {}


async def _fetch_json(url: str) -> Dict[str, Any]:
    """GET an https JSON document: no redirects, 5 s, at most 256 KiB, through
    the outbound guard like every admin-typed address (app/core/outbound.py).
    An in-cluster issuer (https://kubernetes.default.svc) resolves to a private
    address: the operator allows it with OUTBOUND_PRIVATE_ALLOWLIST, or the
    policy carries the keys pasted in."""
    async with guarded_async_client(timeout=5.0) as client:
        async with client.stream("GET", url, headers={"Accept": "application/json"}) as r:
            r.raise_for_status()
            body = b""
            async for chunk in r.aiter_bytes():
                body += chunk
                if len(body) > MAX_DOCUMENT_BYTES:
                    raise AttestationError("attestation.jwks_unavailable", "document too large")
    doc = json.loads(body)
    if not isinstance(doc, dict):
        raise AttestationError("attestation.jwks_unavailable", "not a JSON object")
    return doc


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


async def _jwks_for(p: AttestationPolicy, refresh: bool = False) -> Dict[str, Any]:
    """The issuer's keys: pasted into the policy, or fetched over https (its
    jwks_url, else OIDC discovery on the issuer). The discovery document must
    name this issuer, and its jwks_uri must be on the issuer's host - nothing
    the admin did not configure is fetched. Both are cached for an hour."""
    if p.jwks:
        return p.jwks
    url = p.jwks_url
    try:
        if not url:
            disc = p.issuer.rstrip("/") + "/.well-known/openid-configuration"
            hit = _jwks_cache.get(disc)
            if hit and not refresh and hit[0] > time.monotonic():
                url = hit[1]["jwks_uri"]
            else:
                doc = await _fetch_json(disc)
                if str(doc.get("issuer", "")).rstrip("/") != p.issuer.rstrip("/"):
                    raise AttestationError("attestation.jwks_unavailable", "the discovery document names another issuer")
                url = doc.get("jwks_uri")
                if not isinstance(url, str) or not url.startswith("https://") or _host(url) != _host(p.issuer):
                    raise AttestationError("attestation.jwks_unavailable",
                                           "the discovery jwks_uri is not https on the issuer's host - "
                                           "paste the keys or set the JWKS URL in the policy")
                _jwks_cache[disc] = (time.monotonic() + JWKS_TTL_SECONDS, {"jwks_uri": url})
        hit = _jwks_cache.get(url)
        if hit and not refresh and hit[0] > time.monotonic():
            return hit[1]
        jwks = k8s_attest.check_jwks(await _fetch_json(url))
    except (httpx.HTTPError, ValueError) as e:  # AttestationError is a ValueError
        if isinstance(e, AttestationError):
            raise
        raise AttestationError("attestation.jwks_unavailable", type(e).__name__)
    _jwks_cache[url] = (time.monotonic() + JWKS_TTL_SECONDS, jwks)
    return jwks


async def check_evidence(p: AttestationPolicy, token: str) -> Dict[str, Any]:
    """The workload identity in `token`, if it passes policy `p`."""
    if p.kind not in KINDS:
        raise AttestationError("attestation.unsupported_kind", p.kind)

    def verify(jwks: Dict[str, Any]) -> Dict[str, Any]:
        if p.kind == "oidc":
            return oidc_attest.verify_token(token, issuer=p.issuer, audience=p.audience, jwks=jwks,
                                            rules=dict(p.claim_rules or {}))
        return k8s_attest.verify_token(token, issuer=p.issuer, audience=p.audience, jwks=jwks)

    try:
        identity = verify(await _jwks_for(p))
    except AttestationError as e:
        if e.code != "attestation.unknown_key" or p.jwks:
            raise
        # the cluster may have rotated its signing key: refetch - but not on
        # every token naming an unknown key, or anyone could make us hammer it
        key = p.jwks_url or p.issuer
        if time.monotonic() - _last_refetch.get(key, -1e9) < MIN_REFETCH_SECONDS:
            raise
        _last_refetch[key] = time.monotonic()
        identity = verify(await _jwks_for(p, refresh=True))
    if p.kind == "k8s_sa":
        k8s_attest.check_identity(identity, namespaces=list(p.namespaces or []),
                                  service_accounts=list(p.service_accounts or []), require_pod=p.require_pod_bound)
    return identity


async def dry_run(db: AsyncSession, org_id: int, policy_id: int, token: str) -> Dict[str, Any]:
    """Admin check of a token against a policy, nothing recorded: what the
    token says and whether it would pass."""
    p = await get_policy(db, org_id, policy_id)
    try:
        identity = await check_evidence(p, token)
        return {"ok": True, "identity": identity}
    except AttestationError as e:
        return {"ok": False, "reason": e.code, "detail": e.detail,
                "issuer_in_token": k8s_attest.unverified_issuer(token)}


# --------------------------------------------------------------------------- agents
async def _role(db: AsyncSession, agent: Agent) -> Optional[RoleTemplate]:
    return await db.get(RoleTemplate, agent.role_id) if agent.role_id else None


async def _locked(db: AsyncSession, agent: Agent) -> Agent:
    return (await db.execute(
        select(Agent).where(Agent.id == agent.id).with_for_update().execution_options(populate_existing=True)
    )).scalar_one()


async def _org_default_id(db: AsyncSession, org_id: int) -> Optional[int]:
    from app.models.agent_identity import AgentIdentitySettings

    return (await db.execute(select(AgentIdentitySettings.default_attestation_policy_id).where(
        AgentIdentitySettings.org_id == org_id))).scalar_one_or_none()


async def _policy_id_for(db: AsyncSession, agent: Agent) -> Tuple[Optional[int], bool]:
    """(the policy the agent attests under, whether it must): its role's
    policy, else the organization's default policy - which every agent must
    satisfy."""
    role = await _role(db, agent)
    if role is not None and role.attestation_policy_id is not None:
        return role.attestation_policy_id, bool(role.require_attestation)
    if role is not None and role.require_attestation:
        return None, True
    default = await _org_default_id(db, agent.org_id)
    return default, default is not None


async def _policy_for(db: AsyncSession, agent: Agent) -> AttestationPolicy:
    policy_id, _ = await _policy_id_for(db, agent)
    if policy_id is None:
        raise api_error(status.HTTP_409_CONFLICT, "attestation.no_policy")
    return await get_policy(db, agent.org_id, policy_id)


async def challenge(db: AsyncSession, agent: Agent) -> Dict[str, Any]:
    agent = await _locked(db, agent)
    if agent.status != "active":
        raise api_error(status.HTTP_409_CONFLICT, "delegation.agent_not_active")
    if not agent.public_key:
        raise api_error(status.HTTP_403_FORBIDDEN, "agent.key_required")
    p = await _policy_for(db, agent)
    agent.attest_challenge = secrets.token_hex(32)
    agent.attest_challenge_expires_at = _now() + CHALLENGE_TTL
    await db.commit()
    return {"agent_id": agent.id, "challenge": agent.attest_challenge, "kind": p.kind, "audience": p.audience,
            "policy": p.name, "expires_at": agent.attest_challenge_expires_at.isoformat()}


async def attest(db: AsyncSession, agent: Agent, *, challenge_value: str, kind: str, evidence: str,
                 signature: str, pq_signature: Optional[str]) -> Dict[str, Any]:
    from app.services import key_revocation
    from app.services.enrollment import _same

    # 1. under the agent's row lock: spend the challenge, check who signed
    agent = await _locked(db, agent)
    expected, expires = agent.attest_challenge, _aware(agent.attest_challenge_expires_at)
    agent.attest_challenge, agent.attest_challenge_expires_at = None, None  # spent by any attempt
    if not _same(expected, challenge_value) or expires is None or expires <= _now():
        await _refused(db, agent, "enrollment.bad_challenge")  # commits: the challenge stays spent
        raise api_error(status.HTTP_401_UNAUTHORIZED, "enrollment.bad_challenge")
    if agent.status != "active" or not agent.public_key:
        await _refused(db, agent, "delegation.agent_not_active")
        raise api_error(status.HTTP_409_CONFLICT, "delegation.agent_not_active")
    evidence = (evidence or "").strip()
    stmt = statement(challenge_value, agent.id, k8s_attest.token_sha256(evidence), kind)
    rev = await key_revocation.for_signer(db, agent.org_id, agent.public_key, agent.pq_public_key)
    if rev is not None or not sig.verify_agent_signature(stmt, signature, pq_signature, agent.public_key,
                                                         agent.pq_public_key):
        await _refused(db, agent, "attestation.bad_agent_signature",
                       {"key_revoked": rev is not None, "evidence_sha256": stmt["evidence_sha256"]})
        raise api_error(status.HTTP_401_UNAUTHORIZED, "attestation.bad_agent_signature")
    signer = sig.key_fingerprint(agent.public_key, agent.pq_public_key)
    try:
        p = await _policy_for(db, agent)
    except Exception:
        await db.commit()  # the challenge stays spent
        raise
    policy_version = _aware(p.updated_at)
    # 2. release the lock before looking at the evidence: fetching an issuer's
    #    keys can take seconds, and the kill switch must not wait for that
    await db.commit()

    now = _now()
    row = AgentAttestation(org_id=agent.org_id, agent_id=agent.id, policy_id=p.id, kind=kind, created_at=now,
                           ok=False, evidence_sha256=stmt["evidence_sha256"], signer_fingerprint=signer,
                           policy_version=policy_version)
    if kind != p.kind:
        row.reason, row.detail = "attestation.wrong_kind", f"the policy expects {p.kind}"
    else:
        try:
            identity = await check_evidence(p, evidence)
            # serialize attempts with the same token: two agents racing with
            # one copied token must not both pass the check below
            await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:h))"),
                             {"h": "provenza.attest:" + stmt["evidence_sha256"]})
            other = (await db.execute(select(AgentAttestation.agent_id).where(
                AgentAttestation.org_id == agent.org_id, AgentAttestation.evidence_sha256 == stmt["evidence_sha256"],
                AgentAttestation.agent_id != agent.id, AgentAttestation.ok.is_(True)).limit(1))).scalar_one_or_none()
            if other is not None:
                # one pod's token attests one agent: a second agent holding a
                # copy of it is exactly what attestation is meant to catch
                raise AttestationError("attestation.token_reused", f"already attested agent {other}")
            # the workload this agent is bound to: the first that passes; any
            # other workload with this agent's key is what attestation is for
            bound = await _bind(db, agent.id, identity)
            if bound is not None:
                raise AttestationError("attestation.workload_changed", f"bound to {bound}"[:200])
            row.identity = identity
            row.ok = True
            # never longer than the policy allows, and never past the token's
            # own expiry: the agent must come back with a fresh token
            row.valid_until = min(now + timedelta(minutes=p.validity_minutes),
                                  datetime.fromtimestamp(identity["exp"], timezone.utc))
        except AttestationError as e:
            row.reason, row.detail = e.code, (e.detail or "")[:500]
            if e.code == "attestation.workload_changed":
                from app.models.agent_action import AgentIncident

                row.identity = {"iss": identity.get("iss"), "sub": identity.get("sub")}
                db.add(AgentIncident(org_id=agent.org_id, agent_id=agent.id, incident_type=BINDING_INCIDENT,
                                     severity="critical", details={"bound": e.detail, "presented": row.identity}))
            if e.code == "attestation.workload_not_allowed":
                # what the token said, verified: helps the admin fix the policy
                row.identity = {"workload": e.detail}
    db.add(row)
    await db.flush()
    return attestation_out(row, p)


async def _refused(db: AsyncSession, agent: Agent, reason: str, extra: Optional[Dict[str, Any]] = None) -> None:
    """An attempt refused before its evidence was looked at: not an
    attestation record, but always an audit record (the log commits)."""
    from app.services.audit_service import AuditService

    await AuditService(db).log(agent.org_id, None, "agent", agent.id, "attestation_refused",
                               {"reason": reason, **(extra or {})})


def attestation_out(a: AgentAttestation, p: Optional[AttestationPolicy] = None) -> Dict[str, Any]:
    return {"id": a.id, "agent_id": a.agent_id, "policy_id": a.policy_id, "policy": p.name if p else None,
            "kind": a.kind, "ok": a.ok, "reason": a.reason, "detail": a.detail, "identity": a.identity,
            "created_at": _aware(a.created_at).isoformat(),
            "valid_until": _aware(a.valid_until).isoformat() if a.valid_until else None}


# --------------------------------------------------------------------------- enforcement
async def current(db: AsyncSession, agent: Agent, p: AttestationPolicy) -> Optional[AgentAttestation]:
    """The passing attestation that counts now under `p`, if any: made under
    the policy exactly as it stands (any change re-opens the question), and
    signed by the agent's current key (a revoked, rotated or re-keyed key
    takes its attestations with it)."""
    signer = sig.key_fingerprint(agent.public_key, agent.pq_public_key) if agent.public_key else None
    if signer is None:
        return None
    return (await db.execute(
        select(AgentAttestation).where(
            AgentAttestation.agent_id == agent.id, AgentAttestation.policy_id == p.id,
            AgentAttestation.ok.is_(True), AgentAttestation.valid_until > _now(),
            AgentAttestation.policy_version == p.updated_at,
            AgentAttestation.signer_fingerprint == signer,
        ).order_by(AgentAttestation.id.desc()).limit(1)
    )).scalar_one_or_none()


async def refusal(db: AsyncSession, agent: Agent) -> Optional[str]:
    """None when the agent may act; else the error code. Agents whose role
    requires attestation are concerned, and every agent when the organization
    has a default policy."""
    policy_id, required = await _policy_id_for(db, agent)
    if not required:
        return None
    if policy_id is None:
        return "agent.attestation_policy_missing"
    p = await db.get(AttestationPolicy, policy_id)
    if p is None:
        return "agent.attestation_policy_missing"
    return None if await current(db, agent, p) is not None else "agent.attestation_required"


async def status_of(db: AsyncSession, org_id: int, agent_id: int) -> Dict[str, Any]:
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id))).scalar_one_or_none()
    if agent is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "agent.not_found")
    policy_id, required = await _policy_id_for(db, agent)
    p = await db.get(AttestationPolicy, policy_id) if policy_id else None
    valid = await current(db, agent, p) if p else None
    last = (await db.execute(select(AgentAttestation).where(AgentAttestation.agent_id == agent.id)
                             .order_by(AgentAttestation.id.desc()).limit(1))).scalar_one_or_none()
    return {"required": required, "policy": policy_out(p) if p else None,
            "binding": {"issuer": agent.attested_issuer, "subject": agent.attested_subject,
                        "bound_at": _aware(agent.attested_bound_at).isoformat() if agent.attested_bound_at else None}
            if agent.attested_subject else None,
            "refusal": await refusal(db, agent),
            "current": attestation_out(valid, p) if valid else None,
            "last": attestation_out(last, await db.get(AttestationPolicy, last.policy_id) if last and last.policy_id
                                    else None) if last else None}


async def list_attestations(db: AsyncSession, org_id: int, agent_id: Optional[int] = None,
                            limit: int = 50) -> List[Dict[str, Any]]:
    q = select(AgentAttestation, Agent.name).join(Agent, Agent.id == AgentAttestation.agent_id).where(
        AgentAttestation.org_id == org_id)
    if agent_id is not None:
        q = q.where(AgentAttestation.agent_id == agent_id)
    rows = (await db.execute(q.order_by(AgentAttestation.id.desc()).limit(limit))).all()
    names = {p.id: p.name for p in (await db.execute(
        select(AttestationPolicy).where(AttestationPolicy.org_id == org_id))).scalars()}
    out = []
    for a, agent_name in rows:
        d = attestation_out(a)
        d["agent_name"] = agent_name
        d["policy"] = names.get(a.policy_id)
        out.append(d)
    return out


# --------------------------------------------------------------------------- workload binding
def _workload(identity: Dict[str, Any]) -> Tuple[str, str]:
    return str(identity.get("iss") or "")[:500], str(identity.get("sub") or "")[:500]


async def _bind(db: AsyncSession, agent_id: int, identity: Dict[str, Any]) -> Optional[str]:
    """Bind an unbound agent to this workload (atomically: two first
    attestations racing bind one). Returns the workload it is bound to when
    that is another one, else None."""
    from sqlalchemy import update

    iss, sub = _workload(identity)
    await db.execute(update(Agent).where(Agent.id == agent_id, Agent.attested_subject.is_(None)).values(
        attested_issuer=iss, attested_subject=sub, attested_bound_at=_now()))
    bound = (await db.execute(select(Agent.attested_issuer, Agent.attested_subject).where(
        Agent.id == agent_id).execution_options(populate_existing=True))).one()
    return None if (bound[0], bound[1]) == (iss, sub) else f"{bound[0]} {bound[1]}"


async def unbind(db: AsyncSession, org_id: int, agent_id: int) -> Dict[str, Any]:
    """An admin releases the binding (the agent moved): its next passing
    attestation binds it again. Its current attestations stop counting."""
    from sqlalchemy import update

    agent = (await db.execute(select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
                              .with_for_update())).scalar_one_or_none()
    if agent is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "agent.not_found")
    before = {"issuer": agent.attested_issuer, "subject": agent.attested_subject}
    agent.attested_issuer = agent.attested_subject = agent.attested_bound_at = None
    await db.execute(update(AgentAttestation).where(AgentAttestation.agent_id == agent.id,
                                                    AgentAttestation.valid_until > _now())
                     .values(valid_until=_now()))
    return before
