# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Where the credentials of upstreams live (app/pvp/sealed.py): sealed to the
egress proxies, or only in a proxy's configuration - never readable here.

    none     the upstream takes no credential
    sealed   envelopes, one per proxy, sealed in the browser to the proxy's key
    local    only in the proxies' own configuration (local_secrets)

Credentials the server held before (encrypted with its own key) are sealed
to the proxies once by an administrator (seal_legacy) and erased; until
then nothing uses them.

An administrator signs the envelopes they seal with their session key
(provenza.credential.sealed: the object, its origin, the SHA-256 of each
proxy's envelope). A proxy that follows the signed policy opens only an
envelope an administrator of its signed manifest vouched for, so this
server cannot slip in a credential of its own choosing (an account of its
own at the same API, say). Envelopes sealed here from the credentials held
before are countersigned the same way (the browser cannot check what they
hold: that was this server's word).
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import api_error
from app.models.a2a_gateway import A2APeer
from app.models.ai_provider import AIProvider
from app.models.egress_proxy import EgressProxy, EgressRoute
from app.models.http_tool import HttpTool
from app.models.mcp import MCPServer
from app.models.sealed_credential import SealedCredential
from app.pvp import sealed
from app.pvp.policy_bundle import sha256 as doc_sha256

SEALED_TYPE = "provenza.credential.sealed"
# object -> (model, legacy secret column)
OBJECTS = {"route": (EgressRoute, "secret_encrypted"), "provider": (AIProvider, "api_key_encrypted"),
           "mcp_server": (MCPServer, "auth_secret_encrypted"), "a2a_peer": (A2APeer, "auth_secret_encrypted"),
           "http_tool": (HttpTool, "auth_secret_encrypted")}


def upstream_of(obj: str, row) -> Optional[str]:
    """Where the object's credential may be sent: the origin bound into the
    envelope (app/pvp/sealed.py). None: it has no address a credential can go to."""
    if obj == "route":
        return sealed.origin(row.upstream_url)
    if obj == "provider":
        from app.services.gateway_adapters import DEFAULT_BASE

        return sealed.origin(row.base_url or DEFAULT_BASE.get(row.type))
    if obj == "mcp_server":
        return sealed.origin(row.url)
    if obj == "a2a_peer":
        return sealed.origin(row.card_url)   # the peer's endpoint must be on the same origin
    if obj == "http_tool":
        return sealed.origin(row.url)
    return None


def plaintext_refused():
    """A credential sent to the server in clear text is refused: it is sealed
    in the browser to the egress proxies (or kept in their configuration)."""
    return api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "credential.plaintext_refused")


async def target(db: AsyncSession, org_id: int, obj: str, object_id: int):
    if obj not in OBJECTS:
        raise api_error(status.HTTP_404_NOT_FOUND, "credential.unknown_object")
    model, _ = OBJECTS[obj]
    row = (await db.execute(select(model).where(model.id == object_id, model.org_id == org_id))).scalar_one_or_none()
    if row is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "credential.unknown_object")
    return row


async def proxies_with_keys(db: AsyncSession, org_id: int) -> List[EgressProxy]:
    return list((await db.execute(select(EgressProxy).where(
        EgressProxy.org_id == org_id, EgressProxy.enabled.is_(True), EgressProxy.revoked_at.is_(None),
        EgressProxy.encryption_key.is_not(None)).order_by(EgressProxy.id))).scalars())


async def state(db: AsyncSession, org_id: int, obj: str, row) -> Dict[str, Any]:
    """Where an object's credential lives, and which proxies cannot open it:
    no envelope for them, or one sealed for another address than the
    object's now (it no longer opens there)."""
    source = getattr(row, "credential_source", "none") or "none"
    upstream = upstream_of(obj, row)
    envelopes = (await db.execute(select(SealedCredential).where(
        SealedCredential.object_type == obj, SealedCredential.object_id == row.id))).scalars().all()
    sealed_for = {e.proxy_id for e in envelopes if (e.envelope.get("context") or {}).get("upstream") == upstream}
    keys = [p.id for p in await proxies_with_keys(db, org_id)]
    _, legacy = OBJECTS[obj]
    return {"source": source, "upstream": upstream, "sealed_for": sorted(sealed_for),
            "missing": sorted(set(keys) - sealed_for) if source == "sealed" else [],
            "stale": sorted({e.proxy_id for e in envelopes} - sealed_for),
            # envelopes no administrator signed (sealed here from a credential held before)
            "unsigned": sorted({e.proxy_id for e in envelopes if not e.sealer}),
            "awaiting_sealing": bool(getattr(row, legacy, None))}


def _wipe(row, obj: str) -> None:
    _, legacy = OBJECTS[obj]
    setattr(row, legacy, None)


def sealed_statement(user, session, obj: str, object_id: int, upstream: str, digests: Dict[int, str],
                     issued_at: int) -> Dict[str, Any]:
    """What an administrator signs with their session key over an object's
    envelopes (proxy/internal/trust/sealer.go checks it)."""
    return {"type": SEALED_TYPE, "v": 1, "org_id": user.org_id, "user_id": user.id, "session_id": session.id,
            "object": obj, "object_id": object_id, "upstream": upstream,
            "envelopes": {str(pid): sha for pid, sha in sorted(digests.items())}, "issued_at": issued_at}


async def _checked(db: AsyncSession, org_id: int, obj: str, object_id: int,
                   envelopes: List[Dict[str, Any]]) -> Tuple[Any, str, Dict[int, str]]:
    """The object, its origin and the envelopes' SHA-256 by proxy - or a 4xx."""
    row = await target(db, org_id, obj, object_id)
    keys = {p.id: p for p in await proxies_with_keys(db, org_id)}
    if not envelopes:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "credential.no_envelopes")
    upstream = upstream_of(obj, row)
    if upstream is None:
        raise api_error(status.HTTP_409_CONFLICT, "credential.no_upstream")
    digests: Dict[int, str] = {}
    for env in envelopes:
        pid = env.get("proxy_id") if isinstance(env, dict) else None
        proxy = keys.get(pid) if isinstance(pid, int) and not isinstance(pid, bool) else None
        if proxy is None or pid in digests:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "credential.unknown_proxy")
        problem = sealed.envelope_problem(env, sealed.context(org_id, obj, object_id, pid, upstream),
                                          proxy.encryption_key)
        if problem:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "credential.bad_envelope", problem=problem)
        digests[pid] = doc_sha256(env)
    return row, upstream, digests


async def _stored(db: AsyncSession, org_id: int, obj: str, object_id: int) -> Tuple[Any, str, Dict[int, str]]:
    """The object's stored envelopes, by proxy - for a countersignature."""
    row = await target(db, org_id, obj, object_id)
    upstream = upstream_of(obj, row)
    rows = (await db.execute(select(SealedCredential).where(SealedCredential.object_type == obj,
                                                            SealedCredential.object_id == object_id))).scalars().all()
    if upstream is None or not rows:
        raise api_error(status.HTTP_409_CONFLICT, "credential.nothing_to_sign")
    return row, upstream, {r.proxy_id: doc_sha256(r.envelope) for r in rows}


async def statement(db: AsyncSession, user, session, obj: str, object_id: int,
                    envelopes: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """The statement to sign for envelopes about to be stored (the browser
    checks the digests against the envelopes it made), or - without
    envelopes - for the envelopes already stored (a countersignature)."""
    from app.services import signing_sessions as ss

    session = ss.require_certified(session)
    if envelopes is None:
        _, upstream, digests = await _stored(db, user.org_id, obj, object_id)
    else:
        _, upstream, digests = await _checked(db, user.org_id, obj, object_id, envelopes)
    return sealed_statement(user, session, obj, object_id, upstream, digests, int(time.time()))


async def store(db: AsyncSession, user, session, obj: str, object_id: int, envelopes: List[Dict[str, Any]],
                st: Any, signature: Any) -> Dict[str, Any]:
    """Replace an object's credential by envelopes sealed in the browser,
    signed by the administrator who sealed them."""
    from app.services import signing_sessions as ss

    org_id = user.org_id
    row, upstream, digests = await _checked(db, org_id, obj, object_id, envelopes)
    session = ss.require_certified(session)
    proof = await ss.verify_signed(db, session, sealed_statement(user, session, obj, object_id, upstream, digests, 0),
                                   st, signature)
    await db.execute(delete(SealedCredential).where(SealedCredential.object_type == obj,
                                                    SealedCredential.object_id == object_id))
    for env in envelopes:
        db.add(SealedCredential(org_id=org_id, object_type=obj, object_id=object_id, proxy_id=env["proxy_id"],
                                envelope=env, sealer=proof, created_by=user.id))
    row.credential_source = "sealed"
    _wipe(row, obj)
    await db.commit()
    return await state(db, org_id, obj, row)


async def countersign(db: AsyncSession, user, session, obj: str, object_id: int, st: Any,
                      signature: Any) -> Dict[str, Any]:
    """An administrator signs the envelopes stored for an object (those
    sealed here from a credential held before)."""
    from app.services import signing_sessions as ss

    row, upstream, digests = await _stored(db, user.org_id, obj, object_id)
    session = ss.require_certified(session)
    proof = await ss.verify_signed(db, session, sealed_statement(user, session, obj, object_id, upstream, digests, 0),
                                   st, signature)
    rows = (await db.execute(select(SealedCredential).where(SealedCredential.object_type == obj,
                                                            SealedCredential.object_id == object_id))).scalars()
    for r in rows:
        r.sealer = proof
    await db.commit()
    return await state(db, user.org_id, obj, row)


async def set_source(db: AsyncSession, org_id: int, obj: str, object_id: int, source: str) -> Dict[str, Any]:
    """"local" (the proxies' configuration) or "none": envelopes are dropped."""
    if source not in ("local", "none"):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "credential.bad_source")
    row = await target(db, org_id, obj, object_id)
    await db.execute(delete(SealedCredential).where(SealedCredential.object_type == obj,
                                                    SealedCredential.object_id == object_id))
    row.credential_source = source
    _wipe(row, obj)
    await db.commit()
    return await state(db, org_id, obj, row)


async def forget(db: AsyncSession, obj: str, object_id: int) -> None:
    """An object is deleted: so are its envelopes (the caller commits)."""
    await db.execute(delete(SealedCredential).where(SealedCredential.object_type == obj,
                                                    SealedCredential.object_id == object_id))


async def for_proxy(db: AsyncSession, proxy: EgressProxy) -> List[Dict[str, Any]]:
    rows = (await db.execute(select(SealedCredential).where(SealedCredential.proxy_id == proxy.id,
                                                            SealedCredential.org_id == proxy.org_id)
                             .order_by(SealedCredential.id))).scalars()
    return [{"object": r.object_type, "object_id": r.object_id, "envelope": r.envelope, "sealer": r.sealer}
            for r in rows]


async def seal_legacy(db: AsyncSession, org_id: int, user_id: int) -> Dict[str, Any]:
    """Credentials this server held before: sealed to every proxy with a key,
    then erased here. Needs at least one such proxy."""
    from app.core.crypto import decrypt_secret

    proxies = await proxies_with_keys(db, org_id)
    if not proxies:
        raise api_error(status.HTTP_409_CONFLICT, "credential.no_proxy_keys")
    done: Dict[str, int] = {}
    objects: List[Dict[str, Any]] = []     # to countersign (the browser signs them next)
    failed: List[Tuple[str, int]] = []
    for obj, (model, legacy) in OBJECTS.items():
        rows = (await db.execute(select(model).where(model.org_id == org_id,
                                                     getattr(model, legacy).is_not(None)))).scalars().all()
        for row in rows:
            upstream = upstream_of(obj, row)
            try:
                secret = decrypt_secret(getattr(row, legacy))
            except ValueError:
                secret = None
            if secret is None or upstream is None:
                failed.append((obj, row.id))
                continue
            await db.execute(delete(SealedCredential).where(SealedCredential.object_type == obj,
                                                            SealedCredential.object_id == row.id))
            for p in proxies:
                db.add(SealedCredential(org_id=org_id, object_type=obj, object_id=row.id, proxy_id=p.id,
                                        envelope=sealed.seal(secret, p.encryption_key,
                                                             sealed.context(org_id, obj, row.id, p.id, upstream)),
                                        created_by=user_id))
            del secret
            row.credential_source = "sealed"
            _wipe(row, obj)
            done[obj] = done.get(obj, 0) + 1
            objects.append({"object": obj, "object_id": row.id})
    await db.commit()
    return {"sealed": done, "objects": objects, "proxies": [p.id for p in proxies],
            "failed": [{"object": o, "object_id": i} for o, i in failed]}


async def legacy_count(db: AsyncSession, org_id: int) -> int:
    from sqlalchemy import func

    total = 0
    for model, legacy in OBJECTS.values():
        total += (await db.execute(select(func.count()).select_from(model).where(
            model.org_id == org_id, getattr(model, legacy).is_not(None)))).scalar_one()
    return total


def configured(row) -> Optional[str]:
    """None when the upstream needs no credential, else where it lives."""
    src = getattr(row, "credential_source", "none") or "none"
    return None if src == "none" else src
