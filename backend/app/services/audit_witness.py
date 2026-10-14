# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Witnessing the audit log with RFC 3161 time-stamps (app/core/rfc3161.py).

Every checkpoint (a signed Merkle root of the organization's audit log) is
sent - as the SHA-256 of its canonical statement, nothing else - to the
organization's Time-Stamp Authority, which signs that hash with the time.
The token is verified and stored next to the checkpoint.

What it adds: a checkpoint with a token is proof, signed by a third party,
that this exact state of the log existed at that time. Anyone holding one
(an auditor who exported it, the offline verifier) can show that a later
log which no longer contains it was rewritten, and when it still did. The
server's own key cannot backdate a checkpoint, and nobody can claim one was
made up afterwards.

What it does not: the TSA keeps no history for us. If an administrator
restores the database to an older state, the tokens issued after it go
with the rows; the rewrite is caught by whoever kept a copy. Export the
timestamped checkpoints regularly (Audit -> Checkpoints) and keep them
outside the server; `tools/provenza_audit.py timestamps` checks them.
"""

import base64
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import rfc3161
from app.core.errors import api_error
from app.core.outbound import guarded_async_client, validate_url
from app.models.audit_log import AuditCheckpoint, AuditCheckpointTimestamp, AuditTsaSettings

BATCH = 50
MAX_RESPONSE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 15.0


def digest_of(statement: str) -> bytes:
    """What is time-stamped: SHA-256 of the checkpoint's canonical statement."""
    return hashlib.sha256(statement.encode("utf-8")).digest()


def settings_out(row: Optional[AuditTsaSettings]) -> Dict[str, Any]:
    if row is None:
        return {"enabled": False, "url": None, "trust_subjects": [], "last_error": None, "last_error_at": None}
    anchors = rfc3161.load_anchors(row.trust_pem)
    return {"enabled": row.enabled, "url": row.url, "trust_subjects": [a.subject.rfc4514_string() for a in anchors],
            "last_error": row.last_error, "last_error_at": row.last_error_at}


async def get_settings(db: AsyncSession, org_id: int) -> Optional[AuditTsaSettings]:
    return (await db.execute(select(AuditTsaSettings).where(AuditTsaSettings.org_id == org_id))).scalar_one_or_none()


def _checked(url: str, trust_pem: str):
    try:
        url = validate_url(url)
    except ValueError as exc:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "tsa.bad_url", detail=str(exc)[:200])
    try:
        anchors = rfc3161.load_anchors(trust_pem)
    except rfc3161.TimestampError as exc:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.code)
    if not anchors:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "tsa.no_trust_anchor")
    return url, anchors


async def stamp(url: str, anchors, digest: bytes) -> rfc3161.Token:
    """Ask the TSA; the answer is verified before anything is kept."""
    nonce = secrets.randbits(63)
    try:
        async with guarded_async_client(timeout=TIMEOUT_SECONDS) as client:
            async with client.stream("POST", url, content=rfc3161.request(digest, nonce),
                                     headers={"Content-Type": "application/timestamp-query",
                                              "Accept": "application/timestamp-reply"}) as resp:
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise rfc3161.TimestampError("tsa.response_too_large")
                if resp.status_code != 200:
                    raise rfc3161.TimestampError("tsa.http_error", f"HTTP {resp.status_code}")
    except httpx.HTTPError as exc:
        raise rfc3161.TimestampError("tsa.unreachable", f"{type(exc).__name__}: {str(exc)[:150]}")
    return rfc3161.verify_response(body, digest, nonce, anchors)


async def save_settings(db: AsyncSession, org_id: int, user_id: int, *, enabled: bool, url: str,
                        trust_pem: Optional[str]) -> AuditTsaSettings:
    """Saving tests the TSA first: a configuration that cannot time-stamp is
    refused, not stored. No trust_pem keeps the stored one."""
    row = await get_settings(db, org_id)
    if trust_pem is None:
        if row is None:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "tsa.no_trust_anchor")
        trust_pem = row.trust_pem
    url, anchors = _checked(url, trust_pem)
    if enabled:
        try:
            await stamp(url, anchors, digest_of("provenza.tsa.test " + datetime.now(timezone.utc).isoformat()))
        except rfc3161.TimestampError as exc:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.code, detail=(exc.detail or "")[:200])
    if row is None:
        row = AuditTsaSettings(org_id=org_id)
        db.add(row)
    row.enabled, row.url, row.trust_pem, row.updated_by = enabled, url, trust_pem.strip(), user_id
    row.last_error = row.last_error_at = None
    await db.commit()
    return row


async def stamp_pending(db: AsyncSession, org_id: int, limit: int = BATCH) -> Dict[str, int]:
    """Time-stamp the organization's checkpoints that have no token from its
    TSA yet, oldest first. A TSA that fails is noted and retried next run."""
    row = await get_settings(db, org_id)
    if row is None or not row.enabled:
        return {"stamped": 0, "failed": 0}
    anchors = rfc3161.load_anchors(row.trust_pem)
    done = select(AuditCheckpointTimestamp.checkpoint_id).where(AuditCheckpointTimestamp.tsa_url == row.url)
    pending = (await db.execute(
        select(AuditCheckpoint).where(AuditCheckpoint.org_id == org_id, AuditCheckpoint.id.not_in(done))
        .order_by(AuditCheckpoint.tree_size).limit(limit))).scalars().all()
    stamped = 0
    url = row.url
    for cp in pending:
        cp_id, statement = cp.id, cp.statement
        try:
            tok = await stamp(url, anchors, digest_of(statement))
        except rfc3161.TimestampError as exc:
            row.last_error, row.last_error_at = f"{exc.code}: {exc.detail}"[:500], datetime.now(timezone.utc)
            await db.commit()
            return {"stamped": stamped, "failed": 1}
        try:
            async with db.begin_nested():
                db.add(AuditCheckpointTimestamp(
                    org_id=org_id, checkpoint_id=cp_id, tsa_url=url, token=base64.b64encode(tok.der).decode(),
                    gen_time=tok.gen_time, serial=str(tok.serial)[:64], tsa_subject=tok.tsa_subject[:500]))
        except IntegrityError:
            continue   # stamped meanwhile by another worker
        stamped += 1
    if stamped:
        row.last_error = row.last_error_at = None
    await db.commit()
    return {"stamped": stamped, "failed": 0}


async def stamp_all(db: AsyncSession) -> Dict[str, int]:
    orgs = (await db.execute(select(AuditTsaSettings.org_id).where(AuditTsaSettings.enabled.is_(True)))).scalars().all()
    total = {"stamped": 0, "failed": 0}
    for org_id in orgs:
        r = await stamp_pending(db, org_id)
        total["stamped"] += r["stamped"]
        total["failed"] += r["failed"]
    return total


async def timestamps_for(db: AsyncSession, checkpoint_ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
    """The tokens of these checkpoints, as exported with them."""
    out: Dict[int, List[Dict[str, Any]]] = {}
    if not checkpoint_ids:
        return out
    rows = (await db.execute(select(AuditCheckpointTimestamp).where(
        AuditCheckpointTimestamp.checkpoint_id.in_(checkpoint_ids)).order_by(AuditCheckpointTimestamp.id))).scalars()
    for t in rows:
        out.setdefault(t.checkpoint_id, []).append({
            "format": "rfc3161", "tsa_url": t.tsa_url, "gen_time": t.gen_time.isoformat(), "serial": t.serial,
            "tsa_subject": t.tsa_subject, "token": t.token, "imprint": "sha256(statement)"})
    return out
