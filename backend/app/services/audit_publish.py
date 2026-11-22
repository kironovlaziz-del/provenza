# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Publishing the audit log's checkpoints outside the server.

A signed checkpoint (a Merkle root of the organization's audit log,
app/services/audit_proofs.py) proves what the log was - to whoever kept a
copy. Publication makes keeping a copy automatic: every interval (one hour
by default, 5 minutes to 24 hours), the latest checkpoint goes to places the
server cannot rewrite:

  rekor   Sigstore Rekor, a public append-only transparency log - on by
          default. Only the SHA-256 of the checkpoint's statement, a
          signature over it and the publishing key go there, never the log.
  github  a repository the organization owns: one JSON file per checkpoint.
  s3      a bucket with Object Lock: one object per checkpoint, retained.

A history that was rewritten after a checkpoint was published can no longer
be shown to extend it (a consistency proof, docs/audit-proofs.md) - and the
published copy is out of reach. Each target is outbound traffic to the host
it names, shown as such on the Audit Log page, and can be switched off.

Rekor does not take the audit key's Ed25519 + ML-DSA-65 signatures, so each
organization has a publishing key (ECDSA P-256) that signs only what is sent
there. It is not trusted for the log's contents: the checkpoint inside is
signed by the audit key as always. Anyone can list the organization's
entries in Rekor by its publishing key.

Every Rekor answer is checked before it is kept: the entry is exactly what
was sent, and its signed entry timestamp verifies with the log's key (for
the public instance, the key Sigstore distributes; for another instance, the
key the administrator gave).
"""

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.errors import api_error
from app.core.outbound import guarded_async_client, validate_url
from app.models.audit_log import AuditCheckpoint, AuditCheckpointPublication, AuditPublicationSettings

TARGETS = ("rekor", "github", "s3")
DEFAULT_INTERVAL = 60
MIN_INTERVAL, MAX_INTERVAL = 5, 24 * 60
TIMEOUT_SECONDS = 20.0
MAX_RESPONSE_BYTES = 256 * 1024

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"
# The public Rekor's key, as Sigstore distributes it (github.com/sigstore/root-signing,
# targets/rekor.pub and the rekor.sigstore.dev entry of targets/trusted_root.json,
# valid from 2021-01-12). Its log ID is the SHA-256 of this key's DER encoding.
SIGSTORE_REKOR_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
"""
SIGSTORE_REKOR_LOG_ID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"


class PublishError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _host(url: Optional[str]) -> Optional[str]:
    return urlparse(url).hostname if url else None


# ----------------------------------------------------------------------------- settings

async def get_settings(db: AsyncSession, org_id: int) -> Optional[AuditPublicationSettings]:
    return (await db.execute(select(AuditPublicationSettings).where(
        AuditPublicationSettings.org_id == org_id))).scalar_one_or_none()


async def settings_row(db: AsyncSession, org_id: int) -> AuditPublicationSettings:
    """The organization's row, made with the defaults when it has none yet."""
    row = await get_settings(db, org_id)
    if row is not None:
        return row
    try:
        async with db.begin_nested():
            db.add(AuditPublicationSettings(org_id=org_id, interval_minutes=DEFAULT_INTERVAL, rekor_enabled=True,
                                            rekor_url=DEFAULT_REKOR_URL, github_enabled=False, s3_enabled=False))
    except IntegrityError:
        pass                                    # made meanwhile by another worker
    return await get_settings(db, org_id)


def interval_of(row: Optional[AuditPublicationSettings]) -> int:
    return row.interval_minutes if row is not None else DEFAULT_INTERVAL


def enabled_targets(row: Optional[AuditPublicationSettings]) -> List[str]:
    """No row: the defaults (Rekor). GitHub and S3 count once they are set up."""
    if row is None:
        return ["rekor"]
    out = []
    if row.rekor_enabled:
        out.append("rekor")
    if row.github_enabled and row.github_repo and row.github_token_enc:
        out.append("github")
    if row.s3_enabled and row.s3_bucket and row.s3_secret_enc:
        out.append("s3")
    return out


def rekor_key(row: Optional[AuditPublicationSettings]) -> Tuple[str, str]:
    """(URL, PEM of the key its entries must be signed with)."""
    if row is None or (row.rekor_url or DEFAULT_REKOR_URL) == DEFAULT_REKOR_URL:
        return DEFAULT_REKOR_URL, SIGSTORE_REKOR_PUBLIC_KEY
    if not row.rekor_public_key:
        raise PublishError("publish.rekor_no_key")
    return row.rekor_url, row.rekor_public_key


def _load_ec_public(pem: str) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, TypeError) as exc:
        raise PublishError("publish.bad_public_key", str(exc)[:150])
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise PublishError("publish.bad_public_key", "an ECDSA P-256 public key is expected")
    return key


def _der(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def fingerprint(public_pem: str) -> str:
    """SHA256:<base64, no padding> of the key's DER encoding - the form agent and audit keys use."""
    raw = _der(serialization.load_pem_public_key(public_pem.encode()))
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


async def save_settings(db: AsyncSession, org_id: int, user_id: int, *, interval_minutes: int,
                        rekor_enabled: bool, rekor_url: Optional[str] = None,
                        rekor_public_key: Optional[str] = None) -> AuditPublicationSettings:
    if not MIN_INTERVAL <= interval_minutes <= MAX_INTERVAL:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "publish.bad_interval")
    url = (rekor_url or DEFAULT_REKOR_URL).strip().rstrip("/")
    if url != DEFAULT_REKOR_URL:
        try:
            url = validate_url(url).rstrip("/")
        except ValueError as exc:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "publish.bad_url", detail=str(exc)[:200])
    row = await settings_row(db, org_id)
    if url == DEFAULT_REKOR_URL:
        pem = None                              # the key Sigstore distributes, built in
    else:
        pem = (rekor_public_key or "").strip() or (row.rekor_public_key if row.rekor_url == url else None)
        if not pem:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "publish.rekor_no_key")
        try:
            _load_ec_public(pem)
        except PublishError as exc:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.code, detail=exc.detail)
    if url != row.rekor_url:
        row.rekor_last_error = row.rekor_last_error_at = None
    row.interval_minutes, row.rekor_enabled, row.rekor_url, row.rekor_public_key = (
        interval_minutes, rekor_enabled, url, pem)
    row.updated_by = user_id
    await db.commit()
    return row


# ----------------------------------------------------------------------------- the publishing key

async def publishing_key(db: AsyncSession, row: AuditPublicationSettings) -> ec.EllipticCurvePrivateKey:
    """The organization's publishing key, made the first time it is needed.
    Two workers making it at once: the first one stored wins (the row is
    locked), so every Rekor entry of an organization names one key."""
    if row.publish_private_key_enc is None:
        locked = (await db.execute(select(AuditPublicationSettings).where(
            AuditPublicationSettings.id == row.id).with_for_update()
            .execution_options(populate_existing=True))).scalar_one()
        if locked.publish_private_key_enc is None:
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            locked.publish_private_key_enc = encrypt_secret(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()).decode())
            locked.publish_public_key = pem
            locked.publish_key_fingerprint = fingerprint(pem)
        await db.commit()
        row = locked
    return serialization.load_pem_private_key(decrypt_secret(row.publish_private_key_enc).encode(), password=None)


# ----------------------------------------------------------------------------- Rekor

def rekor_entry(statement: str, signature: bytes, public_pem: str) -> Dict[str, Any]:
    """A hashedrekord entry: the SHA-256 of the statement, the publishing key's
    signature over the statement (ECDSA P-256, SHA-256) and the key."""
    return {"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": {
        "data": {"hash": {"algorithm": "sha256", "value": hashlib.sha256(statement.encode("utf-8")).hexdigest()}},
        "signature": {"content": base64.b64encode(signature).decode(),
                      "publicKey": {"content": base64.b64encode(public_pem.encode()).decode()}}}}


def set_payload(entry: Dict[str, Any]) -> bytes:
    """What Rekor's signed entry timestamp signs: the entry's body (base64,
    as answered), integrated time, log ID and index, as canonical JSON."""
    return json.dumps({"body": entry["body"], "integratedTime": entry["integratedTime"], "logID": entry["logID"],
                       "logIndex": entry["logIndex"]}, sort_keys=True, separators=(",", ":")).encode()


def verify_rekor_answer(answer: Any, sent: Dict[str, Any], log_pem: str) -> Tuple[str, Dict[str, Any]]:
    """The entry Rekor answered with, checked: one entry, its body exactly the
    entry sent, from the log of this key, its signed entry timestamp valid."""
    if not isinstance(answer, dict) or len(answer) != 1:
        raise PublishError("publish.rekor_bad_answer", "expected one entry")
    uuid, entry = next(iter(answer.items()))
    try:
        body = json.loads(base64.b64decode(entry["body"], validate=True))
        integrated, index, log_id = int(entry["integratedTime"]), int(entry["logIndex"]), str(entry["logID"])
        set_sig = base64.b64decode(entry["verification"]["signedEntryTimestamp"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise PublishError("publish.rekor_bad_answer", f"{type(exc).__name__}: {str(exc)[:120]}")
    if body.get("kind") != sent["kind"] or body.get("apiVersion") != sent["apiVersion"]:
        raise PublishError("publish.rekor_bad_answer", "not the entry sent")
    spec, want = body.get("spec") or {}, sent["spec"]
    if (spec.get("data") or {}).get("hash") != want["data"]["hash"] or spec.get("signature") != want["signature"]:
        raise PublishError("publish.rekor_bad_answer", "not the entry sent")
    log_key = _load_ec_public(log_pem)
    if log_id != hashlib.sha256(_der(log_key)).hexdigest():
        raise PublishError("publish.rekor_wrong_log", "the entry names another log")
    try:
        log_key.verify(set_sig, set_payload(entry), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise PublishError("publish.rekor_bad_signature", "the signed entry timestamp does not verify")
    if integrated <= 0 or index < 0:
        raise PublishError("publish.rekor_bad_answer", "no integrated time or index")
    return uuid, entry


async def _post_json(url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Tuple[int, Any]:
    try:
        async with guarded_async_client(timeout=TIMEOUT_SECONDS) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as resp:
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise PublishError("publish.response_too_large")
                code = resp.status_code
    except httpx.HTTPError as exc:
        raise PublishError("publish.unreachable", f"{type(exc).__name__}: {str(exc)[:150]}")
    try:
        return code, json.loads(body) if body else None
    except ValueError:
        return code, None


async def publish_rekor(db: AsyncSession, row: AuditPublicationSettings, cp: AuditCheckpoint) -> AuditCheckpointPublication:
    url, log_pem = rekor_key(row)
    key = await publishing_key(db, row)
    public_pem = row.publish_public_key
    statement = cp.statement
    sent = rekor_entry(statement, key.sign(statement.encode("utf-8"), ec.ECDSA(hashes.SHA256())), public_pem)
    code, answer = await _post_json(f"{url}/api/v1/log/entries", sent,
                                    {"Content-Type": "application/json", "Accept": "application/json"})
    if code != 201:
        msg = (answer or {}).get("message") if isinstance(answer, dict) else None
        raise PublishError("publish.http_error", f"HTTP {code}" + (f": {str(msg)[:150]}" if msg else ""))
    uuid, entry = verify_rekor_answer(answer, sent, log_pem)
    host = _host(url)
    location = (f"https://search.sigstore.dev/?logIndex={entry['logIndex']}" if url == DEFAULT_REKOR_URL
                else f"{url}/api/v1/log/entries/{uuid}")
    return AuditCheckpointPublication(
        org_id=cp.org_id, checkpoint_id=cp.id, target="rekor", destination=url, reference=uuid[:200],
        location=location[:500], log_index=int(entry["logIndex"]),
        published_at=datetime.fromtimestamp(int(entry["integratedTime"]), timezone.utc),
        receipt=json.dumps({"format": "provenza.audit.publication/1", "target": "rekor", "host": host,
                            "uuid": uuid, "entry": entry, "sent": sent}, sort_keys=True, separators=(",", ":")))


PUBLISHERS = {"rekor": publish_rekor}


# ----------------------------------------------------------------------------- when and what

async def latest_checkpoint(db: AsyncSession, org_id: int) -> Optional[AuditCheckpoint]:
    return (await db.execute(select(AuditCheckpoint).where(AuditCheckpoint.org_id == org_id)
                             .order_by(AuditCheckpoint.tree_size.desc()).limit(1))).scalar_one_or_none()


async def last_publication(db: AsyncSession, org_id: int, target: str) -> Optional[Tuple[AuditCheckpointPublication, int]]:
    """The target's latest publication and the size of the checkpoint it published."""
    r = (await db.execute(
        select(AuditCheckpointPublication, AuditCheckpoint.tree_size)
        .join(AuditCheckpoint, AuditCheckpoint.id == AuditCheckpointPublication.checkpoint_id)
        .where(AuditCheckpointPublication.org_id == org_id, AuditCheckpointPublication.target == target)
        .order_by(AuditCheckpointPublication.id.desc()).limit(1))).first()
    return (r[0], int(r[1])) if r else None


def _note_error(row: AuditPublicationSettings, target: str, exc: PublishError) -> None:
    setattr(row, f"{target}_last_error", f"{exc.code}: {exc.detail}"[:500] if exc.detail else exc.code)
    setattr(row, f"{target}_last_error_at", _now())


async def publish_org(db: AsyncSession, org_id: int, *, force: bool = False) -> Dict[str, str]:
    """Publish the organization's latest checkpoint to every target that is
    due: switched on, the interval over since its last publication (unless
    forced), and the log grown since. {target: "published" | "not_due" |
    "nothing_new" | "failed"}."""
    row = await get_settings(db, org_id)
    targets = enabled_targets(row)
    out: Dict[str, str] = {}
    if not targets:
        return out
    cp = await latest_checkpoint(db, org_id)
    if cp is None:
        return {t: "nothing_new" for t in targets}
    row = row or await settings_row(db, org_id)
    for target in targets:
        last = await last_publication(db, org_id, target)
        if last is not None and last[1] >= cp.tree_size:
            out[target] = "nothing_new"
            continue
        if not force and last is not None and _now() - last[0].created_at < timedelta(minutes=interval_of(row)):
            out[target] = "not_due"
            continue
        try:
            pub = await PUBLISHERS[target](db, row, cp)
        except PublishError as exc:
            _note_error(row, target, exc)
            await db.commit()
            out[target] = "failed"
            continue
        try:
            async with db.begin_nested():
                db.add(pub)
        except IntegrityError:
            out[target] = "nothing_new"          # published meanwhile by another worker
            continue
        setattr(row, f"{target}_last_error", None)
        setattr(row, f"{target}_last_error_at", None)
        await db.commit()
        out[target] = "published"
    return out


async def publish_all(db: AsyncSession) -> Dict[str, int]:
    """Every organization that has checkpoints (the scheduler, every 5 minutes)."""
    orgs = (await db.execute(select(AuditCheckpoint.org_id).group_by(AuditCheckpoint.org_id))).scalars().all()
    total: Dict[str, int] = {}
    for org_id in orgs:
        try:
            result = await publish_org(db, org_id)
        except Exception:  # noqa: BLE001 - one organization must not stop the others
            await db.rollback()
            total["errors"] = total.get("errors", 0) + 1
            continue
        for state in result.values():
            total[state] = total.get(state, 0) + 1
    return total


# ----------------------------------------------------------------------------- what the page shows

async def settings_out(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    row = await get_settings(db, org_id)
    on = enabled_targets(row)
    targets = []
    for target in TARGETS:
        last = await last_publication(db, org_id, target)
        item: Dict[str, Any] = {
            "target": target, "enabled": target in on,
            "last_published_at": last[0].published_at if last else None,
            "last_tree_size": last[1] if last else None,
            "last_location": last[0].location if last else None,
            "last_error": getattr(row, f"{target}_last_error", None) if row else None,
            "last_error_at": getattr(row, f"{target}_last_error_at", None) if row else None,
        }
        if target == "rekor":
            url = (row.rekor_url if row else None) or DEFAULT_REKOR_URL
            item.update(configured=True, destination=url, host=_host(url), public_instance=url == DEFAULT_REKOR_URL)
        elif target == "github":
            repo = row.github_repo if row else None
            item.update(configured=bool(repo and row.github_token_enc), destination=repo,
                        host="api.github.com" if repo else None)
        else:
            endpoint = row.s3_endpoint if row else None
            item.update(configured=bool(row and row.s3_bucket and row.s3_secret_enc),
                        destination=(f"{row.s3_bucket}" if row and row.s3_bucket else None), host=_host(endpoint))
        targets.append(item)
    published = int(await db.scalar(select(func.count()).select_from(AuditCheckpointPublication).where(
        AuditCheckpointPublication.org_id == org_id)) or 0)
    return {
        "interval_minutes": interval_of(row), "min_interval": MIN_INTERVAL, "max_interval": MAX_INTERVAL,
        "targets": targets, "publications": published,
        "publishing_key": ({"fingerprint": row.publish_key_fingerprint, "public_key": row.publish_public_key}
                           if row is not None and row.publish_public_key else None),
    }


def publication_out(p: AuditCheckpointPublication, tree_size: Optional[int] = None) -> Dict[str, Any]:
    return {"id": p.id, "checkpoint_id": p.checkpoint_id, "tree_size": tree_size, "target": p.target,
            "destination": p.destination, "reference": p.reference, "location": p.location,
            "log_index": p.log_index, "published_at": p.published_at, "receipt": json.loads(p.receipt)}


async def list_publications(db: AsyncSession, org_id: int, *, target: Optional[str] = None, skip: int = 0,
                            limit: int = 50) -> Tuple[List[Dict[str, Any]], int]:
    q = (select(AuditCheckpointPublication, AuditCheckpoint.tree_size)
         .join(AuditCheckpoint, AuditCheckpoint.id == AuditCheckpointPublication.checkpoint_id)
         .where(AuditCheckpointPublication.org_id == org_id))
    cq = select(func.count()).select_from(AuditCheckpointPublication).where(
        AuditCheckpointPublication.org_id == org_id)
    if target:
        q = q.where(AuditCheckpointPublication.target == target)
        cq = cq.where(AuditCheckpointPublication.target == target)
    rows = (await db.execute(q.order_by(AuditCheckpointPublication.id.desc()).offset(skip).limit(limit))).all()
    return [publication_out(p, int(size)) for p, size in rows], int(await db.scalar(cq) or 0)


async def publications_for(db: AsyncSession, checkpoint_ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
    """The publications of these checkpoints, as exported with them."""
    out: Dict[int, List[Dict[str, Any]]] = {}
    if not checkpoint_ids:
        return out
    rows = (await db.execute(select(AuditCheckpointPublication).where(
        AuditCheckpointPublication.checkpoint_id.in_(checkpoint_ids)).order_by(AuditCheckpointPublication.id))).scalars()
    for p in rows:
        out.setdefault(p.checkpoint_id, []).append(publication_out(p))
    return out
