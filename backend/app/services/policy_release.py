# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Releases of the signed policy (docs/pvp/edge.md, section 3): prepare one
from the working copy, show what it changes, have administrators sign it
with their passkeys, put it in force when the quorum has signed.

Who may sign a release, and how many must, comes from the release in force
when it was prepared (its manifest) - never from the working copy: a
passkey added meanwhile, or a quorum lowered meanwhile, counts only from the
release that contains it on. The first release is signed by the quorum its
own manifest states.
"""

import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import webauthn
from app.core.errors import api_error
from app.models.policy_release import PolicyRelease, PolicyReleaseSignature, PolicySigningSettings
from app.models.user import User
from app.pvp import policy_bundle as pb
from app.pvp import signed_policy as sp
from app.services import signing_sessions as ss

DEFAULTS = {"quorum": 1, "validity_days": 90, "offline_seconds": 900}
LIMITS = {"quorum": (1, 10), "validity_days": (1, 365), "offline_seconds": (60, 86400)}
PROXY_BINARIES = 20
ENFORCEMENT = ("observe", "enforce")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
NOTIFY_EVENT = "policy_release"
CHANGE_LIMIT = 500


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------- settings

async def settings(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    row = (await db.execute(select(PolicySigningSettings).where(
        PolicySigningSettings.org_id == org_id))).scalar_one_or_none()
    out: Dict[str, Any] = {k: (getattr(row, k) if row else v) for k, v in DEFAULTS.items()}
    out["proxy_binaries"] = list((row.proxy_binaries if row else None) or [])
    out["proxy_configs"] = list((row.proxy_configs if row else None) or [])
    out["enforcement"] = (row.enforcement if row else None) or "observe"
    return out


def proxy_binaries(values: Any, field: str = "proxy_binaries") -> List[str]:
    """SHA-256 of egress proxy binaries (or configurations): lowercase hex,
    unique, sorted, at most PROXY_BINARIES."""
    if not isinstance(values, list) or len(values) > PROXY_BINARIES:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "policy_release.bad_setting", field=field)
    out = set()
    for v in values:
        h = v.strip().lower() if isinstance(v, str) else ""
        if not SHA256_HEX.match(h):
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "policy_release.bad_setting", field=field)
        out.add(h)
    return sorted(out)


async def save_settings(db: AsyncSession, org_id: int, user_id: int, values: Dict[str, Any]) -> Dict[str, Any]:
    """The working copy of the quorum, validity, offline time and the egress
    proxy binaries: like any other change, it takes effect with the next
    signed release."""
    for k, (lo, hi) in LIMITS.items():
        v = values.get(k)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "policy_release.bad_setting", field=k)
    row = (await db.execute(select(PolicySigningSettings).where(
        PolicySigningSettings.org_id == org_id))).scalar_one_or_none()
    given = values.get("proxy_binaries")
    binaries = proxy_binaries(given) if given is not None else list((row.proxy_binaries if row else None) or [])
    given = values.get("proxy_configs")
    configs = proxy_binaries(given, "proxy_configs") if given is not None else \
        list((row.proxy_configs if row else None) or [])
    if row is None:
        row = PolicySigningSettings(org_id=org_id)
        db.add(row)
    for k in DEFAULTS:
        setattr(row, k, values[k])
    row.proxy_binaries = binaries or None
    row.proxy_configs = configs or None
    mode = values.get("enforcement")
    if mode is not None:
        if mode not in ENFORCEMENT:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "policy_release.bad_setting", field="enforcement")
        row.enforcement = mode
    row.updated_by = user_id
    await db.commit()
    return await settings(db, org_id)


# ---------------------------------------------------------------------- releases

async def governing(db: AsyncSession, org_id: int) -> Optional[PolicyRelease]:
    """The latest release that was in force and still verifies: it governs
    the next one. (One that does not verify - altered in the database - is
    skipped, so a quorum can still put a sound release in force.)"""
    rows = (await db.execute(select(PolicyRelease).where(
        PolicyRelease.org_id == org_id, PolicyRelease.status.in_(("in_force", "superseded")))
        .order_by(PolicyRelease.number.desc()))).scalars()
    for r in rows:
        if await sp._verify_chain(db, r) is None:
            return r
    return None


async def chain_after(db: AsyncSession, org_id: int, after: int) -> Dict[str, Any]:
    """The release in force and the releases that lead to it from release
    `after` (the last one an enforcement point verified), each as signed with
    the manifest that governs it - for an egress proxy or sensor to check
    every step itself (proxy/internal/trust); this server is only the courier."""
    current = await sp.current_release(db, org_id)
    if current is None:
        return {"current": None, "chain": []}
    path, r = [], current
    while r is not None and r.number > after and len(path) < 1000:
        path.append(r)
        r = await db.get(PolicyRelease, r.governed_by_id) if r.governed_by_id else None
    return {"current": current.number, "chain": [await document(db, org_id, x.id) for x in reversed(path)]}


async def _draft(db: AsyncSession, org_id: int) -> Optional[PolicyRelease]:
    return (await db.execute(select(PolicyRelease).where(
        PolicyRelease.org_id == org_id, PolicyRelease.status == "draft")
        .order_by(PolicyRelease.number.desc()).limit(1))).scalar_one_or_none()


def _governing_manifest(release: PolicyRelease, gov: Optional[PolicyRelease]) -> Dict[str, Any]:
    return gov.manifest if gov is not None else release.manifest


def _changes(old: Optional[PolicyRelease], bundle: Dict[str, Any], manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    return (pb.diff(old.bundle if old else None, bundle, pb.SECTIONS, CHANGE_LIMIT)
            + [dict(c, section=f"manifest.{c['section']}") for c in
               pb.diff(old.manifest if old else None, manifest, pb.MANIFEST_SECTIONS, CHANGE_LIMIT)])[:CHANGE_LIMIT]


async def working_copy(db: AsyncSession, org_id: int) -> tuple:
    cfg = await settings(db, org_id)
    bundle = await pb.bundle_content(db, org_id)
    if cfg["enforcement"] == "enforce":
        # absent means observe: a release made before enforce mode is unchanged
        bundle["enforcement"] = {"mode": "enforce"}
    return bundle, await pb.manifest_content(db, org_id, cfg["quorum"], cfg["proxy_binaries"],
                                             cfg["proxy_configs"]), cfg


async def prepare(db: AsyncSession, user: User) -> PolicyRelease:
    """A draft release from the working copy. An older draft is withdrawn
    with its signatures: what is signed is always one exact document."""
    org_id = user.org_id
    bundle_c, manifest_c, cfg = await working_copy(db, org_id)
    if pb.admins_with_passkeys(manifest_c) == 0:
        raise api_error(status.HTTP_409_CONFLICT, "policy_release.no_signers")
    if manifest_c["quorum"] > pb.admins_with_passkeys(manifest_c):
        raise api_error(status.HTTP_409_CONFLICT, "policy_release.quorum_unreachable",
                        quorum=manifest_c["quorum"], admins=pb.admins_with_passkeys(manifest_c))
    gov = await governing(db, org_id)
    now = int(time.time())
    bundle = {"type": pb.BUNDLE_TYPE, "v": pb.V, "org_id": org_id,
              "version": (gov.bundle["version"] + 1) if gov else 1,
              "previous": gov.bundle_sha256 if gov else None,
              "not_after": now + cfg["validity_days"] * 86400, "offline_seconds": cfg["offline_seconds"],
              **bundle_c}
    manifest = {"type": pb.MANIFEST_TYPE, "v": pb.V, "org_id": org_id, **manifest_c}
    if gov is not None and {k: gov.manifest.get(k) for k in pb.MANIFEST_SECTIONS} == manifest_c:
        manifest = gov.manifest                                    # unchanged: the same document
    else:
        manifest.update(version=(gov.manifest["version"] + 1) if gov else 1,
                        previous=gov.manifest_sha256 if gov else None)
    await db.execute(update(PolicyRelease).where(PolicyRelease.org_id == org_id, PolicyRelease.status == "draft")
                     .values(status="withdrawn", ended_at=_now()))
    number = ((await db.execute(select(func.max(PolicyRelease.number)).where(
        PolicyRelease.org_id == org_id))).scalar() or 0) + 1
    release = PolicyRelease(org_id=org_id, number=number, status="draft", bundle=bundle,
                            bundle_sha256=pb.sha256(bundle), manifest=manifest,
                            manifest_sha256=pb.sha256(manifest), governed_by_id=gov.id if gov else None,
                            changes=_changes(gov, bundle, manifest), created_by=user.id)
    db.add(release)
    await db.commit()
    await db.refresh(release)
    return release


async def _release(db: AsyncSession, org_id: int, release_id: Any) -> PolicyRelease:
    r = await db.get(PolicyRelease, release_id) if isinstance(release_id, int) else None
    if r is None or r.org_id != org_id:
        raise api_error(status.HTTP_404_NOT_FOUND, "policy_release.not_found")
    return r


def _signable(user: User, release: PolicyRelease, gov: Optional[PolicyRelease]) -> List[str]:
    """The passkeys (credential ids) through which this person may sign."""
    signer = (_governing_manifest(release, gov).get("signers") or {}).get(str(user.id)) or {}
    if user.role != pb.QUORUM_ROLE or signer.get("role") != pb.QUORUM_ROLE:
        return []
    return list((signer.get("passkeys") or {}).keys())


async def challenge(db: AsyncSession, user: User, release_id: Any) -> Dict[str, Any]:
    release = await _release(db, user.org_id, release_id)
    if release.status != "draft":
        raise api_error(status.HTTP_409_CONFLICT, "policy_release.not_draft")
    gov = await db.get(PolicyRelease, release.governed_by_id) if release.governed_by_id else None
    creds = _signable(user, release, gov)
    if not creds:
        raise api_error(status.HTTP_403_FORBIDDEN, "policy_release.not_a_signer")
    return await ss.challenge_for(db, user, sp.release_statement(user.org_id, user.id, release, int(time.time())),
                                  creds)


async def sign(db: AsyncSession, user: User, release_id: Any, statement: Any, assertion: Any) -> PolicyRelease:
    """One administrator's passkey over the release. When the quorum of the
    governing manifest has signed, the release comes into force."""
    release = await _release(db, user.org_id, release_id)
    if release.status != "draft":
        raise api_error(status.HTTP_409_CONFLICT, "policy_release.not_draft")
    gov = await db.get(PolicyRelease, release.governed_by_id) if release.governed_by_id else None
    if gov is not None and (gov.status not in ("in_force", "superseded")
                            or await sp._verify_chain(db, gov) is not None):
        raise api_error(status.HTTP_409_CONFLICT, "policy_release.governing_invalid")
    creds = _signable(user, release, gov)
    if not creds:
        raise api_error(status.HTTP_403_FORBIDDEN, "policy_release.not_a_signer")
    issued = statement.get("issued_at") if isinstance(statement, dict) else None
    expected = sp.release_statement(user.org_id, user.id, release, issued if isinstance(issued, int) else 0)
    await ss.confirm_expected(db, user, expected, statement, assertion, creds)
    # the passkey as the governing manifest lists it must have made it, not only the stored one
    key = sp.signer_key(_governing_manifest(release, gov), user.id, assertion["credential_id"])
    try:
        webauthn.verify_assertion_spki(
            public_key_spki=key["public_key"], alg=int(key["alg"]),
            client_data_json=str(assertion.get("client_data_json") or ""),
            authenticator_data=str(assertion.get("authenticator_data") or ""),
            signature=str(assertion.get("signature") or ""), challenge=webauthn.statement_challenge(statement))
    except (webauthn.WebAuthnError, KeyError, TypeError):
        raise api_error(status.HTTP_403_FORBIDDEN, "policy_release.passkey_not_in_manifest")
    exists = (await db.execute(select(PolicyReleaseSignature.id).where(
        PolicyReleaseSignature.release_id == release.id, PolicyReleaseSignature.user_id == user.id))).first()
    if exists:
        raise api_error(status.HTTP_409_CONFLICT, "policy_release.already_signed")
    db.add(PolicyReleaseSignature(org_id=user.org_id, release_id=release.id, user_id=user.id,
                                  credential_id=assertion["credential_id"], statement=statement,
                                  assertion={k: assertion.get(k) for k in
                                             ("client_data_json", "authenticator_data", "signature")}))
    await db.flush()
    sigs = list((await db.execute(select(PolicyReleaseSignature).where(
        PolicyReleaseSignature.release_id == release.id))).scalars())
    gm = _governing_manifest(release, gov)
    if len(sp.valid_signers(release, gm, sigs)) >= sp.quorum_of(gm):
        await db.execute(update(PolicyRelease).where(PolicyRelease.org_id == user.org_id,
                                                     PolicyRelease.status == "in_force")
                         .values(status="superseded", ended_at=_now()))
        release.status, release.in_force_at = "in_force", _now()
        sp.forget(user.org_id)
    await db.commit()
    await db.refresh(release)
    return release


async def withdraw(db: AsyncSession, user: User, release_id: Any) -> None:
    release = await _release(db, user.org_id, release_id)
    if release.status != "draft":
        raise api_error(status.HTTP_409_CONFLICT, "policy_release.not_draft")
    release.status, release.ended_at = "withdrawn", _now()
    await db.commit()


# ---------------------------------------------------------------------- what the interface shows

async def _signers(db: AsyncSession, release: PolicyRelease) -> List[Dict[str, Any]]:
    rows = (await db.execute(select(PolicyReleaseSignature, User.email)
                             .join(User, User.id == PolicyReleaseSignature.user_id)
                             .where(PolicyReleaseSignature.release_id == release.id)
                             .order_by(PolicyReleaseSignature.id))).all()
    return [{"user_id": s.user_id, "email": email, "signed_at": s.created_at} for s, email in rows]


def _summary(r: PolicyRelease) -> Dict[str, Any]:
    return {"id": r.id, "number": r.number, "status": r.status, "created_at": r.created_at,
            "in_force_at": r.in_force_at, "not_after": r.bundle.get("not_after"),
            "offline_seconds": r.bundle.get("offline_seconds"),
            "bundle": {"version": r.bundle.get("version"), "sha256": r.bundle_sha256},
            "manifest": {"version": r.manifest.get("version"), "sha256": r.manifest_sha256},
            "quorum": sp.quorum_of(r.manifest)}


async def state(db: AsyncSession, user: User, with_changes: bool = True) -> Dict[str, Any]:
    """The release in force, the draft waiting for signatures, and what the
    working copy changes that is not signed yet."""
    org_id = user.org_id
    current = await sp.current_release(db, org_id)
    policy = await sp.in_force(db, org_id) if current else None
    draft = await _draft(db, org_id)
    out: Dict[str, Any] = {"settings": await settings(db, org_id), "in_force": None, "draft": None,
                           "unsigned_changes": None, "unsigned_count": None}
    if current is not None:
        out["in_force"] = {**_summary(current), "signers": await _signers(db, current),
                           "problem": policy.problem if policy else None,
                           "expired": bool(policy and policy.expired)}
    if draft is not None:
        gov = await db.get(PolicyRelease, draft.governed_by_id) if draft.governed_by_id else None
        gm = _governing_manifest(draft, gov)
        signers = await _signers(db, draft)
        out["draft"] = {**_summary(draft), "quorum": sp.quorum_of(gm), "signers": signers,
                        "changes": draft.changes or [],
                        "can_sign": bool(_signable(user, draft, gov))
                        and all(s["user_id"] != user.id for s in signers)}
    if with_changes and current is not None:
        bundle_c, manifest_c, _ = await working_copy(db, org_id)
        changes = (pb.diff(current.bundle, bundle_c, pb.SECTIONS, CHANGE_LIMIT)
                   + [dict(c, section=f"manifest.{c['section']}") for c in
                      pb.diff(current.manifest, manifest_c, pb.MANIFEST_SECTIONS, CHANGE_LIMIT)])
        out["unsigned_changes"], out["unsigned_count"] = changes[:CHANGE_LIMIT], len(changes)
    return out


async def history(db: AsyncSession, org_id: int, limit: int = 50) -> List[Dict[str, Any]]:
    rows = (await db.execute(select(PolicyRelease).where(PolicyRelease.org_id == org_id)
                             .order_by(PolicyRelease.number.desc()).limit(limit))).scalars()
    return [_summary(r) for r in rows]


async def document(db: AsyncSession, org_id: int, release_id: Any) -> Dict[str, Any]:
    """A release as signed - both documents and every signature - for anyone
    who wants to check it without this server."""
    r = await _release(db, org_id, release_id)
    sigs = list((await db.execute(select(PolicyReleaseSignature).where(
        PolicyReleaseSignature.release_id == r.id).order_by(PolicyReleaseSignature.id))).scalars())
    gov = await db.get(PolicyRelease, r.governed_by_id) if r.governed_by_id else None
    return {"release": _summary(r), "bundle": r.bundle, "manifest": r.manifest,
            # the manifest that says who may sign this release (none: the first one, its own)
            "governed_by": None if gov is None else {"number": gov.number, "bundle_sha256": gov.bundle_sha256,
                                                     "bundle_version": gov.bundle.get("version"),
                                                     "manifest": gov.manifest, "manifest_sha256": gov.manifest_sha256},
            "signatures": [{"user_id": s.user_id, "credential_id": s.credential_id, "statement": s.statement,
                            "assertion": s.assertion} for s in sigs]}
