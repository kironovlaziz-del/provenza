# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Signed action permits.

An allowed /agents/actions/check comes with a permit: a compact JWS (EdDSA,
Ed25519) signed by the organization's permit key, that the agent hands to
the tool. The tool verifies it against the organization's JWKS and refuses
to run without a valid one (sdk/python provenza.permit, sdk/js permit.ts):

    header  {"alg": "EdDSA", "typ": "provenza-permit+jwt", "kid": "<key id>"}
    claims  {"iss": "provenza:org:<slug>", "sub": "agent:<id>",
             "aud": "<tool name>", "jti": "<permit id>",
             "iat": ..., "nbf": ..., "exp": <the check's expiry>,
             "act": "<action type>", "chain": <chain id or null>,
             "ish": "<SHA-256 of the canonical input>"}

  - one action: the tool computes the hash of the input it received and
    compares it with "ish"; another input, another tool or another time is
    refused;
  - one use: POST /pvp/permits/redeem marks the permit redeemed exactly once
    (any replica of the tool, anywhere); a tool that cannot reach Provenza
    still refuses repeats it has seen itself;
  - bound to the record: the permit belongs to the check (permit_jti), so the
    action recorded under that check carries the permit id and whether a
    tool redeemed it - the record says the tool, not only the agent, saw
    the permit.

The permit key is not the audit key: it signs online, on every allowed
check. Rotation keeps the retired key in the JWKS for KEY_GRACE, longer than
any permit lives.
"""

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import status
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import agent_signing as sig
from app.core.crypto import decrypt_secret, encrypt_secret
from app.core.errors import api_error
from app.models.agent_action import ActionCheck, PermitSigningKey
from app.models.organization import Organization
from app.pvp import jcs

TYP = "provenza-permit+jwt"
HEADER = "Provenza-Permit"
KEY_GRACE = timedelta(hours=1)
LEEWAY_SECONDS = 30
MAX_TOKEN_BYTES = 4096

_PRIVATE: Dict[int, Ed25519PrivateKey] = {}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issuer(slug: str) -> str:
    return f"provenza:org:{slug}"


# ---------------------------------------------------------------- keys

async def _new_key(db: AsyncSession, org_id: int) -> PermitSigningKey:
    priv, pub = sig.generate_keypair()
    key = PermitSigningKey(org_id=org_id, kid="pk_" + secrets.token_hex(12), public_key=pub,
                           private_key_enc=encrypt_secret(priv))
    db.add(key)
    await db.flush()
    return key


async def current_key(db: AsyncSession, org_id: int) -> PermitSigningKey:
    key = (await db.execute(
        select(PermitSigningKey).where(PermitSigningKey.org_id == org_id, PermitSigningKey.retired_at.is_(None))
        .order_by(PermitSigningKey.id.desc()).limit(1)
    )).scalar_one_or_none()
    return key or await _new_key(db, org_id)


async def rotate(db: AsyncSession, org_id: int) -> PermitSigningKey:
    """A new permit key; the old ones stay in the JWKS for KEY_GRACE. The caller commits."""
    now = datetime.now(timezone.utc)
    await db.execute(update(PermitSigningKey).where(PermitSigningKey.org_id == org_id,
                                                    PermitSigningKey.retired_at.is_(None)).values(retired_at=now))
    return await _new_key(db, org_id)


def _jwk(key: PermitSigningKey) -> Dict[str, str]:
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(base64.b64decode(key.public_key)), "kid": key.kid,
            "use": "sig", "alg": "EdDSA"}


async def jwks(db: AsyncSession, org_id: int) -> Dict[str, List[Dict[str, str]]]:
    """The keys a tool may accept permits from: the current one, and keys
    retired less than KEY_GRACE ago."""
    since = datetime.now(timezone.utc) - KEY_GRACE
    keys = (await db.execute(
        select(PermitSigningKey).where(PermitSigningKey.org_id == org_id,
                                       or_(PermitSigningKey.retired_at.is_(None),
                                           PermitSigningKey.retired_at > since))
        .order_by(PermitSigningKey.id.desc())
    )).scalars().all()
    return {"keys": [_jwk(k) for k in keys]}


# ---------------------------------------------------------------- issue

def _unix(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


async def issue(db: AsyncSession, chk: ActionCheck) -> str:
    """The permit for an allowed check; sets chk.permit_jti. The caller commits."""
    slug = (await db.execute(select(Organization.slug).where(Organization.id == chk.org_id))).scalar_one()
    key = await current_key(db, chk.org_id)
    now = int(datetime.now(timezone.utc).timestamp())
    jti = secrets.token_urlsafe(24)
    claims = {"iss": issuer(slug), "sub": f"agent:{chk.agent_id}", "aud": chk.tool_name, "jti": jti,
              "iat": now, "nbf": now, "exp": _unix(chk.expires_at), "act": chk.action_type,
              "chain": chk.chain_id, "ish": chk.input_sha256}
    header = {"alg": "EdDSA", "typ": TYP, "kid": key.kid}
    signing_input = f"{b64url(jcs.canonicalize(header))}.{b64url(jcs.canonicalize(claims))}".encode("ascii")
    if key.id not in _PRIVATE:
        _PRIVATE[key.id] = Ed25519PrivateKey.from_private_bytes(base64.b64decode(decrypt_secret(key.private_key_enc)))
    chk.permit_jti = jti
    return signing_input.decode("ascii") + "." + b64url(_PRIVATE[key.id].sign(signing_input))


# ---------------------------------------------------------------- verify / redeem

def _refuse(code: str, http: int = status.HTTP_400_BAD_REQUEST):
    return api_error(http, code)


async def verify(db: AsyncSession, token: str) -> Dict[str, Any]:
    """The claims of a permit this server signed, if the signature holds and
    it has not expired. Raises 400 permit.invalid / 401 permit.expired."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES or token.count(".") != 2:
        raise _refuse("permit.invalid")
    h64, c64, s64 = token.split(".")
    try:
        header = json.loads(_unb64url(h64))
        claims = json.loads(_unb64url(c64))
        signature = _unb64url(s64)
    except (ValueError, UnicodeDecodeError):
        raise _refuse("permit.invalid")
    if not isinstance(header, dict) or not isinstance(claims, dict) or header.get("alg") != "EdDSA" \
            or header.get("typ") != TYP or not isinstance(header.get("kid"), str):
        raise _refuse("permit.invalid")
    key = (await db.execute(select(PermitSigningKey).where(PermitSigningKey.kid == header["kid"]))).scalar_one_or_none()
    if key is None or (key.retired_at is not None and key.retired_at < datetime.now(timezone.utc) - KEY_GRACE):
        raise _refuse("permit.invalid")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key.public_key)).verify(
            signature, f"{h64}.{c64}".encode("ascii"))
    except (InvalidSignature, ValueError):
        raise _refuse("permit.invalid")
    now = datetime.now(timezone.utc).timestamp()
    exp, nbf = claims.get("exp"), claims.get("nbf")
    if not isinstance(exp, int) or not isinstance(nbf, int) or now > exp + LEEWAY_SECONDS:
        raise _refuse("permit.expired", status.HTTP_401_UNAUTHORIZED)
    if now < nbf - LEEWAY_SECONDS:
        raise _refuse("permit.invalid")
    claims["_org_id"] = key.org_id
    return claims


async def redeem(db: AsyncSession, token: str, *, tool: Optional[str] = None,
                 input_sha256: Optional[str] = None) -> Dict[str, Any]:
    """Mark a permit used - once, whoever asks. `tool` and `input_sha256` are
    what the tool is about to run; a permit for anything else is refused
    and stays unused. The caller commits."""
    claims = await verify(db, token)
    if (tool is not None and tool != claims.get("aud")) or \
            (input_sha256 is not None and input_sha256 != claims.get("ish")):
        raise _refuse("permit.mismatch", status.HTTP_403_FORBIDDEN)
    now = datetime.now(timezone.utc)
    done = await db.execute(
        update(ActionCheck).where(ActionCheck.org_id == claims["_org_id"], ActionCheck.permit_jti == claims["jti"],
                                  ActionCheck.permit_redeemed_at.is_(None))
        .values(permit_redeemed_at=now).returning(ActionCheck.id)
    )
    if done.scalar_one_or_none() is None:
        raise _refuse("permit.redeemed", status.HTTP_409_CONFLICT)
    return {"redeemed": True, "jti": claims["jti"], "agent_id": int(str(claims["sub"]).split(":", 1)[1]),
            "tool": claims["aud"], "action_type": claims.get("act"), "chain_id": claims.get("chain"),
            "expires_at": claims["exp"]}
