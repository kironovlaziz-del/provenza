# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Passkeys (WebAuthn Level 2) - the anchor of an administrator's signatures
(docs/pvp/edge.md, section 2).

Only what Provenza needs, checked strictly:

  registration   clientDataJSON (type "webauthn.create", the challenge we
                 issued, an allowed origin), authenticator data (rpIdHash,
                 user present AND user verified - the device PIN or
                 biometric - and an attested credential). The attestation
                 statement is not verified: Provenza trusts the device the
                 administrator chose, not its maker ("none" is requested).
  assertion      clientDataJSON (type "webauthn.get", the expected
                 challenge, an allowed origin), rpIdHash, UP and UV, the
                 signature over authenticatorData || SHA-256(clientDataJSON)
                 with the registered key, and a signature counter that
                 never goes back (a cloned authenticator).

A statement is signed by putting SHA-256 of its canonical JSON in the
challenge: whoever holds the passkey confirmed exactly that statement.

Keys: ES256 (COSE -7, P-256), EdDSA (-8, Ed25519) and RS256 (-257, Windows
Hello). The relying party is the host of the first CORS origin
(WEBAUTHN_RP_ID overrides it); allowed origins are CORS_ORIGINS.
"""

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from app.core import cbor
from app.core.config import settings

ES256, EDDSA, RS256 = -7, -8, -257
ALGS = (ES256, EDDSA, RS256)
FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80


class WebAuthnError(ValueError):
    """code: an error code for the API (webauthn.*)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > 100_000:
        raise WebAuthnError("webauthn.bad_encoding")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise WebAuthnError("webauthn.bad_encoding")


def origins() -> List[str]:
    return [o.strip().rstrip("/") for o in settings.CORS_ORIGINS.split(",") if o.strip()]


def rp_id() -> str:
    if settings.WEBAUTHN_RP_ID:
        return settings.WEBAUTHN_RP_ID
    first = origins()[0] if origins() else "http://localhost"
    return urlparse(first).hostname or "localhost"


def statement_challenge(statement: Dict[str, Any]) -> bytes:
    """What a passkey signs for a statement: SHA-256 of its canonical JSON
    (sorted keys, no whitespace, ASCII - app/core/agent_signing.canonical_bytes)."""
    from app.core.agent_signing import canonical_bytes

    return hashlib.sha256(canonical_bytes(statement)).digest()


@dataclass
class AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: Optional[bytes] = None
    cose_key: Optional[Dict[int, Any]] = None
    cose_key_bytes: Optional[bytes] = None


def parse_auth_data(raw: bytes) -> AuthData:
    if len(raw) < 37:
        raise WebAuthnError("webauthn.bad_authenticator_data")
    ad = AuthData(rp_id_hash=raw[:32], flags=raw[32], sign_count=int.from_bytes(raw[33:37], "big"))
    pos = 37
    if ad.flags & FLAG_AT:
        if len(raw) < pos + 18:
            raise WebAuthnError("webauthn.bad_authenticator_data")
        pos += 16                                   # AAGUID: not used
        n = int.from_bytes(raw[pos:pos + 2], "big")
        pos += 2
        if n < 16 or n > 1023 or len(raw) < pos + n:
            raise WebAuthnError("webauthn.bad_authenticator_data")
        ad.credential_id = raw[pos:pos + n]
        pos += n
        try:
            key, used = cbor.load_prefix(raw[pos:])
        except cbor.CBORError:
            raise WebAuthnError("webauthn.bad_public_key")
        if not isinstance(key, dict):
            raise WebAuthnError("webauthn.bad_public_key")
        ad.cose_key, ad.cose_key_bytes = key, raw[pos:pos + used]
        pos += used
    if ad.flags & FLAG_ED:
        try:
            _, used = cbor.load_prefix(raw[pos:])
        except cbor.CBORError:
            raise WebAuthnError("webauthn.bad_authenticator_data")
        pos += used
    if pos != len(raw):
        raise WebAuthnError("webauthn.bad_authenticator_data")
    return ad


def public_key(cose: Dict[int, Any]):
    """(algorithm, key) from a COSE_Key - only the forms passkeys use."""
    kty, alg = cose.get(1), cose.get(3)
    if alg == ES256 and kty == 2 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
            raise WebAuthnError("webauthn.bad_public_key")
        try:
            return alg, ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                       ec.SECP256R1()).public_key()
        except ValueError:
            raise WebAuthnError("webauthn.bad_public_key")
    if alg == EDDSA and kty == 1 and cose.get(-1) == 6:
        x = cose.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise WebAuthnError("webauthn.bad_public_key")
        return alg, ed25519.Ed25519PublicKey.from_public_bytes(x)
    if alg == RS256 and kty == 3:
        n, e = cose.get(-1), cose.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes) and 256 <= len(n) <= 512):
            raise WebAuthnError("webauthn.bad_public_key")
        return alg, rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
    raise WebAuthnError("webauthn.unsupported_algorithm")


def spki(public_key_cose: str) -> str:
    """A stored COSE public key as base64 SubjectPublicKeyInfo (DER), the
    form an offline verifier loads (tools/provenza_audit.py)."""
    from cryptography.hazmat.primitives import serialization

    _, key = public_key(cbor.loads(b64url_decode(public_key_cose)))
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode("ascii")


def passkey_fingerprint(public_key_cose: str) -> str:
    """SHA256:<base64 of SHA-256 of the SPKI> - the passkey as an offline
    verifier names it."""
    digest = hashlib.sha256(base64.b64decode(spki(public_key_cose))).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _client_data(raw: bytes, kind: str, challenge: bytes) -> Dict[str, Any]:
    try:
        cd = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("webauthn.bad_client_data")
    if not isinstance(cd, dict) or cd.get("type") != kind:
        raise WebAuthnError("webauthn.bad_client_data")
    if cd.get("challenge") != b64url(challenge):
        raise WebAuthnError("webauthn.challenge_mismatch")
    if str(cd.get("origin", "")).rstrip("/") not in origins():
        raise WebAuthnError("webauthn.origin_mismatch")
    if cd.get("crossOrigin") is True:
        raise WebAuthnError("webauthn.bad_client_data")
    return cd


def _flags(ad: AuthData) -> None:
    if ad.rp_id_hash != hashlib.sha256(rp_id().encode("idna")).digest():
        raise WebAuthnError("webauthn.rp_mismatch")
    if not ad.flags & FLAG_UP:
        raise WebAuthnError("webauthn.user_not_present")
    if not ad.flags & FLAG_UV:
        raise WebAuthnError("webauthn.user_not_verified")    # no PIN / biometric


@dataclass
class Registered:
    credential_id: str          # base64url
    public_key: str             # base64url COSE key
    alg: int
    sign_count: int


def verify_registration(client_data_json: str, attestation_object: str, challenge: bytes) -> Registered:
    cd_raw = b64url_decode(client_data_json)
    _client_data(cd_raw, "webauthn.create", challenge)
    try:
        att = cbor.loads(b64url_decode(attestation_object))
    except cbor.CBORError:
        raise WebAuthnError("webauthn.bad_attestation")
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise WebAuthnError("webauthn.bad_attestation")
    ad = parse_auth_data(att["authData"])
    _flags(ad)
    if ad.credential_id is None or ad.cose_key is None:
        raise WebAuthnError("webauthn.no_credential")
    alg, _ = public_key(ad.cose_key)
    return Registered(credential_id=b64url(ad.credential_id), public_key=b64url(ad.cose_key_bytes), alg=alg,
                      sign_count=ad.sign_count)


def verify_assertion(*, public_key_cose: str, stored_sign_count: int, client_data_json: str,
                     authenticator_data: str, signature: str, challenge: bytes) -> int:
    """Verify one assertion; returns the new signature counter."""
    cd_raw = b64url_decode(client_data_json)
    _client_data(cd_raw, "webauthn.get", challenge)
    ad_raw = b64url_decode(authenticator_data)
    ad = parse_auth_data(ad_raw)
    _flags(ad)
    try:
        cose = cbor.loads(b64url_decode(public_key_cose))
    except cbor.CBORError:
        raise WebAuthnError("webauthn.bad_public_key")
    alg, key = public_key(cose)
    signed = ad_raw + hashlib.sha256(cd_raw).digest()
    sig = b64url_decode(signature)
    try:
        if alg == ES256:
            key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == EDDSA:
            key.verify(sig, signed)
        else:
            key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise WebAuthnError("webauthn.bad_signature")
    # a counter that does not grow means a cloned authenticator - unless the
    # device does not count at all (always 0, as most synced passkeys)
    if (ad.sign_count or stored_sign_count) and ad.sign_count <= stored_sign_count:
        raise WebAuthnError("webauthn.counter_regressed")
    return ad.sign_count


def verify_assertion_spki(*, public_key_spki: str, alg: int, client_data_json: str, authenticator_data: str,
                          signature: str, challenge: bytes) -> None:
    """Check again, later, an assertion that was accepted when it was made
    (a release signature, app/pvp/signed_policy.py): the key from a signed
    manifest (SPKI), this challenge, the person verified. Origin, relying
    party and counter were checked when it was accepted and are not repeated:
    a later change of the site's address must not undo signed decisions."""
    from cryptography.hazmat.primitives import serialization

    cd_raw = b64url_decode(client_data_json)
    try:
        cd = json.loads(cd_raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("webauthn.bad_client_data")
    if not isinstance(cd, dict) or cd.get("type") != "webauthn.get" or cd.get("challenge") != b64url(challenge):
        raise WebAuthnError("webauthn.challenge_mismatch")
    ad_raw = b64url_decode(authenticator_data)
    ad = parse_auth_data(ad_raw)
    if not ad.flags & FLAG_UP or not ad.flags & FLAG_UV:
        raise WebAuthnError("webauthn.user_not_verified")
    try:
        key = serialization.load_der_public_key(base64.b64decode(public_key_spki))
    except (ValueError, TypeError):
        raise WebAuthnError("webauthn.bad_public_key")
    signed, sig = ad_raw + hashlib.sha256(cd_raw).digest(), b64url_decode(signature)
    try:
        if alg == ES256 and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == EDDSA and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, signed)
        elif alg == RS256 and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise WebAuthnError("webauthn.unsupported_algorithm")
    except InvalidSignature:
        raise WebAuthnError("webauthn.bad_signature")
