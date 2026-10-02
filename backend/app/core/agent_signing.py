# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Ed25519 signing and verification for Agent-to-Agent Governance.

Every delegation hop and every agent action is signed with the acting
agent's Ed25519 private key. The server stores only public keys, so an
auditor can verify the whole history offline.

Who can forge depends on where the private key was made:
  - agent-held key (recommended): the agent generates its keypair and
    registers only the public key (AgentCreate.public_key or
    POST /agents/{id}/signing-key). The server never sees the private key
    and cannot sign as the agent;
  - server-generated key (quick start): the server creates the pair at
    registration and returns the private key once. It is not stored, but
    the server had it at that moment - Agent.key_origin = "server" says so.
Each signed record keeps the public key that verified it
(signer_public_key), so key changes never break old signatures, and the
key's fingerprint (key_fingerprint) lets an auditor compare it with the
one the agent's owner holds, independently of this server.

Implemented on the `cryptography` library (already a project dependency)
rather than PyNaCl, so no new dependency is added; Ed25519 is the same
standard either way.

Canonicalization (docs/agent-signing.md has the full specification):
payloads are serialized with json.dumps(sort_keys=True, separators=(",", ":"))
- keys sorted at every level, no whitespace, non-ASCII characters escaped
as \\uXXXX (Python's default ensure_ascii=True), integers only. The result
is pure ASCII, so the signed bytes and the signed text are the same thing;
verification endpoints return that text (signed_message) so a verifier
checks the exact bytes instead of re-serializing.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> Tuple[str, str]:
    """
    Generate a new Ed25519 keypair. Returns (private_key_b64,
    public_key_b64), both base64-encoded raw keys.

    The private key is returned to the agent ONCE at registration and
    never stored server-side; only the public key is persisted.
    """
    private_key = Ed25519PrivateKey.generate()
    priv_raw = private_key.private_bytes_raw()
    pub_raw = private_key.public_key().public_bytes_raw()
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


def canonical_bytes(payload: Dict[str, Any]) -> bytes:
    """The exact byte form that gets signed/verified. Deterministic:
    sorted keys, no incidental whitespace, ASCII only."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_text(payload: Dict[str, Any]) -> str:
    """canonical_bytes as text (it is pure ASCII) - what verifiers sign/check."""
    return canonical_bytes(payload).decode("ascii")


# --- Ed25519 point validation (RFC 8032 arithmetic) -------------------------
# The `cryptography` library accepts any 32 bytes as a public key. A
# small-order point (the identity, or one of the other 7 points of order
# dividing 8) makes a fixed "signature" verify for EVERY message - whoever
# registers such a key gets signatures that prove nothing. So a key must be
# a canonical encoding of a point in the prime-order subgroup.
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _decode_point(raw: bytes):
    """Extended coordinates (X, Y, Z, T) of an encoded point, or None if the
    encoding is non-canonical or not on the curve."""
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    sign = raw[31] >> 7
    if y >= _P:
        return None
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if x == 0 and sign:
        return None  # non-canonical encoding of x = 0
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * _D * t1 * t2 % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(k: int, p):
    q = (0, 1, 1, 0)
    while k:
        if k & 1:
            q = _add(q, p)
        p = _add(p, p)
        k >>= 1
    return q


def _is_identity(p) -> bool:
    x, y, z, _ = p
    return x % _P == 0 and (y - z) % _P == 0


def normalize_public_key(value: str) -> str:
    """Validate an Ed25519 public key given as base64 of the 32 raw bytes and
    return it in canonical base64. Rejects encodings that are not a point,
    non-canonical encodings and points outside the prime-order subgroup
    (small-order / mixed-order points). Raises ValueError."""
    try:
        raw = base64.b64decode((value or "").strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("public_key must be base64 of a raw 32-byte Ed25519 public key") from exc
    if len(raw) != 32:
        raise ValueError(f"public_key must be 32 bytes (Ed25519), got {len(raw)}")
    point = _decode_point(raw)
    if point is None:
        raise ValueError("public_key is not a valid Ed25519 point")
    if _is_identity(_mul(8, point)) or not _is_identity(_mul(_L, point)):
        raise ValueError("public_key is a weak (small-order) Ed25519 key; generate a new key pair")
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise ValueError("public_key is not a valid Ed25519 public key") from exc
    return base64.b64encode(raw).decode()


@lru_cache(maxsize=4096)
def _strong_key(public_key_b64: str) -> bool:
    try:
        normalize_public_key(public_key_b64)
        return True
    except ValueError:
        return False


def key_fingerprint(public_key_b64: Optional[str], pq_public_key_b64: Optional[str] = None) -> Optional[str]:
    """Fingerprint of an agent's signing key(s): "SHA256:" + unpadded base64
    of SHA-256 over the raw Ed25519 key (32 bytes), followed - for a hybrid
    key - by the raw ML-DSA-65 key (1952 bytes). One short value covers
    both keys; the browser and tools/provenza_sign.py compute it themselves."""
    if not public_key_b64:
        return None
    try:
        raw = base64.b64decode(public_key_b64)
        if pq_public_key_b64:
            raw += base64.b64decode(pq_public_key_b64)
    except (binascii.Error, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def sign_payload(payload: Dict[str, Any], private_key_b64: str) -> str:
    """Sign a payload with a base64 Ed25519 private key; returns the
    base64 signature. (Used by the SDK / agent side, and in tests.)"""
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    sig = priv.sign(canonical_bytes(payload))
    return base64.b64encode(sig).decode()


def verify_payload(payload: Dict[str, Any], signature_b64: str, public_key_b64: str) -> bool:
    """
    Verify a payload's signature against a base64 Ed25519 public key.
    Returns True/False, never raises - a malformed key or signature is
    just an unverified payload, not a server error.
    """
    if not signature_b64 or not public_key_b64:
        return False
    if not _strong_key(public_key_b64):
        return False  # a small-order key "verifies" anything - never trust it
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def content_hash(obj) -> str:
    """SHA-256 hex of the canonical JSON form of obj (dict, list or None).
    Used to bind a recorded action to exactly the input/output that was
    checked and signed, without putting the raw data in the signature."""
    import hashlib
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Hybrid post-quantum signatures: Ed25519 + ML-DSA-65 (FIPS 204)
# ---------------------------------------------------------------------------
# An agent with an ML-DSA-65 key signs every record twice, over the SAME
# canonical bytes: once with Ed25519, once with ML-DSA-65 (pure ML-DSA,
# empty context). A record is valid only if BOTH verify, so a forgery needs
# both the classical and the post-quantum scheme broken - Ed25519 falls to
# a large quantum computer, ML-DSA is young; together they cover each other.
# ML-DSA comes from `cryptography` >= 48 (no extra dependency).

SCHEME_CLASSIC = "ed25519"
SCHEME_HYBRID = "ed25519+ml-dsa-65"
MLDSA65_PUBLIC_KEY_BYTES = 1952
MLDSA65_SIGNATURE_BYTES = 3309


def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:  # pragma: no cover - cryptography < 48
        raise RuntimeError("ML-DSA needs cryptography >= 48 on the server") from exc
    return mldsa


def pq_available() -> bool:
    try:
        _mldsa()
        return True
    except RuntimeError:
        return False


def normalize_pq_public_key(value: str) -> str:
    """Validate an ML-DSA-65 public key (base64 of the 1952 raw bytes) and
    return it in canonical base64. Raises ValueError."""
    try:
        raw = base64.b64decode((value or "").strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("pq_public_key must be base64 of a raw ML-DSA-65 public key") from exc
    if len(raw) != MLDSA65_PUBLIC_KEY_BYTES:
        raise ValueError(f"pq_public_key must be {MLDSA65_PUBLIC_KEY_BYTES} bytes (ML-DSA-65), got {len(raw)}")
    try:
        _mldsa().MLDSA65PublicKey.from_public_bytes(raw)
    except RuntimeError as exc:  # cryptography < 48: a clear 422, not a 500
        raise ValueError(str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise ValueError("pq_public_key is not a valid ML-DSA-65 public key") from exc
    return base64.b64encode(raw).decode()


def generate_pq_keypair() -> Tuple[str, str]:
    """(seed_b64, public_key_b64) for ML-DSA-65. The 32-byte seed is the
    private key (FIPS 204 seed form)."""
    key = _mldsa().MLDSA65PrivateKey.generate()
    return (base64.b64encode(key.private_bytes_raw()).decode(),
            base64.b64encode(key.public_key().public_bytes_raw()).decode())


def sign_payload_pq(payload: Dict[str, Any], seed_b64: str) -> str:
    key = _mldsa().MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(seed_b64))
    return base64.b64encode(key.sign(canonical_bytes(payload))).decode()


def verify_payload_pq(payload: Dict[str, Any], signature_b64: Optional[str], public_key_b64: Optional[str]) -> bool:
    """ML-DSA-65 over the canonical bytes; False on anything malformed."""
    if not signature_b64 or not public_key_b64:
        return False
    try:
        pub = _mldsa().MLDSA65PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        pub.verify(base64.b64decode(signature_b64, validate=True), canonical_bytes(payload))
        return True
    except Exception:  # noqa: BLE001 - invalid / malformed = not verified
        return False


def verify_agent_signature(payload: Dict[str, Any], signature: Optional[str], pq_signature: Optional[str],
                           public_key: Optional[str], pq_public_key: Optional[str]) -> bool:
    """The rule every verifier applies: Ed25519 must verify, and when the
    signer has an ML-DSA key, ML-DSA must verify too (AND, never OR)."""
    if not verify_payload(payload, signature or "", public_key or ""):
        return False
    if pq_public_key:
        return verify_payload_pq(payload, pq_signature, pq_public_key)
    return True


def scheme_of(pq_public_key: Optional[str]) -> str:
    return SCHEME_HYBRID if pq_public_key else SCHEME_CLASSIC
