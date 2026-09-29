# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Ed25519 signing and verification for Agent-to-Agent Governance.

Every delegation hop and every agent action is signed with the acting
agent's Ed25519 private key. The server stores only the public key
(Agent.public_key), so it can verify but never forge - and an external
auditor can verify the whole chain offline, which is the accountability
property the EU AI Act asks for.

Implemented on the `cryptography` library (already a project dependency)
rather than PyNaCl, so no new dependency is added; Ed25519 is the same
standard either way.

Canonicalization: payloads are serialized with json.dumps(sort_keys=True,
separators=(",", ":")) so that the exact same dict always produces the
exact same bytes to sign/verify, regardless of key order or whitespace.
Both signer and verifier MUST use this same canonical form.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Tuple

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
    sorted keys, no incidental whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


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
