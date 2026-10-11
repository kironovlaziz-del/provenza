# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Keys, canonical form and signatures - exactly the server's rules
(backend/app/core/agent_signing.py, docs/agent-signing.md):

  canonical form   json.dumps(payload, sort_keys=True, separators=(",", ":")):
                   sorted keys, no whitespace, non-ASCII as \\uXXXX
  content hash     SHA-256 hex of the canonical form of a value (null too)
  fingerprint      "SHA256:" + unpadded base64 of SHA-256 over the raw
                   Ed25519 key, followed by the raw ML-DSA-65 key if hybrid
  hybrid           Ed25519 AND ML-DSA-65 over the same bytes (needs
                   cryptography >= 48: pip install provenza[pq])
"""

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(payload: Any) -> bytes:
    """Refuses NaN / Infinity: the server cannot accept them, and they have
    no JSON form another implementation would agree on."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def fingerprint(public_key: str, pq_public_key: Optional[str] = None) -> str:
    raw = base64.b64decode(public_key) + (base64.b64decode(pq_public_key) if pq_public_key else b"")
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError as exc:  # pragma: no cover - depends on the installed cryptography
        raise RuntimeError("hybrid (post-quantum) keys need cryptography >= 48: pip install 'provenza[pq]'") from exc
    return mldsa


@dataclass(frozen=True)
class Keys:
    """An agent's signing keys (base64 of the raw keys; the ML-DSA private
    key is its 32-byte seed). Private keys never leave the agent."""
    private_key: str
    public_key: str
    pq_private_key: Optional[str] = None
    pq_public_key: Optional[str] = None

    @classmethod
    def generate(cls, hybrid: bool = False) -> "Keys":
        ed = Ed25519PrivateKey.generate()
        pq_priv = pq_pub = None
        if hybrid:
            pk = _mldsa().MLDSA65PrivateKey.generate()
            pq_priv = base64.b64encode(pk.private_bytes_raw()).decode()
            pq_pub = base64.b64encode(pk.public_key().public_bytes_raw()).decode()
        return cls(base64.b64encode(ed.private_bytes_raw()).decode(),
                   base64.b64encode(ed.public_key().public_bytes_raw()).decode(), pq_priv, pq_pub)

    @property
    def hybrid(self) -> bool:
        return self.pq_public_key is not None

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key, self.pq_public_key)

    def sign(self, payload: Dict[str, Any]) -> Tuple[str, Optional[str]]:
        """(Ed25519 signature, ML-DSA-65 signature or None), base64, over
        the canonical form of the payload."""
        msg = canonical(payload)
        sig = base64.b64encode(Ed25519PrivateKey.from_private_bytes(base64.b64decode(self.private_key)).sign(msg))
        pq = None
        if self.pq_private_key:
            pk = _mldsa().MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(self.pq_private_key))
            pq = base64.b64encode(pk.sign(msg)).decode()
        return sig.decode(), pq
