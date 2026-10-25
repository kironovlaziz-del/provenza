# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Credentials sealed to egress proxies (docs/pvp/edge.md, section 4): the
server stores ciphertext it cannot open.

A proxy holds an X25519 key, derived from its Ed25519 signing seed
(`proxy_encryption_key`, so its one key file holds both), and registers the
public half, signed by the signing key (`key_statement`).
A credential an administrator types in the browser is sealed there, once per
proxy, and only the envelopes reach this server:

    {"v": 1, "alg": "X25519-HKDF-SHA256-A256GCM", "proxy_id", "key_fingerprint",
     "context": {"org_id", "object", "object_id", "proxy_id", "upstream"},
     "epk": base64 (ephemeral X25519 public key),
     "nonce": base64 (12 bytes), "ct": base64 (AES-256-GCM, tag appended)}

    shared = X25519(ephemeral private, proxy public)
    key    = HKDF-SHA256(shared, salt = epk || proxy public,
                         info = "provenza sealed credential v1" || canonical(context), 32 bytes)
    ct     = AES-256-GCM(key, nonce, credential, aad = canonical(context))

The context binds a credential to the object it was entered for, to one
proxy and to the upstream it may be sent to (its origin: scheme, host,
port): the server cannot move a credential to another route, connection or
tool (the proxy opens an envelope only for the object it is using), hand
one proxy's envelope to another, or point the object somewhere else and
have the credential follow - the proxy sends it only to the sealed origin,
so an object whose address changed needs its credential sealed again.
Objects:

    route       egress route            (EgressRoute)
    provider    AI provider connection  (AIProvider)  - the API key
    mcp_server  MCP server              (MCPServer)   - the auth header's value
    a2a_peer    A2A peer                (A2APeer)     - the auth header's value
    http_tool   HTTP tool               (HttpTool)    - the auth header's value

A credential can also live only in the proxy's own configuration
(credential_source "local"); this server then never sees it at all.
"""

import base64
import os
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

from app.core.agent_signing import canonical_bytes, key_fingerprint

V = 1
ALG = "X25519-HKDF-SHA256-A256GCM"
INFO = b"provenza sealed credential v1"
ENCRYPTION_INFO = b"provenza proxy encryption key v1"
OBJECTS = ("route", "provider", "mcp_server", "a2a_peer", "http_tool")
SOURCES = ("none", "sealed", "local")
KEY_STATEMENT = "provenza.proxy.encryption_key"
MAX_CREDENTIAL = 8000


def key_statement(encryption_key: str) -> Dict[str, Any]:
    """What the proxy's signing key signs about its encryption key."""
    return {"type": KEY_STATEMENT, "v": 1, "key": encryption_key}


def proxy_encryption_key(signing_seed: bytes) -> X25519PrivateKey:
    """The X25519 key a proxy derives from its signing seed (proxy/internal/egress/sealed.go)."""
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=ENCRYPTION_INFO).derive(signing_seed)
    return X25519PrivateKey.from_private_bytes(raw)


def context(org_id: int, obj: str, object_id: int, proxy_id: int, upstream: str) -> Dict[str, Any]:
    return {"org_id": org_id, "object": obj, "object_id": object_id, "proxy_id": proxy_id, "upstream": upstream}


DEFAULT_PORTS = {"http": 80, "https": 443}


def origin(url: Optional[str]) -> Optional[str]:
    """scheme://host[:port] of a URL - lower case, the default port left out,
    an IPv6 host in brackets (proxy/internal/egress/sealed.go: the same)."""
    from urllib.parse import urlsplit

    if not url:
        return None
    try:
        u = urlsplit(url.strip())
        port = u.port
    except ValueError:
        return None
    scheme, host = (u.scheme or "").lower(), (u.hostname or "").lower()
    if scheme not in DEFAULT_PORTS or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port is not None and port != DEFAULT_PORTS[scheme] else "")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _derive(shared: bytes, epk: bytes, proxy_pub: bytes, ctx: Dict[str, Any]) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk + proxy_pub,
                info=INFO + canonical_bytes(ctx)).derive(shared)


def seal(credential: str, proxy_public_b64: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Seal a credential to one proxy (the server does this only once, for
    credentials it held before stage 9 - then it forgets them; the browser
    does it for everything entered since)."""
    return _seal(credential, proxy_public_b64, ctx, X25519PrivateKey.generate(), os.urandom(12))


def _seal(credential: str, proxy_public_b64: str, ctx: Dict[str, Any], eph: X25519PrivateKey,
          nonce: bytes) -> Dict[str, Any]:
    proxy_pub = base64.b64decode(proxy_public_b64)
    epk = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = _derive(eph.exchange(X25519PublicKey.from_public_bytes(proxy_pub)), epk, proxy_pub, ctx)
    ct = AESGCM(key).encrypt(nonce, credential.encode("utf-8"), canonical_bytes(ctx))
    return {"v": V, "alg": ALG, "proxy_id": ctx["proxy_id"], "key_fingerprint": key_fingerprint(proxy_public_b64),
            "context": ctx, "epk": _b64(epk), "nonce": _b64(nonce), "ct": _b64(ct)}


def open_sealed(envelope: Dict[str, Any], proxy_private: X25519PrivateKey) -> str:
    """The proxy's side, for tests (proxy/internal/egress does it in Go)."""
    proxy_pub = proxy_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    epk = base64.b64decode(envelope["epk"])
    key = _derive(proxy_private.exchange(X25519PublicKey.from_public_bytes(epk)), epk, proxy_pub,
                  envelope["context"])
    return AESGCM(key).decrypt(base64.b64decode(envelope["nonce"]), base64.b64decode(envelope["ct"]),
                               canonical_bytes(envelope["context"])).decode("utf-8")


def envelope_problem(envelope: Any, ctx: Dict[str, Any], encryption_key: Optional[str]) -> Optional[str]:
    """Why an envelope cannot be stored for this object and proxy, or None.
    The server cannot open it; it checks only that it is addressed right."""
    if not isinstance(envelope, dict):
        return "not an envelope"
    if set(envelope) != {"v", "alg", "proxy_id", "key_fingerprint", "context", "epk", "nonce", "ct"}:
        return "unexpected fields"
    if envelope.get("v") != V or envelope.get("alg") != ALG:
        return "unknown version or algorithm"
    if envelope.get("context") != ctx or envelope.get("proxy_id") != ctx["proxy_id"]:
        return "sealed for another object or proxy"
    if not encryption_key or envelope.get("key_fingerprint") != key_fingerprint(encryption_key):
        return "sealed to another key than the proxy's"
    try:
        epk, nonce, ct = (base64.b64decode(envelope[k], validate=True) for k in ("epk", "nonce", "ct"))
    except (ValueError, TypeError):
        return "not base64"
    if len(epk) != 32 or len(nonce) != 12 or not 16 < len(ct) <= MAX_CREDENTIAL + 16:
        return "wrong sizes"
    return None
