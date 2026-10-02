#!/usr/bin/env python3
# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Provenza signing keys and evidence - standalone, needs only `cryptography`
(pip install cryptography). It does not talk to a Provenza server, so what
it says does not depend on trusting one.

  keygen [--hybrid]            new key pair for an agent: Ed25519, plus
                               ML-DSA-65 with --hybrid (post-quantum). Keep
                               the private keys with the agent, register
                               only the public keys in Provenza
  fingerprint PUBLIC_KEY [PQ_PUBLIC_KEY]
                               "SHA256:..." fingerprint of the key(s)
  sign PRIVATE_KEY FILE.json [--pq-private-key SEED]
                               sign a payload (canonical form, see below);
                               with a hybrid key prints both signatures
  verify EVIDENCE.json [--fingerprint SHA256:...]
                               check an evidence file downloaded from
                               Provenza; with --fingerprint, also require the
                               signer key to be the one you expect (get it
                               from the agent's owner, not from the server)

Canonical form (docs/agent-signing.md): json.dumps(payload, sort_keys=True,
separators=(",", ":")) - sorted keys, no whitespace, non-ASCII escaped as
\\uXXXX, integers only. The signature is over those ASCII bytes.

Hybrid keys (Ed25519 + ML-DSA-65, FIPS 204): the record is valid only if
BOTH signatures verify over the same bytes. ML-DSA needs cryptography >= 48.

Exit status: 0 = verified, 1 = not verified, 2 = usage / input error.
"""

import argparse
import base64
import hashlib
import json
import sys

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:  # pragma: no cover
    sys.exit("this tool needs the 'cryptography' package: pip install cryptography")


# Ed25519 point check (RFC 8032). `cryptography` accepts any 32 bytes as a
# key; a small-order key makes a fixed "signature" verify for every message.
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _point(raw: bytes):
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    sign = raw[31] >> 7
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P or (x == 0 and sign):
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * _D * p[3] * q[3] % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(k, p):
    q = (0, 1, 1, 0)
    while k:
        if k & 1:
            q = _add(q, p)
        p, k = _add(p, p), k >> 1
    return q


def strong_key(raw: bytes) -> bool:
    """Canonical encoding of a point in the prime-order subgroup."""
    def ident(p):
        return p[0] % _P == 0 and (p[1] - p[2]) % _P == 0
    pt = _point(raw) if len(raw) == 32 else None
    return bool(pt) and not ident(_mul(8, pt)) and ident(_mul(_L, pt))


def canonical(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def fingerprint(public_key_b64: str, pq_public_key_b64: str = None) -> str:
    raw = base64.b64decode(public_key_b64) + (base64.b64decode(pq_public_key_b64) if pq_public_key_b64 else b"")
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        raise ValueError("ML-DSA needs cryptography >= 48: pip install -U cryptography")
    return mldsa


def cmd_keygen(args) -> int:
    key = Ed25519PrivateKey.generate()
    priv = base64.b64encode(key.private_bytes_raw()).decode()
    pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    pq_priv = pq_pub = None
    if args.hybrid:
        pk = _mldsa().MLDSA65PrivateKey.generate()
        pq_priv = base64.b64encode(pk.private_bytes_raw()).decode()
        pq_pub = base64.b64encode(pk.public_key().public_bytes_raw()).decode()
    print(f"private_key     {priv}    <- stays with the agent; never send it anywhere")
    if pq_priv:
        print(f"pq_private_key  {pq_priv}    <- ML-DSA-65 seed, stays with the agent too")
    print(f"public_key      {pub}    <- register this in Provenza")
    if pq_pub:
        print(f"pq_public_key   {pq_pub}    <- and this (ML-DSA-65)")
    print(f"fingerprint     {fingerprint(pub, pq_pub)}    <- give this to whoever audits the agent")
    return 0


def cmd_fingerprint(args) -> int:
    print(fingerprint(args.public_key, args.pq_public_key))
    if not strong_key(base64.b64decode(args.public_key)):
        print("WARNING: weak (small-order) or invalid Ed25519 key - signatures made with it prove nothing")
        return 1
    if args.pq_public_key:
        try:
            _mldsa().MLDSA65PublicKey.from_public_bytes(base64.b64decode(args.pq_public_key, validate=True))
        except Exception:  # noqa: BLE001 - wrong length / not a key
            print("WARNING: not a valid ML-DSA-65 public key (1952 bytes) - this fingerprint matches nothing real")
            return 1
    return 0


def cmd_sign(args) -> int:
    with open(args.file, encoding="utf-8") as f:
        payload = json.load(f)
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(args.private_key))
    sig = base64.b64encode(key.sign(canonical(payload))).decode()
    if not args.pq_private_key:
        print(sig)
        return 0
    pk = _mldsa().MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(args.pq_private_key))
    print(json.dumps({"signature": sig, "pq_signature": base64.b64encode(pk.sign(canonical(payload))).decode()}))
    return 0


def cmd_verify(args) -> int:
    with open(args.evidence, encoding="utf-8") as f:
        ev = json.load(f)
    sig, pub, msg = ev.get("signature"), ev.get("public_key"), ev.get("signed_message")
    if not sig or not pub:
        print("NOT VERIFIED: the record carries no signature")
        return 1
    if msg is None:
        msg = canonical(ev.get("signed_payload")).decode("ascii")
    # The message must be the canonical form of the payload it claims to be,
    # so what you read in signed_payload is exactly what was signed.
    try:
        parsed = json.loads(msg)
    except ValueError:
        print("NOT VERIFIED: signed_message is not JSON")
        return 1
    if canonical(parsed).decode("ascii") != msg:
        print("NOT VERIFIED: signed_message is not in canonical form")
        return 1
    if ev.get("signed_payload") is not None and canonical(ev["signed_payload"]).decode("ascii") != msg:
        print("NOT VERIFIED: signed_payload differs from the signed message")
        return 1
    if not strong_key(base64.b64decode(pub)):
        print("NOT VERIFIED: weak (small-order) public key - its signatures prove nothing")
        return 1
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(base64.b64decode(sig), msg.encode("ascii"))
    except (InvalidSignature, ValueError):
        print("NOT VERIFIED: the signature does not match")
        return 1
    pq_pub, pq_sig = ev.get("pq_public_key"), ev.get("pq_signature")
    if pq_pub:
        # hybrid: ML-DSA-65 must verify as well - both or nothing
        if not pq_sig:
            print("NOT VERIFIED: hybrid key but no ML-DSA-65 signature")
            return 1
        try:
            _mldsa().MLDSA65PublicKey.from_public_bytes(base64.b64decode(pq_pub)).verify(
                base64.b64decode(pq_sig), msg.encode("ascii"))
        except (InvalidSignature, ValueError) as exc:
            if "cryptography >= 48" in str(exc):
                raise
            print("NOT VERIFIED: the ML-DSA-65 signature does not match")
            return 1
    fp = fingerprint(pub, pq_pub)
    if args.fingerprint and args.fingerprint.strip() != fp:
        print(f"NOT VERIFIED: signed by {fp}, expected {args.fingerprint.strip()}")
        return 1
    print("VERIFIED" + ("  (hybrid: Ed25519 + ML-DSA-65, both valid)" if pq_pub else "  (Ed25519)"))
    print(f"  signer key   {fp}" + ("  (matches the fingerprint you supplied)" if args.fingerprint else
                                     "  - compare it with the one the agent's owner gave you"))
    if ev.get("key_origin") == "server":
        print("  note         this key was generated by the Provenza server, which held the private key at that moment")
    print(f"  signed data  {json.dumps(parsed, ensure_ascii=False)}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--hybrid", action="store_true", help="also an ML-DSA-65 key (post-quantum)")
    k.set_defaults(fn=cmd_keygen)
    f = sub.add_parser("fingerprint")
    f.add_argument("public_key")
    f.add_argument("pq_public_key", nargs="?")
    f.set_defaults(fn=cmd_fingerprint)
    s = sub.add_parser("sign")
    s.add_argument("private_key")
    s.add_argument("file")
    s.add_argument("--pq-private-key", help="ML-DSA-65 seed, for a hybrid key")
    s.set_defaults(fn=cmd_sign)
    v = sub.add_parser("verify")
    v.add_argument("evidence")
    v.add_argument("--fingerprint", help="expected signer key fingerprint (SHA256:...)")
    v.set_defaults(fn=cmd_verify)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
