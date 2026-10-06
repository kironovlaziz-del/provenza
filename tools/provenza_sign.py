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
  enroll --server URL --token TOKEN [--name N] [--hybrid] [--out FILE]
                               join Provenza: generate the agent's keys here,
                               prove possession by signing the server's
                               challenge; keys and API key go to FILE (600)
  rotate [--keys FILE] [--hybrid]
                               new signing key: the old key consents and the
                               new key proves possession (FILE is updated)
  attest [--keys FILE] [--token-file PATH] [--every MINUTES]
                               prove where the agent runs: sends the pod's
                               projected Kubernetes ServiceAccount token,
                               signed with the agent's key over the server's
                               challenge; --every repeats it (run it next to
                               the agent so its attestation never lapses)
  verify EVIDENCE.json [--fingerprint SHA256:...] [--revocations LIST.json]
                               check an evidence file downloaded from
                               Provenza; with --fingerprint, also require the
                               signer key to be the one you expect (get it
                               from the agent's owner, not from the server);
                               with --revocations, refuse a record that
                               arrived after its key stopped being trusted

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


def _ts(value: str):
    from datetime import datetime, timezone

    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


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
    revoked = None
    if args.revocations:
        # the revocation list you exported (GET /agents/key-revocations) - not the
        # server's claim inside the evidence, which an altered server could omit
        with open(args.revocations, encoding="utf-8") as f:
            entries = json.load(f)
        # either half counts: a revoked Ed25519 key paired with a new ML-DSA key is still revoked
        hits = [r for r in entries if r.get("fingerprint") == fp or r.get("public_key") == pub
                or (pq_pub and r.get("pq_public_key") == pq_pub)]
        revoked = min(hits, key=lambda r: _ts(r["untrusted_from"])) if hits else None
        if revoked is not None:
            signed_at, since = ev.get("signed_at"), revoked.get("untrusted_from")
            if not signed_at or not since or _ts(signed_at) >= _ts(since):
                print(f"NOT TRUSTED: the signature is valid, but key {fp} was revoked ({revoked.get('reason')}) "
                      f"and is not trusted from {since}; this record arrived {signed_at or 'at an unknown time'}")
                return 1
    print("VERIFIED" + ("  (hybrid: Ed25519 + ML-DSA-65, both valid)" if pq_pub else "  (Ed25519)"))
    print(f"  signer key   {fp}" + ("  (matches the fingerprint you supplied)" if args.fingerprint else
                                     "  - compare it with the one the agent's owner gave you"))
    if revoked is not None:
        print(f"  revocation   key revoked later; not trusted from {revoked.get('untrusted_from')} - "
              f"this record arrived before ({ev.get('signed_at')}), so it stands")
    elif not args.revocations:
        print("  note         no --revocations list given: revocation of the key was not checked")
    if ev.get("key_origin") == "server":
        print("  note         this key was generated by the Provenza server, which held the private key at that moment")
    print(f"  signed data  {json.dumps(parsed, ensure_ascii=False)}")
    return 0


# --------------------------------------------------------------------------
# enrollment and rotation - the agent side of proof of possession
# --------------------------------------------------------------------------

def _new_keys(hybrid: bool) -> dict:
    key = Ed25519PrivateKey.generate()
    out = {"private_key": base64.b64encode(key.private_bytes_raw()).decode(),
           "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
           "pq_private_key": None, "pq_public_key": None}
    if hybrid:
        pk = _mldsa().MLDSA65PrivateKey.generate()
        out["pq_private_key"] = base64.b64encode(pk.private_bytes_raw()).decode()
        out["pq_public_key"] = base64.b64encode(pk.public_key().public_bytes_raw()).decode()
    return out


def _sign_both(keys: dict, statement: dict):
    msg = canonical(statement)
    ed = Ed25519PrivateKey.from_private_bytes(base64.b64decode(keys["private_key"]))
    s = base64.b64encode(ed.sign(msg)).decode()
    pq = None
    if keys.get("pq_private_key"):
        pk = _mldsa().MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(keys["pq_private_key"]))
        pq = base64.b64encode(pk.sign(msg)).decode()
    return s, pq


def _post(server: str, path: str, body: dict, headers: dict = None) -> dict:
    import urllib.error
    import urllib.request

    url = server.rstrip("/") + "/api/v1" + path
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        raise ValueError(f"{path}: HTTP {e.code} {e.read().decode(errors='replace')[:300]}")


def _save(path: str, data: dict) -> None:
    import os

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # private keys: owner only
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def cmd_enroll(args) -> int:
    """Join Provenza with an enrollment token: generate keys HERE, prove possession."""
    ch = _post(args.server, "/agent-enrollment/challenge", {"token": args.token})
    # hybrid when asked, or when the server requires it (template, organization, or a hybrid agent being re-keyed)
    keys = _new_keys(args.hybrid or bool(ch.get("require_hybrid")))
    name = (ch.get("name") or args.name or "").strip()
    statement = {"type": "provenza.agent.enroll", "v": 1, "challenge": ch["challenge"], "org_id": ch["org_id"],
                 "enrollment_id": ch["enrollment_id"], "public_key": keys["public_key"],
                 "pq_public_key": keys["pq_public_key"], "name": name}
    s, pq = _sign_both(keys, statement)
    res = _post(args.server, "/agent-enrollment/enroll", {
        "token": args.token, "challenge": ch["challenge"], "public_key": keys["public_key"],
        "pq_public_key": keys["pq_public_key"], "name": name or None, "signature": s, "pq_signature": pq})
    saved = {"server": args.server, "agent_id": res["agent_id"], "api_key": res.get("api_key"), **keys,
             "key_fingerprint": res["key_fingerprint"]}
    if not saved["api_key"] and args.keys_in:
        with open(args.keys_in, encoding="utf-8") as f:
            saved["api_key"] = json.load(f).get("api_key")
    _save(args.out, saved)
    print(f"{'ENROLLED' if res.get('purpose') == 'new' else 'RE-KEYED'}  agent {res['agent_id']} ({res.get('name')})")
    print(f"  key fingerprint  {res['key_fingerprint']}  ({res.get('algorithm')})")
    print(f"  saved to         {args.out}  (private keys and API key - keep it secret, mode 600)")
    att = ch.get("attestation")
    if att:
        print(f"  ATTESTATION REQUIRED (policy {att.get('policy')!r}): the agent can act only after")
        print(f"    provenza_sign.py attest --keys {args.out} --every N   (N below {att.get('validity_minutes')} min)")
        print(f"    with a projected ServiceAccount token for audience {att.get('audience')!r} mounted at")
        print(f"    {DEFAULT_TOKEN_FILE}")
    return 0


def cmd_rotate(args) -> int:
    """Rotate to a new key: the old key consents, the new key proves possession."""
    with open(args.keys, encoding="utf-8") as f:
        old = json.load(f)
    server = args.server or old["server"]
    auth = {"X-Agent-Key": old["api_key"]}
    ch = _post(server, f"/agents/{old['agent_id']}/signing-key/challenge", {}, auth)
    new = _new_keys(args.hybrid or bool(old.get("pq_private_key")))  # never a silent downgrade from hybrid
    statement = {"type": "provenza.agent.key_rotation", "v": 1, "challenge": ch["challenge"],
                 "agent_id": old["agent_id"], "old_key_fingerprint": ch["old_key_fingerprint"],
                 "new_key_fingerprint": fingerprint(new["public_key"], new["pq_public_key"]),
                 "new_public_key": new["public_key"], "new_pq_public_key": new["pq_public_key"]}
    os_, opq = _sign_both(old, statement)
    ns, npq = _sign_both(new, statement)
    _post(server, f"/agents/{old['agent_id']}/signing-key/rotate", {
        "challenge": ch["challenge"], "new_public_key": new["public_key"], "new_pq_public_key": new["pq_public_key"],
        "old_signature": os_, "old_pq_signature": opq, "new_signature": ns, "new_pq_signature": npq}, auth)
    _save(args.keys, {**old, **new, "key_fingerprint": statement["new_key_fingerprint"]})
    print(f"ROTATED  agent {old['agent_id']}: {ch['old_key_fingerprint']} -> {statement['new_key_fingerprint']}")
    return 0


DEFAULT_TOKEN_FILE = "/var/run/secrets/provenza/token"


def _token_audience(token: str):
    """The token's aud claim, read without verifying (the server verifies)."""
    try:
        part = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError):
        return None
    aud = claims.get("aud")
    return [aud] if isinstance(aud, str) else list(aud or [])


def _attest_once(keys: dict, server: str, token_file: str) -> bool:
    import hashlib

    with open(token_file, encoding="utf-8") as f:
        token = f.read().strip()  # re-read every time: the kubelet rotates it
    auth = {"X-Agent-Key": keys["api_key"]}
    ch = _post(server, f"/agents/{keys['agent_id']}/attestation/challenge", {}, auth)
    # the audience must be the same in the pod spec, here and in the verifier:
    # say so before sending a token the server would refuse
    aud = _token_audience(token)
    if ch.get("audience") and aud is not None and ch["audience"] not in aud:
        raise ValueError(f"the token at {token_file} is for audience {aud}, the policy expects "
                         f"{ch['audience']!r}: set serviceAccountToken.audience: {ch['audience']} in the pod spec")
    statement = {"type": "provenza.agent.attestation", "v": 1, "challenge": ch["challenge"],
                 "agent_id": keys["agent_id"], "kind": ch.get("kind", "k8s_sa"),
                 "evidence_sha256": hashlib.sha256(token.encode()).hexdigest()}
    s, pq = _sign_both(keys, statement)
    res = _post(server, f"/agents/{keys['agent_id']}/attestation", {
        "challenge": ch["challenge"], "kind": statement["kind"], "evidence": token,
        "signature": s, "pq_signature": pq}, auth)
    ident = res.get("identity") or {}
    if res.get("ok"):
        print(f"ATTESTED  agent {keys['agent_id']} as {ident.get('namespace')}/{ident.get('service_account')}"
              f" (pod {ident.get('pod')}) under policy {res.get('policy')!r}, valid until {res.get('valid_until')}")
        return True
    print(f"NOT ATTESTED  agent {keys['agent_id']}: {res.get('reason')} {res.get('detail') or ''}".rstrip(),
          file=sys.stderr)
    return False


def cmd_attest(args) -> int:
    """Prove where the agent runs (Kubernetes ServiceAccount token)."""
    import time

    def load() -> dict:
        with open(args.keys, encoding="utf-8") as f:
            return json.load(f)

    if not args.every:
        keys = load()
        return 0 if _attest_once(keys, args.server or keys["server"], args.token_file) else 1
    while True:  # a sidecar loop: never let the attestation lapse
        try:
            keys = load()  # re-read every time: `rotate` rewrites the file with the new key
            _attest_once(keys, args.server or keys["server"], args.token_file)
        except (OSError, ValueError, KeyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
        time.sleep(max(1.0, args.every * 60))


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
    v.add_argument("--revocations", help="revocation list (JSON from GET /agents/key-revocations)")
    v.set_defaults(fn=cmd_verify)
    e = sub.add_parser("enroll")
    e.add_argument("--server", required=True, help="Provenza URL, e.g. https://provenza.example.com")
    e.add_argument("--token", required=True, help="the one-time enrollment token from your admin")
    e.add_argument("--name", help="agent name, when the token does not fix one")
    e.add_argument("--hybrid", action="store_true", help="Ed25519 + ML-DSA-65 (post-quantum)")
    e.add_argument("--out", default="provenza-agent.json", help="where to save keys and API key (mode 600)")
    e.add_argument("--keys-in", help="optional: a previous keys file (its API key is kept if the server issues none)")
    e.set_defaults(fn=cmd_enroll)
    r = sub.add_parser("rotate")
    r.add_argument("--keys", default="provenza-agent.json", help="the agent's keys file (updated in place)")
    r.add_argument("--server", help="overrides the server stored in the keys file")
    r.add_argument("--hybrid", action="store_true", help="the new key is Ed25519 + ML-DSA-65")
    r.set_defaults(fn=cmd_rotate)
    a = sub.add_parser("attest")
    a.add_argument("--keys", default="provenza-agent.json", help="the agent's keys file")
    a.add_argument("--server", help="overrides the server stored in the keys file")
    a.add_argument("--token-file", default=DEFAULT_TOKEN_FILE,
                   help=f"projected ServiceAccount token (default {DEFAULT_TOKEN_FILE})")
    a.add_argument("--every", type=float, metavar="MINUTES",
                   help="repeat every MINUTES (pick less than the policy's validity)")
    a.set_defaults(fn=cmd_attest)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
