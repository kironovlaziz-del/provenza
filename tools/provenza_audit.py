#!/usr/bin/env python3
# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Verify Provenza audit proofs offline - standalone, needs only `cryptography`
(pip install cryptography). It does not talk to a Provenza server and does
not share code with one, so what it says does not depend on trusting either.

  verify PROOF.json [--fingerprint SHA256:...]...
        a record's proof (Audit Log -> Proof, or GET /audit-logs/{id}/proof):
        the record hashes to record_hash, the inclusion path leads from it
        to the checkpoint's Merkle root, and the checkpoint is signed
  checkpoint CHECKPOINT.json [--fingerprint SHA256:...]... [--tsa-ca TSA.pem]
        one signed checkpoint (GET /audit-logs/checkpoints, or the
        "checkpoint" part of a proof)
  consistency CONSISTENCY.json [--pinned CHECKPOINT.json] [--fingerprint SHA256:...]... [--tsa-ca TSA.pem]
        GET /audit-logs/consistency?from_size=N: the newer checkpoint
        extends the older one - nothing in the first N records was changed
        or removed. With --pinned, the older checkpoint must also be the one
        you saved earlier

  --tsa-ca: the checkpoints' RFC 3161 time-stamps ("timestamps") must
        verify against this TSA certificate or CA (rfc3161.py, next to this
        file): a third party saw exactly that state of the log at that time

  receipt RECEIPT.json [--fingerprint SHA256:...]... [--agent-fingerprint SHA256:...]
                       [--approver-passkey SHA256:...]...
        a PVP receipt (GET /pvp/receipts/{action_id}): the action is signed
        by its agent (or was executed by a Provenza gateway), its signed
        payload names this very action, it matches its check, it is a leaf
        of a seal, the seal is a record of the audit log, and that log is
        signed - action -> seal -> audit record -> checkpoint. When a
        person's approval let it run, the receipt carries that approval:
        the reviewer's session key signed it for exactly this call, and the
        reviewer's passkey (a WebAuthn assertion with the person verified)
        certified that session key. --approver-passkey pins the passkeys
        you trust to approve (fingerprints from My profile -> Passkeys).
        An action an egress proxy with its own key handled carries the
        proxy's signed receipt (witness); --proxy-fingerprint pins that key
  release RELEASE.json [--passkey SHA256:...]...
        a signed policy release (GET /policy-releases/{id}): the policy
        bundle and key manifest hash to what was signed, and the quorum of
        the manifest that governs it signed exactly this release with
        passkeys it lists (user verified). Chain releases by checking each
        one's governing manifest against the release before it
  trace EXPORT.json [--fingerprint SHA256:...]...
        a TRACE v0.2 Trust Record export (GET /pvp/receipts/{id}/trace or
        /pvp/chains/{id}/trace): the JWT is signed EdDSA by the key in
        cnf.jwk (and ML-DSA-65 beside it for a hybrid key), its claims hash
        the receipts it carries (RFC 8785 JCS, implemented here), and every
        receipt verifies as above

--fingerprint names an audit key you trust (repeat it for several): take it
from a checkpoint you saved earlier or from where the organization
published it - never from the file you are checking. Without any, the tool
proves the file is internally consistent and signed by the key it names -
not whose key that is.

Key changes. When the organization rotated its audit key, the file carries
the signed handovers (old key consents, new key countersigns). A key you
pass with --fingerprint is trusted directly - that is what confirming it
means. But history that crosses a key change (consistency from a checkpoint
signed by the old key, or a proof checked against your old pin) is accepted
only if BOTH hold:
  1. a chain of valid handovers leads from the key you trusted to the new one, and
  2. you confirmed the new fingerprint independently: --fingerprint NEW.
Either alone is refused, and a key handed over twice (a fork) is refused. When a check fails, the trust chain is printed
FIRST - which keys you trusted, where each fingerprint came from, how the
handovers link them - because a mismatch there, not a broken signature, is
the usual cause after a rotation.

Formats are in docs/audit-proofs.md. Merkle hashing is RFC 9162:
leaf = SHA-256(0x00 || record_hash bytes), node = SHA-256(0x01 || left || right).

Exit status: 0 = verified, 1 = not verified, 2 = usage / input error.
"""

import argparse
import base64
import hashlib
import json
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    sys.exit("this tool needs the 'cryptography' package: pip install cryptography")

HYBRID = "ed25519+ml-dsa-65"
CLASSIC = "ed25519"


class Fail(Exception):
    pass


HANDOVER_TYPE = "provenza.audit.key_handover"


def canonical(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fingerprint(pub_b64, pq_b64=None) -> str:
    raw = base64.b64decode(pub_b64) + (base64.b64decode(pq_b64) if pq_b64 else b"")
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _hex32(value, what) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except (TypeError, ValueError):
        raise Fail(f"{what} is not hex")
    if len(raw) != 32:
        raise Fail(f"{what} is not 32 bytes")
    return raw


def inclusion_ok(index, size, data, path, root) -> bool:
    """RFC 9162 2.1.3.2"""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, _leaf(data)
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_ok(m, n, root_m, root_n, path) -> bool:
    """RFC 9162 2.1.4.2"""
    if not 0 < m <= n:
        return False
    if m == n:
        return not path and root_m == root_n
    path = list(path)
    if m & (m - 1) == 0:
        path.insert(0, root_m)
    if not path:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == root_m and sr == root_n


def _verify_ed25519(pub_b64, sig_b64, msg) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(sig_b64), msg)
        return True
    except Exception:  # noqa: BLE001
        return False


def _verify_mldsa(pub_b64, sig_b64, msg) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        raise Fail("this checkpoint is signed with ML-DSA-65 too; checking it needs cryptography >= 48")
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(sig_b64), msg)
        return True
    except Exception:  # noqa: BLE001
        return False


def _verify_pair(label, pub, pq_pub, sig_, pq_sig, msg):
    if not _verify_ed25519(pub, sig_, msg):
        raise Fail(f"{label}: Ed25519 signature does not verify")
    if pq_pub:
        if not pq_sig:
            raise Fail(f"{label}: hybrid key but the ML-DSA-65 signature is missing")
        if not _verify_mldsa(pq_pub, pq_sig, msg):
            raise Fail(f"{label}: ML-DSA-65 signature does not verify")


def _statement(obj, label, kind):
    text = obj.get("statement")
    if not isinstance(text, str) or not text:
        raise Fail(f"{label}: statement missing")
    try:
        st = json.loads(text)
    except ValueError:
        raise Fail(f"{label}: statement is not JSON")
    if canonical(st).decode("utf-8") != text:
        raise Fail(f"{label}: statement is not in canonical form")
    if st.get("type") != kind:
        raise Fail(f"{label}: not a Provenza {kind}")
    return st, text.encode("ascii")


def signer_of(cp) -> str:
    """Fingerprint of the key a checkpoint names - computed from its public
    keys, before anything is verified (for the trust report)."""
    return fingerprint(cp["public_key"], cp.get("pq_public_key"))


def check_checkpoint(cp, pin=None) -> str:
    """Raises Fail; returns the key fingerprint. `pin`: a fingerprint or a
    list of them, one of which must have signed it."""
    for k in ("statement", "signature", "public_key", "tree_size", "root_hash", "org_id"):
        if cp.get(k) in (None, ""):
            raise Fail(f"checkpoint: {k} missing")
    st, msg = _statement(cp, "checkpoint", "provenza.audit.checkpoint")
    for k in ("org_id", "tree_size", "root_hash", "issued_at", "algorithm", "key_fingerprint"):
        if st.get(k) != cp.get(k):
            raise Fail(f"checkpoint: {k} differs from the signed statement")
    _hex32(st["root_hash"], "checkpoint root_hash")
    fp = signer_of(cp)
    if st.get("key_fingerprint") != fp:
        raise Fail("checkpoint: the signed fingerprint does not match the public key(s)")
    scheme = HYBRID if cp.get("pq_public_key") else CLASSIC
    if st.get("algorithm") != scheme:
        raise Fail(f"checkpoint: signed algorithm {st.get('algorithm')!r} does not match the keys ({scheme})")
    _verify_pair("checkpoint", cp["public_key"], cp.get("pq_public_key"), cp["signature"], cp.get("pq_signature"), msg)
    pins = [pin] if isinstance(pin, str) else list(pin or [])
    if pins and fp not in pins:
        raise Fail(f"checkpoint: signed by {fp}, expected {' or '.join(pins)}")
    return fp


def check_handover(h, org_id=None):
    """A key handover: both keys signed the same statement. Returns (old_fp, new_fp, statement)."""
    label = f"key handover (rotation {h.get('rotation_id')})"
    for k in ("old_public_key", "old_signature", "new_public_key", "new_signature"):
        if not h.get(k):
            raise Fail(f"{label}: {k} missing")
    st, msg = _statement(h, label, HANDOVER_TYPE)
    for k in ("org_id", "rotation_id", "tree_size", "root_hash", "issued_at", "old_key_fingerprint",
              "new_key_fingerprint"):
        if st.get(k) != h.get(k):
            raise Fail(f"{label}: {k} differs from the signed statement")
    old_fp = fingerprint(h["old_public_key"], h.get("old_pq_public_key"))
    new_fp = fingerprint(h["new_public_key"], h.get("new_pq_public_key"))
    if st["old_key_fingerprint"] != old_fp or st["new_key_fingerprint"] != new_fp:
        raise Fail(f"{label}: a signed fingerprint does not match its public key(s)")
    if old_fp == new_fp:
        raise Fail(f"{label}: hands a key over to itself")
    for side in ("old", "new"):
        scheme = HYBRID if h.get(f"{side}_pq_public_key") else CLASSIC
        if st.get(f"{side}_algorithm") != scheme:
            raise Fail(f"{label}: {side}_algorithm does not match the {side} key")
    if org_id is not None and st["org_id"] != org_id:
        raise Fail(f"{label}: belongs to another organization")
    approvals, quorum = st.get("approvals"), st.get("quorum")
    if (not isinstance(approvals, list) or not all(isinstance(a, int) for a in approvals)
            or not isinstance(quorum, int) or quorum < 1 or len(set(approvals)) < quorum):
        raise Fail(f"{label}: approvals do not meet the quorum it states")
    _verify_pair(f"{label}, old key's consent", h["old_public_key"], h.get("old_pq_public_key"),
                 h["old_signature"], h.get("old_pq_signature"), msg)
    _verify_pair(f"{label}, new key's countersignature", h["new_public_key"], h.get("new_pq_public_key"),
                 h["new_signature"], h.get("new_pq_signature"), msg)
    return old_fp, new_fp, st


class Trust:
    """Fingerprints the user trusts, with where each one came from."""

    def __init__(self, fingerprints=None, pinned=None):
        self.sources = {}
        for fp in fingerprints or []:
            self.sources.setdefault(fp.strip(), "--fingerprint")
        if pinned:
            self.sources.setdefault(pinned, "the pinned checkpoint file")

    def __bool__(self):
        return bool(self.sources)

    def __contains__(self, fp):
        return fp in self.sources


def handover_links(doc, org_id):
    """{old_fp: (new_fp, statement)} from the file's handovers - each verified."""
    links = {}
    for h in doc.get("key_handovers") or []:
        old_fp, new_fp, st = check_handover(h, org_id)
        if old_fp in links and links[old_fp][0] != new_fp:
            # a key can be handed over once; two successors means someone holding
            # the old key signed a second handover - never pick one silently
            raise Fail(f"key {old_fp} was handed over twice ({links[old_fp][0]} and {new_fp}): "
                       "the old key may be compromised")
        links[old_fp] = (new_fp, st)
    return links


def chain_between(links, start, target):
    """Handover statements leading from start to target, or None."""
    path, fp, seen = [], start, set()
    while fp != target:
        if fp in seen or fp not in links:
            return None
        seen.add(fp)
        fp, st = links[fp]
        path.append(st)
    return path


def trust_report(target, links, trust):
    """Lines describing the trust chain to `target` (what the user trusts,
    from where, how handovers link it) and a verdict:
    "trusted" | "no_pins" | "unconfirmed_change" | "unknown"."""
    lines = ["trust chain:"]
    for fp, src in trust.sources.items():
        lines.append(f"  you trust      {fp}  (from {src})")
    if not trust:
        lines.append("  you trust      nothing yet (no --fingerprint, no --pinned)")
    best = None
    for fp in trust.sources:
        path = chain_between(links, fp, target)
        if path is not None and (best is None or len(path) > len(best[1])):  # show the full linkage
            best = (fp, path)
    if best and best[1]:
        for st in best[1]:
            lines.append(f"  handover       {st['old_key_fingerprint']} -> {st['new_key_fingerprint']}  "
                         f"(rotation {st['rotation_id']}, at {st['tree_size']} records, {st['issued_at']}, "
                         f"{len(st['approvals'])} of {st['quorum']} admins approved; old and new key signatures valid)")
    lines.append(f"  signed by      {target}  (named by the file itself)")
    if target in trust:
        verdict = "trusted"
    elif not trust:
        verdict = "no_pins"
    elif best:
        verdict = "unconfirmed_change"
        lines.append(f"  -> the key changed to {target}; the old key consented, but you have not confirmed the")
        lines.append("     new fingerprint independently. Compare it with where the organization published it,")
        lines.append(f"     then add --fingerprint {target}")
    else:
        verdict = "unknown"
        lines.append("  -> no valid handover leads from a key you trust to this one: compare the fingerprint")
        lines.append("     sources above first - a wrong or outdated pin is the usual cause, not the signature")
    return verdict, lines


class TrustFail(Fail):
    def __init__(self, message, lines):
        super().__init__(message)
        self.lines = lines


def _require_trust(target, links, trust, what):
    verdict, lines = trust_report(target, links, trust)
    if verdict == "unconfirmed_change":
        raise TrustFail(f"{what} is signed by a new audit key that you have not confirmed", lines)
    if verdict == "unknown":
        raise TrustFail(f"{what} is signed by {target}, which you do not trust", lines)
    return verdict, lines


def check_proof(doc, pin=None):
    if doc.get("format") != "provenza.audit.proof/1":
        raise Fail("not a Provenza audit proof (format)")
    rec, cp = doc.get("record") or {}, doc.get("checkpoint") or {}
    trust = pin if isinstance(pin, Trust) else Trust([pin] if isinstance(pin, str) else pin)
    links = handover_links(doc, cp.get("org_id"))
    _require_trust(signer_of(cp), links, trust, "the checkpoint")  # trust first, signatures after
    fp = check_checkpoint(cp)
    text = rec.get("canonical")
    if not isinstance(text, str):
        raise Fail("record: canonical text missing")
    payload = json.loads(text)
    if canonical(payload).decode("utf-8") != text:
        raise Fail("record: canonical text is not in canonical form")
    if rec.get("payload") is not None and canonical(rec["payload"]).decode("utf-8") != text:
        raise Fail("record: payload differs from the canonical text")
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if h != rec.get("record_hash"):
        raise Fail("record: does not hash to record_hash - the record was altered")
    if payload.get("org_id") != cp["org_id"]:
        raise Fail("record: belongs to another organization than the checkpoint")
    seq = payload.get("seq")
    if not isinstance(seq, int) or doc.get("leaf_index") != seq - 1:
        raise Fail("record: leaf_index does not match seq")
    if doc.get("tree_size") != cp["tree_size"]:
        raise Fail("tree_size differs from the checkpoint")
    path = [_hex32(x, "inclusion path") for x in doc.get("inclusion_path") or []]
    if not inclusion_ok(seq - 1, cp["tree_size"], bytes.fromhex(h), path, bytes.fromhex(cp["root_hash"])):
        raise Fail("inclusion path does not lead to the checkpoint root - the record is not in that log")
    return payload, cp, fp


def check_consistency(doc, pinned=None, pin=None):
    if doc.get("format") != "provenza.audit.consistency/1":
        raise Fail("not a Provenza consistency proof (format)")
    old, new = doc.get("old") or {}, doc.get("new") or {}
    trust = pin if isinstance(pin, Trust) else Trust([pin] if isinstance(pin, str) else pin)
    if pinned is not None:
        trust.sources.setdefault(signer_of(pinned), "the pinned checkpoint file")
    if old.get("org_id") != new.get("org_id"):
        raise Fail("the two checkpoints belong to different organizations")
    links = handover_links(doc, new.get("org_id"))
    fp_old, fp_new = signer_of(old), signer_of(new)
    lines = []
    if fp_old != fp_new:
        steps = chain_between(links, fp_old, fp_new)
        if steps is None:
            _, lines = trust_report(fp_new, links, trust)
            raise TrustFail(f"the checkpoints are signed by different keys ({fp_old} / {fp_new}) and no valid "
                            "handover links them", lines)
        for st in steps:
            if not old["tree_size"] <= st["tree_size"] <= new["tree_size"]:
                raise Fail(f"key handover (rotation {st['rotation_id']}) is not between the two checkpoints")
        if not trust:
            _, lines = trust_report(fp_new, links, trust)
            raise TrustFail("the audit key changed between the checkpoints; confirm the new fingerprint "
                            "independently and pass it with --fingerprint", lines)
    if trust:
        _, lines = _require_trust(fp_new, links, trust, "the newer checkpoint")
    check_checkpoint(old)
    check_checkpoint(new)
    if pinned is not None:
        check_checkpoint(pinned)
        for k in ("org_id", "tree_size", "root_hash"):
            if pinned.get(k) != old.get(k):
                raise Fail(f"the older checkpoint is not the pinned one ({k} differs)")
    path = [_hex32(x, "consistency path") for x in doc.get("consistency_path") or []]
    if not consistency_ok(old["tree_size"], new["tree_size"], bytes.fromhex(old["root_hash"]),
                          bytes.fromhex(new["root_hash"]), path):
        raise Fail("the newer checkpoint does NOT extend the older one - history was rewritten")
    return old, new, fp_old, fp_new


# ---------------------------------------------------------------------------
# PVP receipts and TRACE exports
# ---------------------------------------------------------------------------

SEAL_ENTITY = "pvp_action_seal"
TRACE_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
ACTION_FIELDS = ("check_id", "agent_id", "chain_id", "action_type", "tool_name", "input_sha256", "output_sha256")


APPROVAL_TYPE = "provenza.approval"
CERTIFICATE_TYPE = "provenza.session.certificate"
APPROVAL_FIELDS = ("agent_id", "chain_id", "action_type", "tool_name", "input_sha256")


def passkey_fingerprint(spki_b64) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(spki_b64)).digest()).decode().rstrip("=")


def _verify_passkey(passkey, assertion, challenge: bytes):
    """A WebAuthn assertion (docs/pvp/edge.md, section 2) by this passkey
    over this challenge, made with the person verified (PIN or biometric)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    client_raw = _b64url_decode(assertion["client_data_json"])
    auth = _b64url_decode(assertion["authenticator_data"])
    client = json.loads(client_raw.decode("utf-8"))
    if client.get("type") != "webauthn.get":
        raise Fail("approval: the passkey certificate is not a WebAuthn assertion")
    if client.get("challenge") != base64.urlsafe_b64encode(challenge).decode().rstrip("="):
        raise Fail("approval: the passkey did not sign this session certificate")
    if len(auth) < 37 or auth[32] & 0x05 != 0x05:
        raise Fail("approval: the passkey was used without verifying the person (PIN or biometric)")
    key = serialization.load_der_public_key(base64.b64decode(passkey["public_key"]))
    signed, sig = auth + hashlib.sha256(client_raw).digest(), _b64url_decode(assertion["signature"])
    try:
        if passkey["alg"] == -7:
            key.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        elif passkey["alg"] == -8:
            key.verify(sig, signed)
        elif passkey["alg"] == -257:
            key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise Fail(f"approval: unsupported passkey algorithm {passkey['alg']}")
    except (InvalidSignature, TypeError, AttributeError):
        raise Fail("approval: the passkey's signature on the session certificate does not verify")


def check_approval(ap, action, check, passkey_fps=None) -> str:
    """The approval that let the action run: the reviewer's session key
    signed the decision on exactly this call, and the reviewer's passkey
    certified that session key. Returns the passkey fingerprint."""
    st, cert = ap["statement"], ap["certificate"]["statement"]
    if st.get("type") != APPROVAL_TYPE or st.get("decision") != "approved":
        raise Fail("approval: not a signed approval")
    for k in APPROVAL_FIELDS:
        if st.get(k) != action.get(k):
            raise Fail(f"approval: it approves another call ({k})")
    if check is None or check.get("decision") != "allowed":
        raise Fail("approval: no allowed check to go with it")
    if cert.get("type") != CERTIFICATE_TYPE or cert.get("public_key") != ap["session_public_key"]:
        raise Fail("approval: the session certificate is not for the key that signed")
    for k in ("org_id", "user_id", "session_id"):
        if st.get(k) != cert.get(k):
            raise Fail(f"approval: signed in another session than the certificate names ({k})")
    if not cert["not_before"] <= st["issued_at"] <= cert["not_after"]:
        raise Fail("approval: signed outside the session's validity")
    if not _verify_ed25519(ap["session_public_key"], ap["signature"], canonical(st)):
        raise Fail("approval: the session key's signature does not verify")
    _verify_passkey(ap["passkey"], ap["certificate"]["assertion"], hashlib.sha256(canonical(cert)).digest())
    fp = passkey_fingerprint(ap["passkey"]["public_key"])
    if passkey_fps and fp not in passkey_fps:
        raise Fail(f"approval: signed with passkey {fp}, not one of the passkeys you gave")
    return fp


RELEASE_TYPE = "provenza.policy.release"


def _sha(doc) -> str:
    return hashlib.sha256(canonical(doc)).hexdigest()


def check_release(doc, passkey_fps=None):
    """A signed policy release (GET /policy-releases/{id}): both documents
    hash to what was signed, and the quorum of the manifest that governs it
    (the release before; for the first release its own) signed exactly this
    release with passkeys that manifest lists, the person verified each
    time. Returns (release summary, fingerprints of the passkeys that signed)."""
    rel, bundle, manifest = doc["release"], doc["bundle"], doc["manifest"]
    if _sha(bundle) != rel["bundle"]["sha256"] or _sha(manifest) != rel["manifest"]["sha256"]:
        raise Fail("a document does not hash to what the release names")
    gov = doc.get("governed_by")
    governing = gov["manifest"] if gov else manifest
    if gov:
        if _sha(governing) != gov["manifest_sha256"]:
            raise Fail("the governing manifest does not hash to its name")
        if bundle.get("previous") != gov["bundle_sha256"] or bundle.get("version") != gov["bundle_version"] + 1:
            raise Fail("the bundle does not follow the governing release's")
        if rel["manifest"]["sha256"] != gov["manifest_sha256"] and (
                manifest.get("previous") != gov["manifest_sha256"]
                or manifest.get("version") != governing.get("version", 0) + 1):
            raise Fail("the manifest does not follow the governing one")
    signed = {}
    for s in doc.get("signatures") or []:
        st = s["statement"]
        want = {"type": RELEASE_TYPE, "v": 1, "org_id": bundle["org_id"], "user_id": s["user_id"],
                "release": rel["number"], "bundle": {"version": bundle["version"], "sha256": rel["bundle"]["sha256"]},
                "manifest": {"version": manifest["version"], "sha256": rel["manifest"]["sha256"]},
                "not_after": bundle["not_after"], "issued_at": st.get("issued_at")}
        if st != want:
            continue
        person = (governing.get("signers") or {}).get(str(s["user_id"])) or {}
        key = (person.get("passkeys") or {}).get(s["credential_id"])
        if person.get("role") != "admin" or not key:
            continue
        try:
            _verify_passkey(key, s["assertion"], hashlib.sha256(canonical(st)).digest())
        except Fail:
            continue
        signed[s["user_id"]] = key["fingerprint"]
    quorum = max(1, int(governing.get("quorum") or 1))
    if len(signed) < quorum:
        raise Fail(f"{len(signed)} valid administrator signature(s); the governing manifest requires {quorum}")
    if passkey_fps and not set(signed.values()) & set(passkey_fps):
        raise Fail("none of the passkeys you gave signed this release")
    return rel, signed


WITNESS_TYPE = "provenza.proxy.receipt"
WITNESS_FIELDS = ("check_id", "agent_id", "chain_id", "action_type", "tool_name", "input_sha256", "output_sha256",
                  "decision")


def check_witness(w, action, proxy_fps=None) -> str:
    """The executor's own signed receipt (an egress proxy): it names exactly
    this action and its key signed it. Returns the key fingerprint."""
    st = w.get("statement") or {}
    if st.get("type") != WITNESS_TYPE:
        raise Fail("witness: not a proxy receipt")
    for k in WITNESS_FIELDS:
        if st.get(k) != action.get(k):
            raise Fail(f"witness: the proxy's receipt names another action ({k})")
    fp = fingerprint(w["public_key"])
    if fp != w.get("key_fingerprint"):
        raise Fail("witness: the key fingerprint does not match its key")
    if not _verify_ed25519(w["public_key"], w["signature"], canonical(st)):
        raise Fail("witness: the proxy's signature does not verify")
    if proxy_fps and fp not in proxy_fps:
        raise Fail(f"witness: signed by proxy key {fp}, not one of the keys you gave")
    return fp


def check_receipt(doc, trust=None, agent_fp=None, passkey_fps=None, proxy_fps=None):
    """Returns (action, checkpoint, audit key fingerprint); with a signed
    approval in the receipt, that is checked too (check_approval)."""
    if doc.get("pvp") != "pvp/1" or doc.get("type") != "receipt":
        raise Fail("not a PVP receipt (pvp/1)")
    action, seal = doc.get("action") or {}, doc.get("seal")
    if seal is None or doc.get("audit_proof") is None:
        raise Fail("the receipt carries no seal / audit proof - it is not anchored to the audit log")
    # 1. the audit log: the seal's record is in a signed checkpoint
    payload, cp, fp = check_proof(doc["audit_proof"], trust if trust is not None else Trust())
    meta = payload.get("metadata") or {}
    if (payload.get("entity_type"), payload.get("entity_id")) != (SEAL_ENTITY, seal["seal_id"]) \
            or doc["audit_proof"]["record"].get("id") != seal["audit_log_id"]:
        raise Fail("the audit record is not this receipt's seal")
    if meta.get("root") != seal["root"] or meta.get("size") != seal["size"]:
        raise Fail("the seal differs from what the audit log recorded for it")
    # 2. the seal: the action's evidence is one of its leaves
    leaf = hashlib.sha256(canonical(action)).digest()
    path = [_hex32(x, "seal path") for x in seal.get("inclusion_path") or []]
    if not inclusion_ok(seal["leaf_index"], seal["size"], leaf, path, bytes.fromhex(seal["root"])):
        raise Fail("the action is not in its seal - its evidence was altered")
    # 3. the action: signed by its agent, and the signature is about this action
    signed_by = action.get("signed_by")
    if signed_by is None:
        if not action.get("executed_by"):
            raise Fail("the action is not signed and no Provenza gateway executed it")
    else:
        sp = action.get("signed_payload") or {}
        if set(sp) != set(ACTION_FIELDS) or any(sp[k] != action.get(k) for k in ACTION_FIELDS):
            raise Fail("the signed payload does not name this action")
        _verify_pair("agent signature", signed_by["public_key"], signed_by.get("pq_public_key"),
                     signed_by["signature"], signed_by.get("pq_signature"), canonical(sp))
        if agent_fp and fingerprint(signed_by["public_key"], signed_by.get("pq_public_key")) != agent_fp:
            raise Fail("the action was signed by another key than the agent fingerprint you gave")
    # 3b. the executor's own receipt (an egress proxy with a key)
    if action.get("witness") is not None:
        check_witness(action["witness"], action, proxy_fps)
    elif proxy_fps:
        raise Fail("the action carries no proxy receipt, yet you gave proxy keys")
    # 4. the check it was recorded under
    check = doc.get("check")
    if check is not None:
        for k in ("check_id", "agent_id", "chain_id", "action_type", "tool_name", "input_sha256"):
            if check.get(k) != action.get(k):
                raise Fail(f"the action differs from its check ({k})")
        if check.get("decision") != "allowed" and action.get("decision") == "allowed":
            raise Fail("the check refused the action, yet it is recorded as allowed")
    # 5. the person's approval that let it run, when one did
    if doc.get("approval") is not None:
        check_approval(doc["approval"], action, check, passkey_fps)
    elif passkey_fps:
        raise Fail("the receipt carries no approval, yet you gave approver passkeys")
    return action, cp, fp


def _jcs_number(x):
    if isinstance(x, bool):
        raise ValueError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > 2 ** 53 - 1:
            raise ValueError("integer outside the I-JSON range")
        return str(x)
    from decimal import Decimal
    import math
    if not math.isfinite(x):
        raise ValueError("non-finite number")
    if x == 0:
        return "0"
    _, digits, exp = Decimal(repr(abs(x))).as_tuple()
    digits = list(digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exp += 1
    d = "".join(map(str, digits))
    k, n = len(d), exp + len(d)
    sign = "-" if x < 0 else ""
    if k <= n <= 21:
        return sign + d + "0" * (n - k)
    if 0 < n <= 21:
        return sign + d[:n] + "." + d[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + d
    e = n - 1
    return f"{sign}{d[0]}{'.' + d[1:] if k > 1 else ''}e{'+' if e > 0 else '-'}{abs(e)}"


def jcs(v) -> bytes:
    """RFC 8785, written independently of the server's app/pvp/jcs.py."""
    def ser(v):
        if v is None:
            return "null"
        if v is True or v is False:
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return _jcs_number(v)
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)
        if isinstance(v, list):
            return "[" + ",".join(ser(i) for i in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + ser(v[k]) for k in keys) + "}"
        raise ValueError("not a JSON value")
    return ser(v).encode("utf-8")


def _b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _jcs_digest(v):
    return "sha256:" + hashlib.sha256(jcs(v)).hexdigest()


def check_trace(doc, trust):
    if doc.get("format") != "provenza.trace-export/1":
        raise Fail("not a Provenza TRACE export (format)")
    parts = (doc.get("jwt") or "").split(".")
    if len(parts) != 3:
        raise Fail("jwt: not a compact JWS")
    header, claims = json.loads(_b64url_decode(parts[0])), json.loads(_b64url_decode(parts[1]))
    if header.get("alg") != "EdDSA":
        raise Fail("jwt: alg must be EdDSA")
    if claims.get("eat_profile") != TRACE_PROFILE:
        raise Fail("jwt: not a TRACE v0.2 record (eat_profile)")
    if doc.get("claims") is not None and doc["claims"] != claims:
        raise Fail("the claims shown beside the JWT are not the signed ones")
    jwk = (claims.get("cnf") or {}).get("jwk") or {}
    if (jwk.get("kty"), jwk.get("crv")) != ("OKP", "Ed25519"):
        raise Fail("cnf.jwk is not an Ed25519 key")
    pub = base64.b64encode(_b64url_decode(jwk["x"])).decode()
    key = doc.get("key") or {}
    if key.get("public_key") != pub:
        raise Fail("the export's key is not the key in cnf.jwk")
    fp = fingerprint(pub, key.get("pq_public_key"))
    if header.get("kid") != fp or jwk.get("kid") != fp:
        raise Fail("kid does not name the signing key")
    if trust:
        _require_trust(fp, {}, trust, "the trust record")
    _verify_pair("trust record", pub, key.get("pq_public_key"), base64.b64encode(_b64url_decode(parts[2])).decode(),
                 doc.get("pq_signature"), f"{parts[0]}.{parts[1]}".encode("ascii"))
    receipts = doc.get("receipts") or []
    refs = {r["id"]: r for r in claims.get("references") or [] if r.get("rel") == "pvp-receipt"}
    if not receipts or len(refs) != len(receipts):
        raise Fail("the export does not carry the receipts the record references")
    for r in receipts:
        ref = refs.get(str((r.get("action") or {}).get("action_id")))
        if ref is None or ref.get("digest") != _jcs_digest(r):
            raise Fail("a receipt differs from the one the signed record references")
        check_receipt(r, trust)
    transcript = (claims.get("tool_transcript") or {})
    if transcript.get("hash") != _jcs_digest([r["action"] for r in receipts]) \
            or transcript.get("call_count") != len(receipts):
        raise Fail("tool_transcript does not hash the actions carried")
    return claims, fp


def cmd_receipt(args) -> int:
    doc = _load(args.file)
    trust = Trust(args.fingerprint)
    action, cp, fp = check_receipt(doc, trust, args.agent_fingerprint, args.approver_passkey, args.proxy_fingerprint)
    who = (f"signed by agent key {fingerprint(action['signed_by']['public_key'], action['signed_by'].get('pq_public_key'))}"
           if action.get("signed_by") else f"executed and witnessed by the Provenza {action['executed_by']}")
    print(f"VERIFIED  action {action['action_id']} ({action['tool_name']}, {action['decision']}) of agent "
          f"{action['agent_id']}: {who}")
    print(f"          sealed in seal {doc['seal']['seal_id']}, audit record of organization {cp['org_id']}, "
          f"checkpoint of {cp['tree_size']} records signed by {fp}")
    if action.get("witness"):
        w = action["witness"]["statement"]
        print(f"          witnessed by egress proxy key {action['witness']['key_fingerprint']} (agent signature "
              f"{w.get('agent_signature')}; signed policy "
              f"{'release #%s' % w['policy']['release'] if w.get('policy') else 'none'})")
    if doc.get("approval"):
        ap = doc["approval"]
        print(f"          approved by user {ap['statement']['user_id']} (approval {ap['approval_id']}): signed with "
              f"their session key, certified by passkey {passkey_fingerprint(ap['passkey']['public_key'])}")
        if not args.approver_passkey:
            print("note: no --approver-passkey given - this proves a passkey approved it, not whose")
    if doc.get("current_decision") and doc["current_decision"] != action["decision"]:
        print(f"          decided later: {doc['current_decision']} (a human approval; not part of the proof)")
    if not args.agent_fingerprint and action.get("signed_by"):
        print("note: no --agent-fingerprint given - this proves the action was signed, not by whose key")
    _note(trust)
    return 0


def cmd_release(args) -> int:
    rel, signed = check_release(_load(args.file), args.passkey)
    print(f"VERIFIED  policy release #{rel['number']}: bundle v{rel['bundle']['version']} "
          f"{rel['bundle']['sha256'][:16]}, manifest v{rel['manifest']['version']} {rel['manifest']['sha256'][:16]}")
    for uid, fp in sorted(signed.items()):
        print(f"          signed by administrator {uid} with passkey {fp}")
    if not args.passkey:
        print("note: no --passkey given - this proves the quorum of the manifest it names signed, not that "
              "the manifest's passkeys are the ones you trust")
    return 0


def cmd_trace(args) -> int:
    doc = _load(args.file)
    trust = Trust(args.fingerprint)
    claims, fp = check_trace(doc, trust)
    print(f"VERIFIED  TRACE v0.2 trust record (level {doc.get('level')}) for {claims['subject']}: "
          f"{claims['tool_transcript']['call_count']} action(s), appraisal {claims['appraisal']['status']}, "
          f"policy {claims['policy']['enforcement_mode']}")
    print(f"          signed EdDSA{' + ML-DSA-65' if doc.get('pq_signature') else ''} by {fp}; every receipt verifies")
    _note(trust)
    return 0


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        raise SystemExit(2)


def _note(trust):
    if not trust:
        print("note: no --fingerprint given - this proves integrity, not whose key signed it")


def _print_chain(target, doc, trust, org_id):
    links = handover_links(doc, org_id)
    if links:
        for line in trust_report(target, links, trust)[1]:
            print("          " + line)


def cmd_verify(args) -> int:
    doc = _load(args.file)
    trust = Trust(args.fingerprint)
    payload, cp, fp = check_proof(doc, trust)
    print(f"VERIFIED  record seq {payload['seq']} ({payload['entity_type']} {payload['action']}, "
          f"{payload['created_at']}) is in the audit log of organization {cp['org_id']}")
    print(f"          checkpoint: {cp['tree_size']} records, root {cp['root_hash']}, issued {cp['issued_at']}")
    print(f"          signed by {fp} ({cp['algorithm']})")
    _print_chain(fp, doc, trust, cp["org_id"])
    _note(trust)
    return 0


def _tsa():
    """rfc3161.py beside this file: standalone, like this tool."""
    import importlib.util
    import os

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rfc3161.py")
    spec = importlib.util.spec_from_file_location("provenza_rfc3161", path)
    if spec is None or not os.path.exists(path):
        raise Fail("--tsa-ca needs rfc3161.py next to this tool")
    if spec.name in sys.modules:
        return sys.modules[spec.name]
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod   # its dataclasses look themselves up there
    spec.loader.exec_module(mod)
    return mod


def check_timestamps(cp, tsa_ca_path):
    """Every time-stamp the checkpoint carries is for its statement and
    chains to the given TSA. At least one is required."""
    tsa = _tsa()
    with open(tsa_ca_path, encoding="utf-8") as f:
        anchors = tsa.load_anchors(f.read())
    stamps = cp.get("timestamps") or []
    if not stamps:
        raise Fail(f"checkpoint {cp['tree_size']} carries no time-stamp")
    digest = hashlib.sha256(cp["statement"].encode("utf-8")).digest()
    out = []
    for st in stamps:
        try:
            tok = tsa.verify_token(base64.b64decode(st["token"]), digest, anchors)
        except tsa.TimestampError as e:
            raise Fail(f"time-stamp of checkpoint {cp['tree_size']} from {st.get('tsa_url')}: {e.code} {e.detail}")
        out.append(tok)
    return out


def _print_stamps(cp, toks):
    for tok in toks:
        print(f"          time-stamped {tok.gen_time.isoformat()} by {tok.tsa_subject} (serial {tok.serial}): "
              f"the log had these {cp['tree_size']} records then")


def cmd_checkpoint(args) -> int:
    cp = _load(args.file)
    trust = Trust(args.fingerprint)
    if trust:
        _require_trust(signer_of(cp), {}, trust, "the checkpoint")
    fp = check_checkpoint(cp)
    toks = check_timestamps(cp, args.tsa_ca) if args.tsa_ca else []
    print(f"VERIFIED  checkpoint of organization {cp['org_id']}: {cp['tree_size']} records, root {cp['root_hash']}")
    print(f"          signed by {fp} ({cp['algorithm']})")
    _print_stamps(cp, toks)
    _note(trust)
    return 0


def cmd_consistency(args) -> int:
    pinned = _load(args.pinned) if args.pinned else None
    doc = _load(args.file)
    trust = Trust(args.fingerprint)
    old, new, fp_old, fp = check_consistency(doc, pinned, trust)
    # the auditor's own copy, when it has its tokens: the server's need not be trusted for them
    stamped = pinned if pinned is not None and pinned.get("timestamps") else old
    toks_old = check_timestamps(stamped, args.tsa_ca) if args.tsa_ca else []
    print(f"VERIFIED  the log of organization {new['org_id']} at {new['tree_size']} records extends "
          f"the one at {old['tree_size']}: nothing in the first {old['tree_size']} was changed or removed")
    print(f"          signed by {fp}" + (f" (key changed from {fp_old})" if fp != fp_old else ""))
    _print_stamps(old, toks_old)
    _print_chain(fp, doc, trust, new["org_id"])
    _note(trust)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("file")
    v.add_argument("--fingerprint", action="append", default=[])
    c = sub.add_parser("checkpoint")
    c.add_argument("file")
    c.add_argument("--fingerprint", action="append", default=[])
    c.add_argument("--tsa-ca")
    s = sub.add_parser("consistency")
    s.add_argument("file")
    s.add_argument("--pinned")
    s.add_argument("--fingerprint", action="append", default=[])
    s.add_argument("--tsa-ca")
    r = sub.add_parser("receipt")
    r.add_argument("file")
    r.add_argument("--fingerprint", action="append", default=[])
    r.add_argument("--agent-fingerprint")
    r.add_argument("--proxy-fingerprint", action="append", default=[],
                   help="fingerprint of an egress proxy key you trust (its receipt must be signed by it); repeatable")
    r.add_argument("--approver-passkey", action="append", default=[],
                   help="fingerprint of a passkey trusted to approve (My profile -> Passkeys); repeatable")
    rr = sub.add_parser("release")
    rr.add_argument("file")
    rr.add_argument("--passkey", action="append", default=[],
                    help="fingerprint of an administrator passkey you trust; repeatable")
    t = sub.add_parser("trace")
    t.add_argument("file")
    t.add_argument("--fingerprint", action="append", default=[])
    args = p.parse_args(argv)
    try:
        return {"verify": cmd_verify, "checkpoint": cmd_checkpoint, "consistency": cmd_consistency,
                "receipt": cmd_receipt, "trace": cmd_trace, "release": cmd_release}[args.cmd](args)
    except TrustFail as e:
        for line in e.lines:  # the trust chain first: it, not the signature, is the usual culprit
            print(line)
        print(f"NOT VERIFIED  {e}")
        return 1
    except Fail as e:
        print(f"NOT VERIFIED  {e}")
        return 1
    except (KeyError, TypeError, ValueError) as e:
        print(f"NOT VERIFIED  malformed file: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
