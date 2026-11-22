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
  checkpoint CHECKPOINT.json [--fingerprint SHA256:...]... [--tsa-ca TSA.pem] [PUBLICATION]
        one signed checkpoint (GET /audit-logs/checkpoints, or the
        "checkpoint" part of a proof)
  consistency CONSISTENCY.json [--pinned CHECKPOINT.json] [--fingerprint SHA256:...]... [--tsa-ca TSA.pem]
              [PUBLICATION]
        GET /audit-logs/consistency?from_size=N: the newer checkpoint
        extends the older one - nothing in the first N records was changed
        or removed. With --pinned, the older checkpoint must also be the one
        you saved earlier

  --tsa-ca: the checkpoints' RFC 3161 time-stamps ("timestamps") must
        verify against this TSA certificate or CA (rfc3161.py, next to this
        file): a third party saw exactly that state of the log at that time

  PUBLICATION: [--require-rekor] [--publishing-key SHA256:...]... [--rekor-key REKOR.pem]...
        the Rekor entries a checkpoint carries ("publications") are checked
        always: each is a hashedrekord of exactly that checkpoint's
        statement, signed by the organization's publishing key, and its
        signed entry timestamp verifies with the log's key - the Sigstore
        log's is built in, --rekor-key adds another instance's. An entry
        that does not verify fails the check; one from a log you gave no key
        for is named as not checked. --require-rekor: at least one must
        verify (for consistency: on the older checkpoint) - the state of the
        log was public at that time. --publishing-key pins the publishing
        key (fingerprint on the Audit Log page). An S3 copy is named; fetch
        the object and run `checkpoint` on it

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
  authority PROOF.json [--fingerprint SHA256:...]... [--agent-fingerprint SHA256:...]
                       [--passkey SHA256:...]... [--require-full]
        a Proof of Authority (GET /pvp/authority/{action_id};
        docs/proof-of-authority.md): the receipt as above, and the chain of
        authority behind it - the signed policy release it was decided
        under, verified back to the organization's first release; the
        agent's rights and key in that release; each delegation hop signed
        by the delegating agent's key; the agent's own signature on the
        call; the approver's passkey listed in the signed manifest; and the
        task a person gave, when the call names one - signed with their
        passkey-certified session key, for this agent, tool and time. A link
        that is absent (no signed release, a keyless agent) is reported as
        not proven; --require-full makes that a failure
  completeness REPORT.json [--fingerprint SHA256:...]... [--list N] [--require-full]
        GET /pvp/completeness?agent_id=&since=&until=: consecutive chained
        seals, each one's record in the signed log and its root the Merkle
        root of exactly the actions given - so the agent's actions listed
        are all Provenza recorded for it between the first and the last
  incident BUNDLE.json [--fingerprint SHA256:...]... [--agent-fingerprint SHA256:...]
                       [--passkey SHA256:...]... [--list N] [--require-full]
        an incident bundle (GET /pvp/incidents/{id}/bundle;
        docs/incident-bundle.md): the agent's actions in the window shown to
        be all of them (as completeness), the audit records about it in the
        signed log, the agent's own signature on each call it asked for, the
        tasks, approvals and release people signed with their passkeys, and
        the delegation hops - then one timeline, each line saying who vouches
        for it. What only the server says (the incident itself, unless its
        quarantine record is in the log; checks the agent did not sign) is
        named as such; --require-full makes any such gap a failure
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
import time

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


def _verify_passkey(passkey, assertion, challenge: bytes, label="approval"):
    """A WebAuthn assertion (docs/pvp/edge.md, section 2) by this passkey
    over this challenge, made with the person verified (PIN or biometric)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    client_raw = _b64url_decode(assertion["client_data_json"])
    auth = _b64url_decode(assertion["authenticator_data"])
    client = json.loads(client_raw.decode("utf-8"))
    if client.get("type") != "webauthn.get":
        raise Fail(f"{label}: the passkey certificate is not a WebAuthn assertion")
    if client.get("challenge") != base64.urlsafe_b64encode(challenge).decode().rstrip("="):
        raise Fail(f"{label}: the passkey did not sign this session certificate")
    if len(auth) < 37 or auth[32] & 0x05 != 0x05:
        raise Fail(f"{label}: the passkey was used without verifying the person (PIN or biometric)")
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
            raise Fail(f"{label}: unsupported passkey algorithm {passkey['alg']}")
    except (InvalidSignature, TypeError, AttributeError):
        raise Fail(f"{label}: the passkey's signature on the session certificate does not verify")


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


MANDATE_TYPE = "provenza.mandate"
MANDATE_END_TYPE = "provenza.mandate.end"
MANDATE_END_FIELDS = ("type", "v", "org_id", "user_id", "session_id", "mandate_id", "statement_sha256", "issued_at")
CHECK_WINDOW = 300          # seconds a check may wait for its record (CHECK_TTL_SECONDS)
MANDATE_FIELDS = ("type", "v", "org_id", "user_id", "session_id", "agent_id", "task", "tools", "valid_hours", "nonce",
                  "issued_at")


def check_mandate(m, action, org_id=None, root_agent_id=None) -> str:
    """The task a person gave, that the action names (Proof of Authority):
    the statement is the one the evidence names, gives the task to this agent
    (or to the root of its delegation chain), covers the tool and the time,
    and the person's session key signed it, certified by their passkey.
    Returns the passkey fingerprint."""
    ref = action.get("mandate") or {}
    st = m.get("statement") or {}
    if set(st) != set(MANDATE_FIELDS) or st.get("type") != MANDATE_TYPE or st.get("v") != 1:
        raise Fail("task: not a signed task statement")
    if m.get("mandate_id") != ref.get("id") or _sha(st) != ref.get("statement_sha256"):
        raise Fail("task: not the task the action's evidence names")
    if org_id is not None and st["org_id"] != org_id:
        raise Fail("task: given in another organization")
    # a refused call may have named a task outside which it was: only an
    # allowed one must be inside it
    allowed = action.get("decision") == "allowed"
    if allowed and st["agent_id"] not in (action.get("agent_id"), root_agent_id):
        raise Fail(f"task: given to agent {st['agent_id']}, not to agent {action.get('agent_id')} or the root of "
                   f"its delegation chain, yet the action was allowed")
    if allowed and st["tools"] is not None and action.get("action_type") != "model_call" \
            and action.get("tool_name") not in st["tools"]:
        raise Fail(f"task: it does not include the tool {action.get('tool_name')}, yet the action was allowed")
    # checked while the task was in force, recorded at most CHECK_WINDOW later
    at, until = action.get("recorded_at"), st["issued_at"] + st["valid_hours"] * 3600
    if allowed and isinstance(at, int) and not st["issued_at"] <= at <= until + CHECK_WINDOW:
        raise Fail("task: the action was allowed outside the time the task was given for")
    fp = _session_signed(m, "task")
    # what ended it, signed by a person: their end statement, or the statement
    # of the task that replaced it
    end = m.get("ended")
    if end:
        est = end.get("statement") or {}
        if est.get("type") == MANDATE_END_TYPE:
            if set(est) != set(MANDATE_END_FIELDS) or est.get("mandate_id") != m.get("mandate_id") \
                    or est.get("statement_sha256") != ref.get("statement_sha256"):
                raise Fail("task: the end statement ends another task")
        elif est.get("type") == MANDATE_TYPE:
            if set(est) != set(MANDATE_FIELDS) or est.get("agent_id") != st["agent_id"] \
                    or not isinstance(est.get("issued_at"), int) or est["issued_at"] < st["issued_at"] \
                    or _sha(est) == ref.get("statement_sha256"):
                raise Fail("task: the task said to have replaced it does not replace it")
        else:
            raise Fail("task: what ended it is not a signed statement")
        if est.get("org_id") != st["org_id"]:
            raise Fail("task: ended in another organization")
        _session_signed(end, "task end")
        if allowed and isinstance(at, int) and est["issued_at"] + CHECK_WINDOW < at:
            raise Fail("task: the action was allowed after the task was ended")
    elif m.get("status") == "ended":
        raise Fail("task: said to be ended, but the file carries no signed statement that ended it")
    return fp


def task_end(m):
    """(unix time, user id) of the signed statement that ended the task, or None."""
    est = (m.get("ended") or {}).get("statement")
    return (est["issued_at"], est["user_id"]) if est else None


def _session_signed(m, label) -> str:
    """A statement a person signed with their session key (a task, its end):
    the key is the one their passkey certified, for this person and session,
    and it signed inside the certificate's validity. Returns the passkey
    fingerprint."""
    st, cert = m.get("statement") or {}, (m.get("certificate") or {}).get("statement") or {}
    if cert.get("type") != CERTIFICATE_TYPE or cert.get("public_key") != m.get("session_public_key"):
        raise Fail(f"{label}: the session certificate is not for the key that signed")
    for k in ("org_id", "user_id", "session_id"):
        if st.get(k) != cert.get(k):
            raise Fail(f"{label}: signed in another session than the certificate names ({k})")
    if not isinstance(st.get("issued_at"), int) or not cert["not_before"] <= st["issued_at"] <= cert["not_after"]:
        raise Fail(f"{label}: signed outside the session's validity")
    if not _verify_ed25519(m["session_public_key"], m.get("signature"), canonical(st)):
        raise Fail(f"{label}: the session key's signature does not verify")
    _verify_passkey(m["passkey"], m["certificate"]["assertion"], hashlib.sha256(canonical(cert)).digest(), label)
    return passkey_fingerprint(m["passkey"]["public_key"])


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


REQUEST_FIELDS = ("type", "agent_id", "chain_id", "action_type", "tool_name", "input_sha256", "tool_version",
                  "tool_digest", "nonce", "issued_at")


def check_requested(req, action) -> str:
    """The agent's own signed action.request (Proof of Authority): it asks
    for exactly this call, and the agent's key signed it. Returns the key
    fingerprint."""
    p, sig = req.get("payload") or {}, req.get("signed_by") or {}
    if set(p) - {"mandate_id"} != set(REQUEST_FIELDS) or p.get("type") != "action.request":
        raise Fail("the agent's request: not a signed action.request")
    for k in ("agent_id", "chain_id", "action_type", "tool_name", "input_sha256"):
        if p.get(k) != action.get(k):
            raise Fail(f"the agent's request asks for another call ({k})")
    named = (action.get("mandate") or {}).get("id")
    if (named is not None or action.get("decision") == "allowed") and p.get("mandate_id") != named:
        raise Fail("the agent's request names another task than the action's evidence")
    _verify_pair("the agent's request", sig["public_key"], sig.get("pq_public_key"), sig["signature"],
                 sig.get("pq_signature"), canonical(p))
    return fingerprint(sig["public_key"], sig.get("pq_public_key"))


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
    # 3a. the agent's own signed request for this call (a gateway executed it)
    if action.get("requested") is not None:
        rfp = check_requested(action["requested"], action)
        if agent_fp and rfp != agent_fp:
            raise Fail("the request was signed by another key than the agent fingerprint you gave")
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


# ---------------------------------------------------------------- Proof of Authority

def check_release_chain(docs, passkey_fps=None):
    """Every release from the organization's first one to the last in the
    file verifies (check_release), and each is governed by the one before it
    - the history is unbroken. --passkey pins the release last in the file
    (the one the action was decided under). Returns (last document, [(number,
    {user_id: passkey fingerprint})] for each release)."""
    prev, signed_by = None, []
    for i, d in enumerate(docs):
        last = i == len(docs) - 1
        rel, signed = check_release(d, passkey_fps if last else None)
        gov = d.get("governed_by")
        if prev is None:
            if gov is not None:
                raise Fail(f"release #{rel['number']} is governed by release #{gov.get('number')}, which the file "
                           f"does not carry - the history must start at the organization's first release")
        elif gov is None or gov.get("number") != prev["release"]["number"] \
                or gov.get("manifest_sha256") != prev["release"]["manifest"]["sha256"] \
                or gov.get("bundle_sha256") != prev["release"]["bundle"]["sha256"]:
            raise Fail(f"release #{rel['number']} is not governed by release #{prev['release']['number']} "
                       f"before it - the history is broken")
        prev = d
        signed_by.append((rel["number"], signed))
    return prev, signed_by


def _signer_of_passkey(manifest, fp):
    """(user id, role) of the person whose passkey has this fingerprint in a
    signed manifest, or None."""
    for uid, person in (manifest.get("signers") or {}).items():
        for key in (person.get("passkeys") or {}).values():
            if key.get("fingerprint") == fp:
                return uid, person.get("role")
    return None


def delegation_path(deleg, action):
    """The hops that brought the acting agent into its chain, from the agent
    back to the chain's root: at each step the latest hop to that agent
    before the one after it."""
    hops, root, cur = deleg.get("hops") or [], deleg.get("root_agent_id"), action["agent_id"]
    path, below = [], None
    while cur != root:
        cands = [h for h in hops if h["to_agent_id"] == cur and (below is None or h["hop_id"] < below)]
        if not cands or len(path) > len(hops):
            raise Fail(f"no delegation in the file brings agent {cur} into chain {deleg.get('chain_id')}")
        h = max(cands, key=lambda x: x["hop_id"])
        path.append(h)
        cur, below = h["from_agent_id"], h["hop_id"]
    return path


def check_hop(h, manifest=None):
    """A delegation hop: the delegating agent's key signed exactly it, and -
    with a signed manifest - that key is the one the manifest lists. Returns
    the key fingerprint, or None for an unsigned hop (a keyless agent)."""
    p, sig = h.get("signed_payload"), h.get("signed_by")
    if not p or not sig:
        return None
    if p.get("from_agent_id") != h["from_agent_id"] or p.get("to_agent_id") != h["to_agent_id"]:
        raise Fail(f"delegation hop {h['hop_id']}: the signed delegation names other agents")
    _verify_pair(f"delegation hop {h['hop_id']}", sig["public_key"], sig.get("pq_public_key"), sig["signature"],
                 sig.get("pq_signature"), canonical(p))
    fp = fingerprint(sig["public_key"], sig.get("pq_public_key"))
    if manifest is not None and (manifest.get("agents") or {}).get(str(h["from_agent_id"])) != fp:
        raise Fail(f"delegation hop {h['hop_id']}: agent {h['from_agent_id']}'s key is not the one in the "
                   f"signed manifest")
    return fp


def check_authority(doc, trust=None, agent_fp=None, passkey_fps=None):
    """Proof of Authority (docs/proof-of-authority.md). Returns (lines to
    print, links not proven)."""
    if doc.get("pvp") != "pvp/1" or doc.get("type") != "authority":
        raise Fail("not a Proof of Authority (pvp/1)")
    receipt = doc.get("receipt") or {}
    action, cp, fp = check_receipt(receipt, trust, agent_fp)
    lines, gaps = [], []
    allowed = action.get("decision") == "allowed"

    # the agent's key: its signed record, or its signed request for a gateway-executed call
    key_fp, how = None, None
    if action.get("signed_by"):
        sb = action["signed_by"]
        key_fp, how = fingerprint(sb["public_key"], sb.get("pq_public_key")), "signed the action record"
    elif action.get("requested"):
        sb = action["requested"]["signed_by"]
        key_fp, how = fingerprint(sb["public_key"], sb.get("pq_public_key")), "signed the request for this call"

    # 1-2. the signed policy and the agent's rights in it
    manifest = None
    ref = action.get("release")
    if ref:
        docs = doc.get("releases") or []
        if not docs:
            raise Fail(f"the action names signed release #{ref['number']}, but the file carries no releases")
        last, signed_by = check_release_chain(docs, passkey_fps)
        rel = last["release"]
        if rel["number"] != ref["number"] or rel["bundle"]["sha256"] != ref["bundle_sha256"]:
            raise Fail(f"the releases in the file end at #{rel['number']}, not at release #{ref['number']} the "
                       f"action was decided under")
        bundle, manifest = last["bundle"], last["manifest"]
        signers = ", ".join(f"administrator {u} (passkey {f})" for u, f in sorted(signed_by[-1][1].items()))
        lines.append(f"policy:     release #{rel['number']} (bundle v{bundle['version']} {rel['bundle']['sha256'][:16]}) "
                     f"signed by {signers}; history verified from release #{signed_by[0][0]}")
        entry = (bundle.get("agents") or {}).get(str(action["agent_id"]))
        if entry is None:
            raise Fail(f"agent {action['agent_id']} is not in the signed policy (release #{rel['number']})")
        if allowed:
            if entry.get("status") != "active":
                raise Fail(f"the signed policy has agent {action['agent_id']} {entry.get('status')}, yet the action "
                           f"was allowed")
            if action.get("action_type") != "model_call" and action["tool_name"] not in (entry.get("allowed_tools") or []):
                raise Fail(f"the signed policy does not give agent {action['agent_id']} the tool "
                           f"{action['tool_name']}, yet the action was allowed")
        signed_fp = (manifest.get("agents") or {}).get(str(action["agent_id"]))
        if key_fp and signed_fp != key_fp:
            raise Fail(f"the agent's key {key_fp} is not the one the signed manifest lists ({signed_fp})")
        lines.append(f"rights:     the signed policy gives agent {action['agent_id']} "
                     f"{'the tool ' + action['tool_name'] if action.get('action_type') != 'model_call' else 'its models'}"
                     f"{'' if not signed_fp else '; its key ' + signed_fp + ' is the one in the signed manifest'}")
    else:
        gaps.append("policy: the action names no signed release - the organization had none in force, or the "
                    "action predates Proof of Authority; its rights rest on the server's word")

    # 3. the delegation chain
    if action.get("chain_id"):
        deleg = doc.get("delegation")
        if not deleg or deleg.get("chain_id") != action["chain_id"]:
            raise Fail(f"the action is in delegation chain {action['chain_id']}, but the file does not carry it")
        path = delegation_path(deleg, action)
        steps = []
        for h in path:
            hfp = check_hop(h, manifest)
            steps.append(f"agent {h['from_agent_id']} -> agent {h['to_agent_id']} (hop {h['hop_id']}, "
                         f"{'signed by ' + hfp if hfp else 'NOT signed'})")
            if hfp is None:
                gaps.append(f"delegation: hop {h['hop_id']} is not signed (a keyless agent)")
        incoming = path[0] if path else None
        tools = ((incoming or {}).get("signed_payload") or {}).get("delegated_tools")
        if allowed and tools is not None and action["tool_name"] not in tools:
            raise Fail(f"the delegation to agent {action['agent_id']} does not pass on {action['tool_name']}, yet "
                       f"the action was allowed")
        lines.append("delegation: " + ("; ".join(reversed(steps)) if steps else
                                       f"agent {action['agent_id']} is the chain's root"))
    else:
        lines.append(f"delegation: none - agent {action['agent_id']} acted on its own rights")

    # 4. the agent's own signature
    if key_fp:
        lines.append(f"agent:      agent {action['agent_id']} {how} with key {key_fp}")
    elif action.get("executed_by"):
        gaps.append(f"agent: the agent did not sign this call - only its API key identified it to the "
                    f"{action['executed_by']}")
    # 0. the task a person gave, when the call names one
    if action.get("mandate"):
        m = doc.get("mandate")
        if not m:
            raise Fail(f"the action names task #{action['mandate']['id']}, but the file does not carry it")
        root = (doc.get("delegation") or {}).get("root_agent_id")
        mfp = check_mandate(m, action, doc.get("org_id"), root)
        st, who, listed = m["statement"], f"user {m['statement']['user_id']}", False
        if manifest is not None:
            found = _signer_of_passkey(manifest, mfp)
            if found is None:
                gaps.append(f"task: passkey {mfp} is not in the signed manifest (added after the release?) - the "
                            f"standing of the person who gave the task rests on the server's word")
            else:
                who, listed = f"{found[1]} {found[0]}", True
        scope = "all of its tools" if st["tools"] is None else ", ".join(st["tools"])
        lines.insert(0, f"task:       task #{m['mandate_id']} given by {who} with passkey {mfp}"
                        f"{' (listed in the signed manifest)' if listed else ''} to agent {st['agent_id']} for "
                        f"{st['valid_hours']} h ({scope}): {st['task'][:120]}")
        ended = task_end(m)
        if ended:
            when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ended[0]))
            lines.insert(1, f"            ended {when} by user {ended[1]}, signed"
                            f"{' (a new task replaced it)' if m['ended']['statement']['type'] == MANDATE_TYPE else ''}")
    # 5. the person's approval
    if receipt.get("approval"):
        ap = receipt["approval"]
        afp = passkey_fingerprint(ap["passkey"]["public_key"])
        who = f"user {ap['statement']['user_id']}"
        listed = False
        if manifest is not None:
            found = _signer_of_passkey(manifest, afp)
            if found is None:
                gaps.append(f"approval: passkey {afp} is not in the signed manifest (added after the release?) - "
                            f"the approver's standing rests on the server's word")
            else:
                who, listed = f"{found[1]} {found[0]}", True
        lines.append(f"approval:   approved by {who} with passkey {afp}"
                     f"{' (listed in the signed manifest)' if listed else ''}")
    # 6. the record
    lines.append(f"record:     sealed in seal {receipt['seal']['seal_id']}; checkpoint of {cp['tree_size']} records "
                 f"of organization {cp['org_id']} signed by {fp}")
    return action, lines, gaps


def merkle_root(hashes):
    """RFC 9162 Merkle tree hash over leaf data (here: evidence hashes)."""
    if not hashes:
        return hashlib.sha256(b"").digest()
    level = [_leaf(h) for h in hashes]

    def mth(nodes):
        if len(nodes) == 1:
            return nodes[0]
        k = 1
        while k * 2 < len(nodes):
            k *= 2
        return _node(mth(nodes[:k]), mth(nodes[k:]))
    return mth(level)


def check_completeness(doc, trust=None):
    """A completeness report: consecutive chained seals, each one's audit
    record in the signed log and its root exactly the Merkle root of the
    evidence given for it. Returns (all members, the agent's members,
    first seal, last seal, checkpoint fingerprints)."""
    if doc.get("pvp") != "pvp/1" or doc.get("type") != "completeness":
        raise Fail("not a completeness report (pvp/1)")
    seals_ = doc.get("seals") or []
    if not seals_:
        raise Fail("the report carries no seals")
    prev, members_all, fps, org = None, [], set(), None
    for s in seals_:
        payload, cp, fp = check_proof(s["audit_proof"], trust if trust is not None else Trust())
        fps.add(fp)
        if (payload.get("entity_type"), payload.get("entity_id")) != (SEAL_ENTITY, s["seal_id"]):
            raise Fail(f"seal {s['seal_id']}: its audit record is not that seal's")
        org = payload["org_id"] if org is None else org
        if payload["org_id"] != org:
            raise Fail("the seals belong to different organizations")
        meta = payload.get("metadata") or {}
        if "prev_seal_id" not in meta:
            raise Fail(f"seal {s['seal_id']} predates the seal chain - completeness cannot be shown that far back")
        members = s.get("members") or []
        if len(members) != meta.get("size"):
            raise Fail(f"seal {s['seal_id']}: {len(members)} actions given, the seal holds {meta.get('size')}")
        ids = [m["action_id"] for m in members]
        if ids != sorted(ids) or len(set(ids)) != len(ids) or (ids and (ids[0], ids[-1]) != (
                meta.get("first_action_id"), meta.get("last_action_id"))):
            raise Fail(f"seal {s['seal_id']}: the actions given are not the ones it seals")
        root = merkle_root([hashlib.sha256(canonical(m)).digest() for m in members])
        if root.hex() != meta.get("root"):
            raise Fail(f"seal {s['seal_id']}: the actions given do not hash to its root - one was added, "
                       f"dropped or altered")
        if prev is not None and (meta.get("prev_seal_id"), meta.get("prev_root")) != (prev[0], prev[1]):
            raise Fail(f"seal {s['seal_id']} does not follow seal {prev[0]} - a seal is missing between them")
        prev = (s["seal_id"], meta.get("root"))
        members_all += members
    mine = [m for m in members_all if m.get("agent_id") == doc.get("agent_id")]
    return members_all, mine, seals_[0]["seal_id"], seals_[-1]["seal_id"], fps


def _first_is_genesis(doc) -> bool:
    """The report's first seal is the organization's very first one: nothing
    was sealed before it."""
    rec = doc["seals"][0]["audit_proof"]["record"]
    meta = (json.loads(rec["canonical"]).get("metadata") or {})
    return "prev_seal_id" in meta and meta["prev_seal_id"] is None


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
    # a refused call was never executed: the gateway decided it and is the witness of that
    did = {"allowed": "executed", "denied": "refused"}.get(action.get("decision"), "recorded")
    who = (f"signed by agent key {fingerprint(action['signed_by']['public_key'], action['signed_by'].get('pq_public_key'))}"
           if action.get("signed_by") else f"{did} and witnessed by the Provenza {action['executed_by']}")
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


def cmd_authority(args) -> int:
    doc = _load(args.file)
    trust = Trust(args.fingerprint)
    action, lines, gaps = check_authority(doc, trust, args.agent_fingerprint, args.passkey)
    head = "VERIFIED" if not gaps else "VERIFIED, WITH GAPS"
    print(f"{head}  proof of authority for action {action['action_id']} ({action['tool_name']}, "
          f"{action['decision']}) of agent {action['agent_id']}")
    for line in lines:
        print("          " + line)
    for g in gaps:
        print("not proven: " + g)
    if not args.passkey and action.get("release"):
        print("note: no --passkey given - this proves the policy's quorum signed, not that those passkeys are the "
              "ones you trust")
    _note(trust)
    return 1 if gaps and args.require_full else 0


def _when(t):
    import datetime as _dt
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def cmd_completeness(args) -> int:
    doc = _load(args.file)
    trust = Trust(args.fingerprint)
    members, mine, first, last, fps = check_completeness(doc, trust)
    span = (min(m["recorded_at"] for m in members), max(m["recorded_at"] for m in members))
    period = doc.get("period") or {}
    since, until = period.get("since", span[0]), period.get("until", span[1])
    inside = [m for m in mine if since <= m["recorded_at"] <= until]
    print(f"VERIFIED  seals {first}..{last} are unbroken: {len(members)} action(s) recorded between "
          f"{_when(span[0])} and {_when(span[1])}, signed by {', '.join(sorted(fps))}")
    print(f"          agent {doc.get('agent_id')}: {len(inside)} action(s) in the period "
          f"{_when(since)} - {_when(until)}, and no other in these seals")
    by = {}
    for m in inside:
        by[m["decision"]] = by.get(m["decision"], 0) + 1
    if by:
        print("          " + ", ".join(f"{n} {d}" for d, n in sorted(by.items())))
    for m in inside[: args.list]:
        print(f"          #{m['action_id']}  {_when(m['recorded_at'])}  {m['tool_name']}  {m['decision']}")
    gap = False
    if span[0] > since and not _first_is_genesis(doc):
        gap = True
        print(f"not proven: the seals start at {_when(span[0])}, after the period's start - an earlier seal "
              f"may hold actions of the period")
    if span[1] < until:
        issued = doc.get("issued_at")
        print(f"note: the last sealed action is at {_when(span[1])}; for the rest of the period the report rests "
              f"on the server's word that nothing more was recorded"
              f"{' before it was issued at ' + _when(issued) if isinstance(issued, int) else ''}")
    if gap and args.require_full:
        _note(trust)
        return 1
    print("note: actions Provenza never saw (a tool called directly, without the egress lockdown or the "
          "sensor) cannot be in any report")
    _note(trust)
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


# ---------------------------------------------------------------------------
# Incident bundle (docs/incident-bundle.md)
# ---------------------------------------------------------------------------

AGENT_RELEASE_TYPE = "provenza.agent.release"
# audit records about what governs every agent (app/pvp/incident_bundle.py CONTEXT)
INCIDENT_CONTEXT = ("kill_switch", "behavior_monitor", "policy_release", "agent_identity", "tool_registry")


def _audit_time(payload):
    import datetime as _dt
    t = _dt.datetime.strptime(payload["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
    return t.replace(tzinfo=_dt.timezone.utc).timestamp()


def _signed_by_person(m, label, passkey_fps):
    fp = _session_signed(m, label)
    if passkey_fps and fp not in passkey_fps:
        raise Fail(f"{label}: signed with passkey {fp}, not one of the passkeys you gave")
    return fp


def check_incident(doc, trust=None, agent_fp=None, passkey_fps=None):
    """An incident bundle. Returns (summary lines, timeline events, gaps);
    an event is (unix time, who vouches for it, text)."""
    if doc.get("pvp") != "pvp/1" or doc.get("type") != "incident":
        raise Fail("not an incident bundle (pvp/1)")
    org, agent, inc = doc["org_id"], doc["agent"], doc["incident"]
    aid = agent["id"]
    since, until = doc["window"]["since"], doc["window"]["until"]
    if inc.get("agent_id") != aid:
        raise Fail("the incident is not about the agent the bundle describes")
    trust = trust if trust is not None else Trust()
    lines, events, gaps = [], [], []
    keys = set()

    # every action recorded in the window, shown to be all of them
    comp = doc.get("completeness")
    if comp:
        if comp.get("org_id") != org or comp.get("agent_id") != aid:
            raise Fail("the completeness report is about another agent or organization")
        members, mine, first, last, fps = check_completeness(comp, trust)
        keys |= fps
        inside = [m for m in mine if since <= m["recorded_at"] <= until]
        for m in inside:
            events.append((m["recorded_at"], "signed log",
                           f"action #{m['action_id']} {m.get('tool_name')} {m.get('decision')}"))
        lines.append(f"actions: {len(inside)} recorded in the window, and no other (seals {first}..{last})")
        span = (min(x["recorded_at"] for x in members), max(x["recorded_at"] for x in members))
        if span[0] > since and not _first_is_genesis(comp):
            gaps.append(f"the seals start at {_when(span[0])}, after the window's start - an earlier seal may "
                        f"hold actions of the window")
    else:
        gaps.append(f"no proof that the actions are all of them: {doc.get('completeness_gap') or 'not given'}")

    # the audit records about the agent, each in the signed log
    task_ids = {t.get("mandate_id") for t in doc.get("tasks") or []}
    quarantine = None
    for p in doc.get("audit") or []:
        payload, cp, fp = check_proof(p, trust)
        keys.add(fp)
        if payload["org_id"] != org:
            raise Fail("an audit record of another organization")
        et, eid, meta = payload.get("entity_type"), payload.get("entity_id"), payload.get("metadata") or {}
        if not ((et == "agent" and eid == aid) or et in INCIDENT_CONTEXT or (et == "task_mandate" and eid in task_ids)):
            raise Fail(f"audit record {payload['seq']} ({et} {eid}) is not about this agent")
        who = f" by user {payload['actor_user_id']}" if payload.get("actor_user_id") else ""
        text = f"{et} {payload.get('action')}{who}"
        if et == "agent" and payload.get("action") == "quarantined":
            c = meta.get("contained") or {}
            text += f" - {c.get('reason') or 'behaviour score ' + str(meta.get('score'))}"
            if meta.get("incident_id") == inc["id"]:
                quarantine = meta
        events.append((_audit_time(payload), "signed log", text))
    if doc.get("audit_truncated"):
        gaps.append("more audit records fell in the window than the bundle carries")

    # the incident: in the signed log when it is a quarantine, otherwise the server's word
    if quarantine is not None:
        lines.append(f"incident #{inc['id']} ({inc['incident_type']}): its record is in the signed audit log")
    else:
        gaps.append(f"incident #{inc['id']} ({inc['incident_type']}) itself rests on the server's word")
    events.append((inc["at"], "signed log" if quarantine is not None else "server",
                   f"INCIDENT #{inc['id']} {inc['incident_type']} ({inc.get('severity')})"))
    for o in doc.get("other_incidents") or []:
        events.append((o["at"], "server", f"incident #{o['id']} {o['incident_type']} ({o.get('severity')})"))

    # the checks: those the agent asked for itself carry its signed request
    checks = doc.get("checks") or []
    signed_checks, by_id = 0, {}
    for c in checks:
        by_id[c["check_id"]] = c
        flag = " [past its boundaries]" if c.get("boundary") else ""
        text = f"check #{c['check_id']} {c.get('tool_name')} {c.get('decision')}{flag}: {c.get('reason')}"
        if c.get("requested"):
            fp = check_requested(c["requested"], {**c, "agent_id": aid, "mandate": {"id": c.get("mandate_id")}})
            if agent_fp and fp != agent_fp:
                raise Fail(f"check #{c['check_id']}: the request is signed by {fp}, not the agent key you gave")
            keys.add(fp)
            signed_checks += 1
            events.append((c["at"], "agent's key", text))
        else:
            events.append((c["at"], "server", text))
    boundary = [c for c in checks if c.get("boundary")]
    lines.append(f"checks: {len(checks)} in the window, {signed_checks} asked for in the agent's own signed "
                 f"request; {len(boundary)} refused for reaching past its boundaries"
                 + (f" ({', '.join(sorted({str(c.get('tool_name')) for c in boundary}))})" if boundary else ""))
    if len(checks) > signed_checks:
        gaps.append(f"{len(checks) - signed_checks} check(s) the agent did not sign rest on the server's word")
    if doc.get("checks_truncated"):
        gaps.append("more checks fell in the window than the bundle carries")
    if quarantine is not None:
        led = [r.get("check_id") for r in (quarantine.get("contained") or {}).get("refusals") or []]
        if led:
            own = [i for i in led if (by_id.get(i) or {}).get("requested")]
            lines.append(f"the quarantine names {len(led)} refusal(s) that led to it; the agent signed the "
                         f"request of {len(own)} of them")

    # what people signed: tasks, decisions on held calls, the release
    for m in doc.get("tasks") or []:
        st = m.get("statement") or {}
        check_mandate(m, {"mandate": {"id": m.get("mandate_id"), "statement_sha256": _sha(st)},
                          "decision": "denied"}, org)
        _signed_by_person(m, "task", passkey_fps)
        to = "" if st.get("agent_id") == aid else f" (given to agent {st.get('agent_id')})"
        events.append((st["issued_at"], "person's passkey",
                       f"task #{m['mandate_id']} given by user {st['user_id']}{to}: {str(st.get('task'))[:80]}"))
        end = task_end(m)
        if end:
            events.append((end[0], "person's passkey", f"task #{m['mandate_id']} ended by user {end[1]}"))
    for a in doc.get("approvals") or []:
        if not a.get("signed"):
            events.append((a["decided_at"], "server", f"held call #{a['action_id']}: {a['decision']}"))
            continue
        st = a["signed"].get("statement") or {}
        if st.get("type") != APPROVAL_TYPE or st.get("action_id") != a["action_id"] \
                or st.get("decision") != a["decision"] \
                or any(st.get(k) != a["action"].get(k) for k in APPROVAL_FIELDS) or st.get("agent_id") != aid:
            raise Fail(f"approval {a['approval_id']}: the signed decision is about another call")
        _signed_by_person(a["signed"], "approval", passkey_fps)
        events.append((st["issued_at"], "person's passkey",
                       f"held call #{a['action_id']} {a['action'].get('tool_name')}: {a['decision']} by user "
                       f"{st['user_id']}"))
    rel = doc.get("release")
    if rel:
        st = rel.get("statement") or {}
        if st.get("type") != AGENT_RELEASE_TYPE or st.get("agent_id") != aid or st.get("org_id") != org:
            raise Fail("release: not a signed release of this agent")
        _signed_by_person(rel, "release", passkey_fps)
        events.append((st["issued_at"], "person's passkey",
                       f"released from quarantine (incident #{st.get('incident_id')}) by user {st['user_id']}"))

    # the delegation hops, each signed by the agent that delegated
    for d in doc.get("delegation") or []:
        for h in d.get("hops") or []:
            fp = check_hop(h)
            if fp and agent_fp and h["from_agent_id"] == aid and fp != agent_fp:
                raise Fail(f"delegation hop {h['hop_id']}: signed by {fp}, not the agent key you gave")
        state = d.get("status")
        if d.get("breaker_tripped_at"):
            events.append((d["breaker_tripped_at"], "server", f"chain #{d['chain_id']} halted ({state})"))
    events.sort(key=lambda e: (e[0] or 0))
    return lines, events, gaps, keys


def cmd_incident(args) -> int:
    doc = _load(args.file)
    trust = Trust(args.fingerprint)
    lines, events, gaps, _ = check_incident(doc, trust, args.agent_fingerprint, args.passkey)
    inc, agent, w = doc["incident"], doc["agent"], doc["window"]
    print(f"{'VERIFIED' if not gaps else 'VERIFIED, WITH GAPS'}  incident #{inc['id']} ({inc['incident_type']}, "
          f"{inc.get('severity')}) of agent {agent['id']} \"{agent.get('name')}\"")
    print(f"          window {_when(w['since'])} - {_when(w['until'])}")
    for line in lines:
        print("          " + line)
    print("timeline (who vouches for each line):")
    shown = events if args.list <= 0 else events[: args.list]
    for t, who, text in shown:
        print(f"  {_when(t) if t else '?':<24} {who:<17} {text}")
    if len(shown) < len(events):
        print(f"  ... and {len(events) - len(shown)} more (--list 0 shows all)")
    for g in gaps:
        print("not proven: " + g)
    if not args.agent_fingerprint and agent.get("key_fingerprint"):
        print(f"note: no --agent-fingerprint given - the file says the agent's key is {agent['key_fingerprint']}")
    if not args.passkey:
        print("note: no --passkey given - what people signed verifies, but not that those passkeys are the ones "
              "you trust")
    _note(trust)
    return 1 if gaps and args.require_full else 0


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


# ---------------------------------------------------------------------------
# Publication outside the server (Sigstore Rekor)
# ---------------------------------------------------------------------------

# The public Rekor's key, as Sigstore distributes it (github.com/sigstore/root-signing,
# targets/rekor.pub; valid from 2021-01-12). Its log ID is the SHA-256 of its DER encoding.
SIGSTORE_REKOR_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
"""
SIGSTORE_REKOR_LOG_ID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"


def _p256(pem, label):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        key = serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
    except (ValueError, TypeError) as e:
        raise Fail(f"{label}: not a public key ({e})")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise Fail(f"{label}: an ECDSA P-256 key is expected")
    return key


def _spki(key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _ecdsa_ok(key, sig: bytes, msg: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def rekor_logs(paths=()):
    """{log ID: (name, key)}: the Sigstore log, built in, and each --rekor-key."""
    key = _p256(SIGSTORE_REKOR_KEY, "built-in Sigstore key")
    logs = {hashlib.sha256(_spki(key)).hexdigest(): ("Sigstore Rekor", key)}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                key = _p256(f.read(), f"--rekor-key {path}")
        except OSError as e:
            print(f"cannot read {path}: {e}", file=sys.stderr)
            raise SystemExit(2)
        log_id = hashlib.sha256(_spki(key)).hexdigest()
        logs.setdefault(log_id, (f"Rekor log {log_id[:16]}", key))
    return logs


def rekor_set_payload(entry) -> bytes:
    """What a Rekor v1 signed entry timestamp signs: body, integrated time,
    log ID and index as canonical JSON."""
    return canonical({"body": entry["body"], "integratedTime": entry["integratedTime"],
                      "logID": entry["logID"], "logIndex": entry["logIndex"]})


def check_rekor_set(entry, logs, label="Rekor entry"):
    """The entry's signed entry timestamp verifies with the key of the log it
    names. Returns the log's name, or None when that log is not one you gave."""
    log_id = entry.get("logID")
    if not isinstance(log_id, str) or log_id not in logs:
        return None
    name, key = logs[log_id]
    if not isinstance(entry.get("integratedTime"), int) or not isinstance(entry.get("logIndex"), int) \
            or entry["integratedTime"] <= 0 or entry["logIndex"] < 0:
        raise Fail(f"{label}: no integrated time or index")
    try:
        sig = base64.b64decode(entry["verification"]["signedEntryTimestamp"], validate=True)
    except (KeyError, TypeError, ValueError):
        raise Fail(f"{label}: no signed entry timestamp")
    if not _ecdsa_ok(key, sig, rekor_set_payload(entry)):
        raise Fail(f"{label}: the signed entry timestamp does not verify with the key of {name}")
    return name


def check_rekor_publication(cp, pub, logs, publishing_pins=()):
    """A Rekor publication of this checkpoint: the entry is a hashedrekord of
    the checkpoint's own statement, signed by the publishing key, and the
    log vouches for it. Returns (verified, line)."""
    label = f"Rekor entry of checkpoint {cp.get('tree_size')}"
    try:
        entry = pub["receipt"]["entry"]
        body = json.loads(base64.b64decode(entry["body"], validate=True))
        spec = body["spec"]
        digest = spec["data"]["hash"]
        sig = base64.b64decode(spec["signature"]["content"], validate=True)
        pub_pem = base64.b64decode(spec["signature"]["publicKey"]["content"], validate=True)
    except (KeyError, TypeError, ValueError) as e:
        raise Fail(f"{label}: malformed ({type(e).__name__}: {e})")
    if body.get("kind") != "hashedrekord" or body.get("apiVersion") != "0.0.1":
        raise Fail(f"{label}: not a hashedrekord 0.0.1 entry")
    statement = cp["statement"].encode("utf-8")
    if digest.get("algorithm") != "sha256" or digest.get("value") != hashlib.sha256(statement).hexdigest():
        raise Fail(f"{label}: the entry is for another statement, not this checkpoint")
    key = _p256(pub_pem, f"{label}: publishing key")
    pfp = "SHA256:" + base64.b64encode(hashlib.sha256(_spki(key)).digest()).decode().rstrip("=")
    if not _ecdsa_ok(key, sig, statement):
        raise Fail(f"{label}: the publishing key's signature over the statement does not verify")
    if publishing_pins and pfp not in publishing_pins:
        raise Fail(f"{label}: published with key {pfp}, expected {' or '.join(publishing_pins)}")
    if pub.get("log_index") is not None and pub["log_index"] != entry.get("logIndex"):
        raise Fail(f"{label}: the listed index differs from the entry's")
    name = check_rekor_set(entry, logs, label)
    if name is None:
        return False, (f"not checked  a Rekor entry in log {str(entry.get('logID'))[:16]}..., which is not "
                       "the Sigstore log: pass that log's key with --rekor-key")
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry["integratedTime"]))
    where = (f"https://search.sigstore.dev/?logIndex={entry['logIndex']}" if entry["logID"] == SIGSTORE_REKOR_LOG_ID
             else f"index {entry['logIndex']}")
    return True, (f"published in {name} at {when} ({where}) with publishing key {pfp}: "
                  f"the log had these {cp['tree_size']} records then")


def check_publications(cp, logs, publishing_pins=()):
    """Every Rekor publication the checkpoint carries verifies (or is named
    as unchecked); S3 copies are named. Returns (lines to print, how many
    Rekor entries verified)."""
    lines, verified = [], 0
    for pub in cp.get("publications") or []:
        target = pub.get("target")
        if target == "rekor":
            ok, line = check_rekor_publication(cp, pub, logs, publishing_pins)
            verified += ok
            lines.append(line)
        elif target == "s3":
            lines.append(f"stored in {pub.get('location')} (S3, Object Lock): not checked here - fetch that "
                         "object and run `checkpoint` on it")
        else:
            lines.append(f"not checked  a publication to {target!r}, which this tool does not know")
    return lines, verified


def _require_rekor(cp, lines, verified):
    if not verified:
        raise Fail(f"checkpoint {cp.get('tree_size')} carries no Rekor entry that verifies"
                   + (" (" + "; ".join(lines) + ")" if lines else ""))


def _print_publications(lines):
    for line in lines:
        print("          " + line)


def cmd_checkpoint(args) -> int:
    cp = _load(args.file)
    trust = Trust(args.fingerprint)
    if trust:
        _require_trust(signer_of(cp), {}, trust, "the checkpoint")
    fp = check_checkpoint(cp)
    toks = check_timestamps(cp, args.tsa_ca) if args.tsa_ca else []
    pubs, verified = check_publications(cp, rekor_logs(args.rekor_key), args.publishing_key)
    if args.require_rekor:
        _require_rekor(cp, pubs, verified)
    print(f"VERIFIED  checkpoint of organization {cp['org_id']}: {cp['tree_size']} records, root {cp['root_hash']}")
    print(f"          signed by {fp} ({cp['algorithm']})")
    _print_stamps(cp, toks)
    _print_publications(pubs)
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
    # the older end must have been published (that is what fixes the history);
    # the newer one may not be yet - its publications are checked when present
    # (and the auditor's own copy's, when it carries any)
    logs = rekor_logs(args.rekor_key)
    pubs_old, verified = check_publications(old, logs, args.publishing_key)
    if pinned is not None and pinned.get("publications"):
        mine, n = check_publications(pinned, logs, args.publishing_key)
        pubs_old, verified = pubs_old + [x for x in mine if x not in pubs_old], verified + n
    if args.require_rekor:
        _require_rekor(old, pubs_old, verified)
    pubs_new, _ = check_publications(new, logs, args.publishing_key)
    print(f"VERIFIED  the log of organization {new['org_id']} at {new['tree_size']} records extends "
          f"the one at {old['tree_size']}: nothing in the first {old['tree_size']} was changed or removed")
    print(f"          signed by {fp}" + (f" (key changed from {fp_old})" if fp != fp_old else ""))
    _print_stamps(old, toks_old)
    _print_publications(pubs_old)
    if pubs_new:
        print(f"          the newer checkpoint ({new['tree_size']} records):")
        _print_publications(pubs_new)
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
    c.add_argument("--rekor-key", action="append", default=[],
                   help="PEM of another Rekor log's key whose entries you accept (the Sigstore log's is built in)")
    c.add_argument("--publishing-key", action="append", default=[],
                   help="fingerprint of the organization's publishing key (Audit Log page); repeatable")
    c.add_argument("--require-rekor", action="store_true",
                   help="fail (exit 1) unless the checkpoint carries a Rekor entry that verifies")
    s = sub.add_parser("consistency")
    s.add_argument("file")
    s.add_argument("--pinned")
    s.add_argument("--fingerprint", action="append", default=[])
    s.add_argument("--tsa-ca")
    s.add_argument("--rekor-key", action="append", default=[],
                   help="PEM of another Rekor log's key whose entries you accept (the Sigstore log's is built in)")
    s.add_argument("--publishing-key", action="append", default=[],
                   help="fingerprint of the organization's publishing key (Audit Log page); repeatable")
    s.add_argument("--require-rekor", action="store_true",
                   help="fail (exit 1) unless the older checkpoint carries a Rekor entry that verifies")
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
    au = sub.add_parser("authority")
    au.add_argument("file")
    au.add_argument("--fingerprint", action="append", default=[])
    au.add_argument("--agent-fingerprint")
    au.add_argument("--passkey", action="append", default=[],
                    help="fingerprint of an administrator passkey you trust; one of them must have signed the "
                         "release the action was decided under; repeatable")
    au.add_argument("--require-full", action="store_true",
                    help="fail (exit 1) when a link is not proven, not only when one is broken")
    co = sub.add_parser("completeness")
    co.add_argument("file")
    co.add_argument("--fingerprint", action="append", default=[])
    co.add_argument("--list", type=int, default=20, help="how many of the agent's actions to list (default 20)")
    co.add_argument("--require-full", action="store_true",
                    help="fail (exit 1) when the seals do not cover the whole period asked for")
    ic = sub.add_parser("incident")
    ic.add_argument("file")
    ic.add_argument("--fingerprint", action="append", default=[])
    ic.add_argument("--agent-fingerprint")
    ic.add_argument("--passkey", action="append", default=[],
                    help="fingerprint of a passkey you trust to give tasks, decide and release; repeatable")
    ic.add_argument("--list", type=int, default=100, help="how many timeline lines to print (0: all)")
    ic.add_argument("--require-full", action="store_true",
                    help="fail (exit 1) when anything rests on the server's word, not only when a link is broken")
    t = sub.add_parser("trace")
    t.add_argument("file")
    t.add_argument("--fingerprint", action="append", default=[])
    args = p.parse_args(argv)
    try:
        return {"verify": cmd_verify, "checkpoint": cmd_checkpoint, "consistency": cmd_consistency,
                "receipt": cmd_receipt, "trace": cmd_trace, "release": cmd_release,
                "authority": cmd_authority, "completeness": cmd_completeness,
                "incident": cmd_incident}[args.cmd](args)
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
