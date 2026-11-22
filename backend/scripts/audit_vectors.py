# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Generate sdk/testdata/audit-vectors.json: public test vectors for verifying
Provenza's audit log (docs/audit-proofs.md) - record proofs, checkpoints,
consistency proofs, audit key changes, RFC 3161 time-stamps and Rekor
publications, each with the verdict a verifier must reach and why.

Every document is made with the server's own code (app/core/audit_chain.py,
app/core/agent_signing.py), the way the server makes it, from a small log
of an example organization. Each tampered case changes one thing. Keys and
ML-DSA signatures are random, so the file is generated once and committed;
backend/tests/test_audit_vectors.py checks it with the server's code and with
the standalone tools/provenza_audit.py, and tools/audit_vectors.py runs any
verifier over it. One case is real: a checkpoint published in the public
Sigstore Rekor (sdk/testdata/audit-sigstore-checkpoint.json). From backend/:

    python scripts/audit_vectors.py
"""

import base64
import copy
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.core import audit_chain as ac  # noqa: E402
from app.core import agent_signing as sig  # noqa: E402
from app.core import rfc3161 as r  # noqa: E402
from app.services import audit_publish  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "sdk" / "testdata" / "audit-vectors.json"
SIGSTORE = ROOT / "sdk" / "testdata" / "audit-sigstore-checkpoint.json"
ORG = 42
T0 = datetime(2026, 11, 2, 9, 0, 0, tzinfo=timezone.utc)
PROOF_FORMAT = "provenza.audit.proof/1"
CONSISTENCY_FORMAT = "provenza.audit.consistency/1"

# What the example organization's log records, in order (entity, id, action, metadata)
EVENTS = [
    ("agent", 7, "created", {"name": "refund-agent", "team": "support"}),
    ("policy", 1, "updated", {"level": "organization", "rule": "refund.amount > 100 needs approval"}),
    ("tool_call", 101, "allowed", {"agent_id": 7, "tool": "lookup_order", "order": "A-1001"}),
    ("tool_call", 102, "held", {"agent_id": 7, "tool": "issue_refund", "amount": 240}),
    ("approval", 102, "approved", {"by_user": 3, "tool": "issue_refund"}),
    ("tool_call", 102, "allowed", {"agent_id": 7, "tool": "issue_refund", "amount": 240}),
    ("tool_call", 103, "denied", {"agent_id": 7, "tool": "export_customers", "reason": "not in the agent's tools"}),
]


# ----------------------------------------------------------------------------- keys

class AuditKey:
    """An audit key as the server keeps it: Ed25519, plus ML-DSA-65 for a hybrid key."""

    def __init__(self, hybrid=True):
        self.ed_private, self.public_key = sig.generate_keypair()
        self.pq_seed, self.pq_public_key = sig.generate_pq_keypair() if hybrid else (None, None)
        self.fingerprint = sig.key_fingerprint(self.public_key, self.pq_public_key)
        self.algorithm = sig.scheme_of(self.pq_public_key)

    def sign(self, statement):
        return (sig.sign_payload(statement, self.ed_private),
                sig.sign_payload_pq(statement, self.pq_seed) if self.pq_seed else None)


# ----------------------------------------------------------------------------- the log

def records(events=EVENTS, org=ORG):
    out, prev = [], ac.GENESIS_HASH
    for i, (entity, eid, action, meta) in enumerate(events, start=1):
        payload = ac.record_payload(org_id=org, seq=i, prev_hash=prev, created_at=T0 + timedelta(minutes=i),
                                    actor_user_id=3, entity_type=entity, entity_id=eid, action=action,
                                    metadata=meta)
        h = ac.record_hash(payload)
        out.append({"id": 1000 + i, "payload": payload, "canonical": sig.canonical_text(payload), "record_hash": h})
        prev = h
    return out


def leaves(recs):
    return [bytes.fromhex(x["record_hash"]) for x in recs]


def checkpoint(key, recs, size, minute):
    root = ac.merkle_root(leaves(recs)[:size]).hex()
    issued = T0 + timedelta(minutes=minute)
    st = ac.checkpoint_statement(org_id=ORG, tree_size=size, root_hash=root, issued_at=issued,
                                 key_fingerprint=key.fingerprint, algorithm=key.algorithm)
    s, pq = key.sign(st)
    return {"org_id": ORG, "tree_size": size, "root_hash": root, "issued_at": ac.format_ts(issued),
            "algorithm": key.algorithm, "statement": sig.canonical_text(st), "signature": s, "pq_signature": pq,
            "public_key": key.public_key, "pq_public_key": key.pq_public_key, "key_fingerprint": key.fingerprint}


def proof(recs, index, cp, handovers=()):
    return {"format": PROOF_FORMAT, "record": copy.deepcopy(recs[index]), "leaf_index": index,
            "tree_size": cp["tree_size"],
            "inclusion_path": ac.hexes(ac.inclusion_proof(index, leaves(recs)[:cp["tree_size"]])),
            "checkpoint": copy.deepcopy(cp), "key_handovers": list(handovers)}


def consistency(recs, old, new, handovers=()):
    return {"format": CONSISTENCY_FORMAT, "old": copy.deepcopy(old), "new": copy.deepcopy(new),
            "consistency_path": ac.hexes(ac.consistency_proof(old["tree_size"], leaves(recs)[:new["tree_size"]])),
            "key_handovers": list(handovers)}


def handover(old_key, new_key, recs, size, minute, rotation_id=1):
    root = ac.merkle_root(leaves(recs)[:size]).hex()
    issued = T0 + timedelta(minutes=minute)
    st = ac.handover_statement(org_id=ORG, rotation_id=rotation_id, tree_size=size, root_hash=root,
                               issued_at=issued, proposed_at=issued - timedelta(days=1), quorum=2, approvals=[3, 4],
                               old_key_fingerprint=old_key.fingerprint, old_algorithm=old_key.algorithm,
                               new_key_fingerprint=new_key.fingerprint, new_algorithm=new_key.algorithm)
    os_, opq = old_key.sign(st)
    ns, npq = new_key.sign(st)
    return {"org_id": ORG, "rotation_id": rotation_id, "tree_size": size, "root_hash": root,
            "issued_at": ac.format_ts(issued), "statement": sig.canonical_text(st),
            "old_key_fingerprint": old_key.fingerprint, "old_public_key": old_key.public_key,
            "old_pq_public_key": old_key.pq_public_key, "old_signature": os_, "old_pq_signature": opq,
            "new_key_fingerprint": new_key.fingerprint, "new_public_key": new_key.public_key,
            "new_pq_public_key": new_key.pq_public_key, "new_signature": ns, "new_pq_signature": npq}


# ----------------------------------------------------------------------------- a time-stamp authority

class TestTSA:
    """A TSA for vectors: CA and TSA certificate valid 2026-2036, so the
    committed tokens keep verifying (validity is checked at the token's time)."""

    def __init__(self, name="Provenza test vectors"):
        from tests.tsa_helpers import FakeTSA, _cert
        tsa = FakeTSA()
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        tsa.ca = _cert(f"{name} TSA Root", f"{name} TSA Root", tsa.ca_key, tsa.ca_key, ca=True, start=start, days=3650)
        tsa.cert = _cert(f"{name} TSA", f"{name} TSA Root", tsa.key, tsa.ca_key, start=start, days=3650)
        self.tsa = tsa

    @property
    def ca_pem(self):
        return self.tsa.ca_pem

    def stamp(self, cp, seconds=1):
        when = datetime.fromisoformat(cp["issued_at"].replace("Z", "+00:00")) + timedelta(seconds=seconds)
        token = self.tsa.token(hashlib.sha256(cp["statement"].encode()).digest(), gen_time=when)
        return {"format": "rfc3161", "tsa_url": "https://tsa.example.org", "gen_time": when.isoformat(),
                "serial": str(self.tsa.serial), "tsa_subject": self.tsa.cert.subject.rfc4514_string(),
                "token": base64.b64encode(token).decode(), "imprint": "sha256(statement)"}


# ----------------------------------------------------------------------------- a Rekor log

class TestRekor:
    """A Rekor v1 log key and an organization's publishing key (ECDSA P-256)."""

    def __init__(self):
        self.log = ec.generate_private_key(ec.SECP256R1())
        self.publisher = ec.generate_private_key(ec.SECP256R1())

    @staticmethod
    def _pem(key):
        return key.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    @property
    def log_pem(self):
        return self._pem(self.log)

    @property
    def publisher_fingerprint(self):
        return audit_publish.fingerprint(self._pem(self.publisher))

    def publish(self, cp, *, index=7, delay=60, statement=None):
        statement = statement or cp["statement"]
        sent = audit_publish.rekor_entry(statement, self.publisher.sign(statement.encode(), ec.ECDSA(hashes.SHA256())),
                                         self._pem(self.publisher))
        der = self.log.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        issued = datetime.fromisoformat(cp["issued_at"].replace("Z", "+00:00"))
        entry = {"body": base64.b64encode(json.dumps(sent, separators=(",", ":")).encode()).decode(),
                 "integratedTime": int(issued.timestamp()) + delay, "logID": hashlib.sha256(der).hexdigest(),
                 "logIndex": index}
        entry["verification"] = {"signedEntryTimestamp": base64.b64encode(
            self.log.sign(audit_publish.set_payload(entry), ec.ECDSA(hashes.SHA256()))).decode()}
        uuid = hashlib.sha256(json.dumps(sent).encode()).hexdigest()
        self.published = getattr(self, "published", 0) + 1
        return {"id": self.published, "checkpoint_id": 100 + cp["tree_size"], "tree_size": cp["tree_size"],
                "target": "rekor", "destination": "https://rekor.example.org", "reference": uuid,
                "location": f"https://rekor.example.org/api/v1/log/entries/{uuid}", "log_index": index,
                "published_at": datetime.fromtimestamp(entry["integratedTime"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "receipt": {"format": "provenza.audit.publication/1", "target": "rekor", "host": "rekor.example.org",
                            "uuid": uuid, "entry": entry, "sent": sent}}


# ----------------------------------------------------------------------------- the cases

def _b64_flip(value):
    raw = bytearray(base64.b64decode(value))
    raw[len(raw) // 2] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def _hex_flip(value):
    return value[:-1] + ("0" if value[-1] != "0" else "1")


def _entry_body(pub):
    return json.loads(base64.b64decode(pub["receipt"]["entry"]["body"]))


def _set_entry_body(pub, body):
    pub["receipt"]["entry"]["body"] = base64.b64encode(json.dumps(body, separators=(",", ":")).encode()).decode()


def build():
    A, B, C, K = AuditKey(), AuditKey(), AuditKey(), AuditKey(hybrid=False)
    tsa, other_tsa, rekor, other_log = TestTSA(), TestTSA("Another"), TestRekor(), TestRekor()
    recs = records()
    cp3, cp7 = checkpoint(A, recs, 3, 20), checkpoint(A, recs, 7, 30)
    cases = []

    def case(name, command, document, expect, why, reason=None, **args):
        cases.append({"name": name, "command": command, "args": args, "expect": expect, "why": why,
                      **({"reason": reason} if reason else {}), "document": document})

    def tampered(doc, change):
        d = copy.deepcopy(doc)
        change(d)
        return d

    ok, bad = "verified", "not_verified"
    pin_a = {"fingerprint": [A.fingerprint]}

    # --- a record is in the log (verify) -------------------------------------
    p = proof(recs, 3, cp7)
    case("proof/valid", "verify", p, ok, "record 4 of 7 is in the log signed by key A (hybrid)", **pin_a)
    case("proof/valid-first-record", "verify", proof(recs, 0, cp7), ok, "the first record (leftmost leaf)", **pin_a)
    case("proof/valid-last-record", "verify", proof(recs, 6, cp7), ok,
         "the last record of an odd-sized tree (a leaf promoted without a sibling)", **pin_a)
    case("proof/valid-classic-key", "verify", proof(recs, 3, checkpoint(K, recs, 7, 30)), ok,
         "an Ed25519-only audit key (algorithm ed25519)", fingerprint=[K.fingerprint])
    case("proof/record-altered", "verify", tampered(p, lambda d: (
        d["record"]["payload"]["metadata"].update(amount=24),
        d["record"].update(canonical=sig.canonical_text(d["record"]["payload"])))), bad,
         "the record's content changed, its record_hash did not", "does not hash to", **pin_a)
    case("proof/record-rehashed", "verify", tampered(p, lambda d: (
        d["record"]["payload"]["metadata"].update(amount=24),
        d["record"].update(canonical=sig.canonical_text(d["record"]["payload"]),
                           record_hash=ac.record_hash(d["record"]["payload"])))), bad,
         "the record changed and was re-hashed: it is no longer the leaf the signed root covers",
         "not in that log", **pin_a)
    case("proof/path-altered", "verify", tampered(p, lambda d: d["inclusion_path"].__setitem__(
        0, _hex_flip(d["inclusion_path"][0]))), bad, "one hash of the inclusion path changed", "not in that log",
         **pin_a)
    case("proof/wrong-index", "verify", tampered(p, lambda d: d.update(leaf_index=2)), bad,
         "the record placed at another position of the tree", "leaf_index", **pin_a)
    case("proof/signature-altered", "verify", tampered(p, lambda d: d["checkpoint"].update(
        signature=_b64_flip(d["checkpoint"]["signature"]))), bad, "the checkpoint's Ed25519 signature changed",
         "signature", **pin_a)
    case("proof/pq-signature-altered", "verify", tampered(p, lambda d: d["checkpoint"].update(
        pq_signature=_b64_flip(d["checkpoint"]["pq_signature"]))), bad,
         "a hybrid key: Ed25519 still verifies but ML-DSA-65 does not - both are required", "ML-DSA", **pin_a)
    case("proof/pq-signature-removed", "verify", tampered(p, lambda d: d["checkpoint"].update(pq_signature=None)),
         bad, "a hybrid key with its ML-DSA-65 signature removed (a downgrade)", "ML-DSA", **pin_a)
    case("proof/pq-key-removed", "verify", tampered(p, lambda d: d["checkpoint"].update(
        pq_signature=None, pq_public_key=None)), bad,
         "the ML-DSA-65 key removed to pass as Ed25519-only: the signed fingerprint names both keys",
         "signed fingerprint does not match")
    case("proof/untrusted-key", "verify", p, bad, "valid, but signed by key A while you trust only key B",
         "which you do not trust", fingerprint=[B.fingerprint])

    # --- one checkpoint ------------------------------------------------------
    case("checkpoint/valid", "checkpoint", cp7, ok, "a checkpoint of 7 records signed by key A", **pin_a)
    case("checkpoint/field-altered", "checkpoint", tampered(cp7, lambda d: d.update(tree_size=6)), bad,
         "tree_size changed outside the signed statement", "differs from the signed statement", **pin_a)

    def restate(d, **change):
        st = json.loads(d["statement"])
        st.update(change)
        d["statement"] = sig.canonical_text(st)
        d.update({k: v for k, v in change.items() if k in d})
    case("checkpoint/statement-altered", "checkpoint", tampered(cp7, lambda d: restate(d, tree_size=6)), bad,
         "the statement and the field changed together: the signature no longer matches", "signature", **pin_a)
    case("checkpoint/statement-not-canonical", "checkpoint", tampered(cp7, lambda d: d.update(
        statement=json.dumps(json.loads(d["statement"]), sort_keys=True, indent=1))), bad,
         "the same statement, not in canonical form (sorted keys, no spaces)", "canonical", **pin_a)

    # --- time-stamps (--tsa-ca) ---------------------------------------------
    stamped = {**cp7, "timestamps": [tsa.stamp(cp7)]}
    case("timestamp/valid", "checkpoint", stamped, ok, "an RFC 3161 time-stamp of the statement by the test TSA",
         tsa_ca=tsa.ca_pem, **pin_a)
    case("timestamp/other-tsa", "checkpoint", stamped, bad, "the token does not chain to the TSA you trust",
         "untrusted", tsa_ca=other_tsa.ca_pem, **pin_a)
    case("timestamp/other-statement", "checkpoint", {**cp7, "timestamps": [tsa.stamp(cp3)]}, bad,
         "a valid token, but for another checkpoint's statement", "imprint", tsa_ca=tsa.ca_pem, **pin_a)
    case("timestamp/missing", "checkpoint", {**cp7, "timestamps": []}, bad,
         "a time-stamp is required (--tsa-ca) and there is none", "no time-stamp", tsa_ca=tsa.ca_pem, **pin_a)

    # --- the log extends an older checkpoint (consistency) -------------------
    cons = consistency(recs, cp3, cp7)
    case("consistency/valid", "consistency", cons, ok, "the log of 7 records extends the one of 3", **pin_a)
    case("consistency/valid-pinned", "consistency", cons, ok,
         "the older checkpoint is the one you saved earlier (--pinned)", pinned=cp3)
    case("consistency/path-altered", "consistency", tampered(cons, lambda d: d["consistency_path"].__setitem__(
        0, _hex_flip(d["consistency_path"][0]))), bad, "one hash of the consistency path changed", "rewritten",
         **pin_a)
    rewritten = copy.deepcopy(recs)
    events = [list(e) for e in EVENTS]
    events[1][3] = {"level": "organization", "rule": "refund.amount > 10000 needs approval"}
    rewritten = records([tuple(e) for e in events])
    cp7_rewritten = checkpoint(A, rewritten, 7, 30)
    case("consistency/history-rewritten", "consistency", consistency(rewritten, cp3, cp7_rewritten), bad,
         "record 2 was rewritten and everything after it re-hashed and re-signed with the real key: the new log "
         "no longer extends the checkpoint taken before", "rewritten", **pin_a)
    case("consistency/not-the-pinned-one", "consistency", consistency(rewritten, checkpoint(A, rewritten, 3, 20),
                                                                       cp7_rewritten), bad,
         "the server shows a rewritten older checkpoint too; yours (--pinned) has another root",
         "not the pinned one", pinned=cp3)

    # --- the audit key changed (key handovers) -------------------------------
    hand = handover(A, B, recs, 5, 25)
    cp7_b = checkpoint(B, recs, 7, 30)
    rot = consistency(recs, cp3, cp7_b, [hand])
    case("rotation/valid", "consistency", rot, ok,
         "key A handed over to key B at 5 records (both signed the handover); B is confirmed independently",
         fingerprint=[A.fingerprint, B.fingerprint])
    case("rotation/new-key-not-confirmed", "consistency", rot, bad,
         "a valid handover, but you have not confirmed key B's fingerprint yourself", "have not confirmed",
         **pin_a)
    case("rotation/no-handover", "consistency", tampered(rot, lambda d: d.update(key_handovers=[])), bad,
         "the newer checkpoint is signed by another key and nothing links the two", "no valid handover",
         fingerprint=[A.fingerprint, B.fingerprint])
    case("rotation/old-key-did-not-consent", "consistency", tampered(rot, lambda d: d["key_handovers"][0].update(
        old_signature=_b64_flip(d["key_handovers"][0]["old_signature"]))), bad,
         "the old key's signature on the handover does not verify", "old key's consent",
         fingerprint=[A.fingerprint, B.fingerprint])
    case("rotation/fork", "consistency", tampered(rot, lambda d: d["key_handovers"].append(
        handover(A, C, recs, 6, 27, rotation_id=2))), bad,
         "key A was handed over twice (to B and to C): whoever held A signed a second successor",
         "handed over twice", fingerprint=[A.fingerprint, B.fingerprint])
    case("rotation/handover-outside-range", "consistency", consistency(
        recs, cp3, cp7_b, [handover(A, B, recs, 2, 15)]), bad,
         "the handover is dated before the older checkpoint, so it cannot link the two", "not between",
         fingerprint=[A.fingerprint, B.fingerprint])

    # --- published in a Rekor log (--require-rekor) --------------------------
    published = {**cp7, "publications": [rekor.publish(cp7)]}
    rk = {"rekor_key": rekor.log_pem, "require_rekor": True}
    case("rekor/valid", "checkpoint", published, ok,
         "a Rekor entry for this checkpoint's statement, signed by the publishing key, with a valid signed "
         "entry timestamp of the test log", publishing_key=[rekor.publisher_fingerprint], **rk, **pin_a)
    case("rekor/time-altered", "checkpoint", tampered(published, lambda d: d["publications"][0]["receipt"]["entry"]
                                                       .update(integratedTime=d["publications"][0]["receipt"]
                                                               ["entry"]["integratedTime"] - 86400)), bad,
         "the log's time moved back a day: the signed entry timestamp no longer verifies",
         "signed entry timestamp", **rk, **pin_a)
    case("rekor/index-altered", "checkpoint", tampered(published, lambda d: (
        d["publications"][0]["receipt"]["entry"].update(logIndex=8), d["publications"][0].update(log_index=8))), bad,
         "the entry's index changed", "signed entry timestamp", **rk, **pin_a)
    case("rekor/other-statement", "checkpoint", {**cp7, "publications": [rekor.publish(cp3)]}, bad,
         "a valid entry, but for another checkpoint's statement", "another statement", **rk, **pin_a)
    other_signer = copy.deepcopy(published)

    def forge(d):
        pub = d["publications"][0]
        body = _entry_body(pub)
        body["spec"]["signature"]["content"] = base64.b64encode(rekor.log.sign(
            cp7["statement"].encode(), ec.ECDSA(hashes.SHA256()))).decode()   # not the publishing key
        _set_entry_body(pub, body)
    forge(other_signer)
    case("rekor/signature-not-by-publishing-key", "checkpoint", other_signer, bad,
         "the entry's signature over the statement is not the publishing key's", "publishing key's signature",
         **rk, **pin_a)
    case("rekor/other-publishing-key", "checkpoint", published, bad,
         "published, but with a key other than the one you pinned (--publishing-key)", "expected",
         publishing_key=[other_log.publisher_fingerprint], **rk, **pin_a)
    case("rekor/unknown-log", "checkpoint", published, bad,
         "an entry of a log whose key you did not give: not checked, so not enough when one is required",
         "no Rekor entry that verifies", require_rekor=True, **pin_a)
    case("rekor/missing", "checkpoint", {**cp7, "publications": []}, bad,
         "a publication is required and the checkpoint has none", "no Rekor entry that verifies", **rk, **pin_a)

    # --- a real one: published in the public Sigstore Rekor ------------------
    real = json.loads(SIGSTORE.read_text(encoding="utf-8"))
    case("sigstore/valid", "checkpoint", real, ok,
         "a real checkpoint of Provenza's own server (stickstock.lol), published in rekor.sigstore.dev; "
         "the log's key is the one Sigstore distributes, built into the verifier", require_rekor=True,
         fingerprint=[real["key_fingerprint"]],
         publishing_key=[audit_publish.fingerprint(base64.b64decode(
             _entry_body(real["publications"][0])["spec"]["signature"]["publicKey"]["content"]).decode())])
    case("sigstore/time-altered", "checkpoint", tampered(real, lambda d: d["publications"][0]["receipt"]["entry"]
                                                          .update(integratedTime=d["publications"][0]["receipt"]
                                                                  ["entry"]["integratedTime"] - 86400)), bad,
         "the real entry with its time moved back a day", "signed entry timestamp", require_rekor=True,
         fingerprint=[real["key_fingerprint"]])
    case("sigstore/tree-size-altered", "checkpoint", tampered(real, lambda d: d.update(tree_size=262)), bad,
         "the real checkpoint claiming one record more", "differs from the signed statement", require_rekor=True,
         fingerprint=[real["key_fingerprint"]])

    return {
        "comment": "generated by backend/scripts/audit_vectors.py; checked by backend/tests/test_audit_vectors.py; "
                   "run with tools/audit_vectors.py - keys are random, the file is made once",
        "format": "provenza.audit.vectors/1",
        "keys": {"A": A.fingerprint, "B": B.fingerprint, "C": C.fingerprint, "classic": K.fingerprint,
                 "rekor_log": rekor.log_pem, "publishing_key": rekor.publisher_fingerprint, "tsa_ca": tsa.ca_pem},
        "cases": cases,
    }


def main():
    OUT.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
