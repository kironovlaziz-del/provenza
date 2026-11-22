# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
sdk/testdata/audit-vectors.json (scripts/audit_vectors.py): the public test
vectors for verifying the audit log. Every case reaches its verdict, for its
reason, in the standalone tools/provenza_audit.py (through tools/audit_vectors.py,
the runner others use); the server's own code agrees on what is intact; and
the generator still makes the same set of cases.
"""

import base64
import hashlib
import importlib.util
import json
from datetime import datetime
from pathlib import Path

import pytest

from app.core import audit_chain as ac
from app.core import rfc3161
from app.core.agent_signing import canonical_text
from app.models.audit_log import AuditCheckpoint, AuditKeyHandover
from app.services import audit_proofs, audit_publish

ROOT = Path(__file__).resolve().parents[2]
V = json.loads((ROOT / "sdk" / "testdata" / "audit-vectors.json").read_text(encoding="utf-8"))
CASES = {c["name"]: c for c in V["cases"]}


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


runner = _load("audit_vectors_runner", ROOT / "tools" / "audit_vectors.py")
generator = _load("audit_vectors_generator", ROOT / "backend" / "scripts" / "audit_vectors.py")
TOOL = runner._tool()

# Cases that fail because of what the verifier is asked to trust or require
# (a pin, a TSA, a log key, a publication) - the documents themselves are intact.
BY_OPTIONS = {
    "proof/untrusted-key", "timestamp/other-tsa", "timestamp/missing", "consistency/not-the-pinned-one",
    "rotation/new-key-not-confirmed", "rotation/no-handover", "rotation/fork", "rotation/handover-outside-range",
    "rekor/other-publishing-key", "rekor/unknown-log", "rekor/missing",
}


@pytest.mark.parametrize("name", list(CASES))
def test_the_offline_verifier_reaches_each_verdict(name):
    case = CASES[name]
    got, out = runner.run_case(case, tool=TOOL)
    assert got == case["expect"], out
    if case["expect"] == "not_verified":
        assert case.get("reason"), f"{name}: a failing case names its reason"
        assert case["reason"] in out, out


def test_the_runner_reports_every_case():
    assert runner.main([str(ROOT / "sdk" / "testdata" / "audit-vectors.json")]) == 0
    assert len(CASES) == len(V["cases"]), "case names are unique"
    assert {c["command"] for c in V["cases"]} == {"verify", "checkpoint", "consistency"}
    assert sum(c["expect"] == "verified" for c in V["cases"]) >= 10


# ----------------------------------------------------------------------------- the server agrees

def _ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _checkpoint_ok(cp) -> bool:
    row = AuditCheckpoint(org_id=cp["org_id"], tree_size=cp["tree_size"], root_hash=cp["root_hash"],
                          issued_at=_ts(cp["issued_at"]), statement=cp["statement"], algorithm=cp["algorithm"],
                          signature=cp["signature"], pq_signature=cp.get("pq_signature"),
                          public_key=cp["public_key"], pq_public_key=cp.get("pq_public_key"),
                          key_fingerprint=cp["key_fingerprint"])
    return audit_proofs.checkpoint_valid(row)


def _handover_ok(h) -> bool:
    row = AuditKeyHandover(org_id=h["org_id"], rotation_id=h["rotation_id"], tree_size=h["tree_size"],
                           root_hash=h["root_hash"], issued_at=_ts(h["issued_at"]), statement=h["statement"],
                           old_fingerprint=h["old_key_fingerprint"], new_fingerprint=h["new_key_fingerprint"],
                           old_public_key=h["old_public_key"], old_pq_public_key=h.get("old_pq_public_key"),
                           new_public_key=h["new_public_key"], new_pq_public_key=h.get("new_pq_public_key"),
                           old_signature=h["old_signature"], old_pq_signature=h.get("old_pq_signature"),
                           new_signature=h["new_signature"], new_pq_signature=h.get("new_pq_signature"))
    return audit_proofs.handover_valid(row)


def _stamps_ok(cp) -> bool:
    anchors = rfc3161.load_anchors(V["keys"]["tsa_ca"])
    digest = hashlib.sha256(cp["statement"].encode()).digest()
    try:
        for st in cp.get("timestamps") or []:
            rfc3161.verify_token(base64.b64decode(st["token"]), digest, anchors)
    except rfc3161.TimestampError:
        return False
    return True


def _publications_ok(cp, log_pem) -> bool:
    for pub in cp.get("publications") or []:
        entry = pub["receipt"]["entry"]
        body = json.loads(base64.b64decode(entry["body"]))
        pem = audit_publish.SIGSTORE_REKOR_PUBLIC_KEY if entry["logID"] == audit_publish.SIGSTORE_REKOR_LOG_ID \
            else log_pem
        if body["spec"]["data"]["hash"]["value"] != hashlib.sha256(cp["statement"].encode()).hexdigest():
            return False
        key = audit_publish._load_ec_public(base64.b64decode(body["spec"]["signature"]["publicKey"]["content"])
                                            .decode())
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            key.verify(base64.b64decode(body["spec"]["signature"]["content"]), cp["statement"].encode(),
                       ec.ECDSA(hashes.SHA256()))
            audit_publish.verify_rekor_answer({pub["reference"]: entry}, body, pem)
        except Exception:  # noqa: BLE001 - not intact
            return False
    return True


def server_intact(case) -> bool:
    """What the server's own code says about the documents, regardless of whom you trust."""
    doc, log_pem = case["document"], V["keys"]["rekor_log"]
    if case["command"] == "checkpoint":
        return _checkpoint_ok(doc) and _stamps_ok(doc) and _publications_ok(doc, log_pem)
    if case["command"] == "verify":
        rec, cp = doc["record"], doc["checkpoint"]
        if canonical_text(rec["payload"]) != rec["canonical"] or ac.record_hash(rec["payload"]) != rec["record_hash"]:
            return False
        if doc["leaf_index"] != rec["payload"]["seq"] - 1:
            return False
        path = [bytes.fromhex(x) for x in doc["inclusion_path"]]
        return _checkpoint_ok(cp) and ac.verify_inclusion(doc["leaf_index"], cp["tree_size"],
                                                          bytes.fromhex(rec["record_hash"]), path,
                                                          bytes.fromhex(cp["root_hash"]))
    old, new = doc["old"], doc["new"]
    path = [bytes.fromhex(x) for x in doc["consistency_path"]]
    return (_checkpoint_ok(old) and _checkpoint_ok(new) and all(_handover_ok(h) for h in doc["key_handovers"])
            and ac.verify_consistency(old["tree_size"], new["tree_size"], bytes.fromhex(old["root_hash"]),
                                      bytes.fromhex(new["root_hash"]), path))


@pytest.mark.parametrize("name", list(CASES))
def test_the_server_agrees_on_what_is_intact(name):
    case = CASES[name]
    expected = case["expect"] == "verified" or name in BY_OPTIONS
    assert server_intact(case) is expected


def test_the_real_entry_is_from_the_public_sigstore_log():
    real = CASES["sigstore/valid"]["document"]
    entry = real["publications"][0]["receipt"]["entry"]
    assert entry["logID"] == audit_publish.SIGSTORE_REKOR_LOG_ID
    assert "rekor_key" not in CASES["sigstore/valid"]["args"]          # the built-in key, nothing given


def test_the_generator_still_makes_these_cases():
    fresh = generator.build()
    assert [(c["name"], c["command"], c["expect"], c.get("reason")) for c in fresh["cases"]] == \
           [(c["name"], c["command"], c["expect"], c.get("reason")) for c in V["cases"]]
    assert runner.check(fresh) == []
