# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Tamper-evident audit log (docs/audit-proofs.md):

  - every record is chained to the one before it (seq, prev_hash, record_hash);
  - the database refuses UPDATE / DELETE / TRUNCATE on the log and its
    checkpoints, except DELETE in a transaction that sets provenza.allow_purge;
  - signed checkpoints, inclusion and consistency proofs verify with the
    standalone tools/provenza_audit.py, and fail once anything is changed;
  - a full verification finds altered records and missing ones.
"""

import copy
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core import agent_signing
from app.core import audit_chain as ac
from app.models.audit_log import AIAuditLog, AuditCheckpoint
from app.services import audit_proofs
from app.services.audit_service import AuditService
from tests.conftest import auth_headers

A = "/api/v1/audit-logs"
ROOT = Path(__file__).resolve().parents[2]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = _load("provenza_audit_tool", ROOT / "tools" / "provenza_audit.py")


async def _write(db, org_id, n, start=0, actor=None):
    out = []
    for i in range(start, start + n):
        out.append(await AuditService(db).log(org_id, actor, "policy", i, "updated", {"n": i}))
    return out


async def _rows(db, org_id):
    return list((await db.execute(
        select(AIAuditLog).where(AIAuditLog.org_id == org_id).order_by(AIAuditLog.seq))).scalars())


# --- chain --------------------------------------------------------------------

async def test_records_form_a_hash_chain(db_session, org_and_users):
    org_id = org_and_users["org"].id
    await _write(db_session, org_id, 4)
    rows = await _rows(db_session, org_id)
    assert [r.seq for r in rows] == list(range(1, len(rows) + 1))
    prev = ac.GENESIS_HASH
    for r in rows:
        assert r.prev_hash == prev
        assert r.record_hash == ac.record_hash(ac.payload_of(r))
        prev = r.record_hash


async def test_hash_survives_the_database_round_trip(db_session, org_and_users):
    """What is hashed before the insert is what is read back later."""
    org_id = org_and_users["org"].id
    meta = {"score": 7.0, "big": 1e20, "f": 0.25, "when": datetime(2026, 1, 2, tzinfo=timezone.utc),
            "nan": float("nan"), "nul": "a\x00b", 3: "int key", "nested": [{"x": 2.0}], "uni": "Тошкент"}
    entry = await AuditService(db_session).log(org_id, None, "policy", 1, "created", meta)
    entry_id = entry.id
    db_session.expire_all()
    row = (await db_session.execute(select(AIAuditLog).where(AIAuditLog.id == entry_id))).scalar_one()
    assert row.metadata_json["score"] == 7 and isinstance(row.metadata_json["score"], int)
    assert row.metadata_json["nan"] == "nan" and row.metadata_json["3"] == "int key"
    assert ac.record_hash(ac.payload_of(row)) == row.record_hash


async def test_organizations_have_separate_chains(db_session, org_and_users):
    from tests.conftest import _create_org_with_admin_and_approver

    other = await _create_org_with_admin_and_approver(
        db_session, org_slug="other-org", admin_email="a@other.example.com", approver_email="b@other.example.com")
    org_id = org_and_users["org"].id
    await _write(db_session, org_id, 2)
    await _write(db_session, other["org"].id, 1)
    first_other = (await _rows(db_session, other["org"].id))[0]
    assert first_other.seq == 1 and first_other.prev_hash == ac.GENESIS_HASH


def test_migration_hashes_like_the_application():
    mig = _load("audit_migration", ROOT / "backend" / "alembic" / "versions" / "d5e8a1c3f7b2_tamper_evident_audit.py")
    when = datetime(2026, 5, 6, 7, 8, 9, 123456, tzinfo=timezone.utc)
    meta = {"b": [1, 2.5, None], "a": "Ünïcode", "z": {"y": True}}
    for actor, eid in ((None, None), (5, 9)):
        payload = ac.record_payload(org_id=3, seq=12, prev_hash="ab" * 32, created_at=when, actor_user_id=actor,
                                    entity_type="agent", entity_id=eid, action="registered", metadata=meta)
        assert mig.record_hash_v1(3, 12, "ab" * 32, when, actor, "agent", eid, "registered", meta) == \
            ac.record_hash(payload)


# --- append-only ----------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "UPDATE ai_audit_logs SET action = 'nothing' WHERE id = :id",
    "DELETE FROM ai_audit_logs WHERE id = :id",
    "TRUNCATE ai_audit_logs",
])
async def test_the_database_refuses_to_change_the_log(db_session, org_and_users, sql):
    entry = (await _write(db_session, org_and_users["org"].id, 1))[0]
    with pytest.raises(DBAPIError, match="append-only"):
        async with db_session.begin_nested():
            await db_session.execute(text(sql), {"id": entry.id} if ":id" in sql else {})


async def test_checkpoints_are_append_only_too(db_session, org_and_users):
    org_id = org_and_users["org"].id
    await _write(db_session, org_id, 2)
    cp = await audit_proofs.checkpoint(db_session, org_id)
    with pytest.raises(DBAPIError, match="append-only"):
        async with db_session.begin_nested():
            await db_session.execute(text("UPDATE audit_checkpoints SET root_hash = :h WHERE id = :id"),
                                     {"h": "00" * 32, "id": cp.id})


async def test_purge_allows_delete_but_never_update(db_session, org_and_users):
    entry = (await _write(db_session, org_and_users["org"].id, 1))[0]
    async with db_session.begin_nested():
        await db_session.execute(text("SELECT set_config('provenza.allow_purge', 'on', true)"))
        with pytest.raises(DBAPIError, match="append-only"):
            async with db_session.begin_nested():
                await db_session.execute(text("UPDATE ai_audit_logs SET action = 'x' WHERE id = :id"),
                                         {"id": entry.id})
        await db_session.execute(text("DELETE FROM ai_audit_logs WHERE id = :id"), {"id": entry.id})
        await db_session.execute(text("SELECT set_config('provenza.allow_purge', 'off', true)"))


# --- Merkle tree -----------------------------------------------------------------

def _naive_root(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return ac.leaf_hash(leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return ac.node_hash(_naive_root(leaves[:k]), _naive_root(leaves[k:]))


def test_merkle_proofs_match_rfc_9162_and_the_offline_tool():
    for n in range(1, 40):
        leaves = [hashlib.sha256(str(i).encode()).digest() for i in range(n)]
        root = ac.merkle_root(leaves)
        assert root == _naive_root(leaves)
        for i in range(n):
            path = ac.inclusion_proof(i, leaves)
            assert ac.verify_inclusion(i, n, leaves[i], path, root)
            assert tool.inclusion_ok(i, n, leaves[i], path, root)
            assert not tool.inclusion_ok(i, n, b"\x01" * 32, path, root)
        for m in range(1, n + 1):
            path = ac.consistency_proof(m, leaves)
            old_root = _naive_root(leaves[:m])
            assert ac.verify_consistency(m, n, old_root, root, path)
            assert tool.consistency_ok(m, n, old_root, root, path)
            if m < n:
                forged = [b"\x02" * 32] + list(leaves[1:m])
                assert not tool.consistency_ok(m, n, _naive_root(forged), root, path)


# --- checkpoints and proofs ---------------------------------------------------------

async def test_checkpoint_is_signed_and_verifies_offline(db_session, org_and_users):
    org_id = org_and_users["org"].id
    await _write(db_session, org_id, 3)
    cp = await audit_proofs.checkpoint(db_session, org_id)
    assert cp.tree_size == len(await _rows(db_session, org_id))
    assert cp.algorithm == agent_signing.scheme_of(cp.pq_public_key)
    if agent_signing.pq_available():
        assert cp.pq_public_key and cp.pq_signature
    out = audit_proofs.checkpoint_out(cp)
    assert tool.check_checkpoint(out) == cp.key_fingerprint
    assert audit_proofs.checkpoint_valid(cp)
    # nothing new: no second checkpoint
    again = await audit_proofs.checkpoint(db_session, org_id)
    assert again.id == cp.id

    forged = dict(out, root_hash="00" * 32)
    with pytest.raises(tool.Fail):
        tool.check_checkpoint(forged)
    with pytest.raises(tool.Fail, match="expected"):
        tool.check_checkpoint(out, pin="SHA256:someone-else")


async def test_proof_endpoint_and_offline_verification(client, db_session, org_and_users, admin_token):
    org_id = org_and_users["org"].id
    entries = await _write(db_session, org_id, 5)
    r = await client.get(f"{A}/{entries[2].id}/proof", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    proof = r.json()
    assert proof["record"]["record_hash"] == entries[2].record_hash
    payload, cp, fp = tool.check_proof(proof)
    assert payload["seq"] == entries[2].seq and fp == cp["key_fingerprint"]
    assert tool.check_proof(json.loads(json.dumps(proof)), pin=fp)

    altered = copy.deepcopy(proof)
    altered["record"]["canonical"] = altered["record"]["canonical"].replace('"updated"', '"deleted"')
    altered["record"]["payload"]["action"] = "deleted"
    with pytest.raises(tool.Fail, match="altered"):
        tool.check_proof(altered)

    rehashed = copy.deepcopy(altered)  # the attacker also recomputes the record hash
    rehashed["record"]["record_hash"] = hashlib.sha256(rehashed["record"]["canonical"].encode()).hexdigest()
    with pytest.raises(tool.Fail, match="not in that log"):
        tool.check_proof(rehashed)


async def test_proof_of_another_organizations_record_is_404(client, db_session, org_and_users, admin_token):
    from tests.conftest import _create_org_with_admin_and_approver

    other = await _create_org_with_admin_and_approver(
        db_session, org_slug="other-org", admin_email="a@other.example.com", approver_email="b@other.example.com")
    entry = (await _write(db_session, other["org"].id, 1))[0]
    r = await client.get(f"{A}/{entry.id}/proof", headers=auth_headers(admin_token))
    assert r.status_code == 404


async def test_consistency_between_checkpoints(client, db_session, org_and_users, admin_token):
    h = auth_headers(admin_token)
    org_id = org_and_users["org"].id
    await _write(db_session, org_id, 3)
    old = (await client.post(f"{A}/checkpoints", headers=h)).json()
    await _write(db_session, org_id, 4, start=3)
    new = (await client.post(f"{A}/checkpoints", headers=h)).json()
    assert new["tree_size"] > old["tree_size"]

    r = await client.get(f"{A}/consistency", params={"from_size": old["tree_size"]}, headers=h)
    assert r.status_code == 200, r.text
    doc = r.json()
    tool.check_consistency(doc, pinned=old)

    forged_old = dict(old, root_hash="11" * 32)
    with pytest.raises(tool.Fail):
        tool.check_consistency(doc, pinned=forged_old)

    r = await client.get(f"{A}/consistency", params={"from_size": 999999}, headers=h)
    assert r.status_code == 404

    integ = (await client.get(f"{A}/integrity", headers=h)).json()
    assert integ["checkpoint"]["tree_size"] == new["tree_size"]
    cps = (await client.get(f"{A}/checkpoints", headers=h)).json()
    assert [c["tree_size"] for c in cps][:2] == [new["tree_size"], old["tree_size"]]


# --- full verification -----------------------------------------------------------------

async def test_verify_reports_a_clean_log(client, db_session, org_and_users, admin_token):
    org_id = org_and_users["org"].id
    await _write(db_session, org_id, 3)
    await audit_proofs.checkpoint(db_session, org_id)
    r = await client.post(f"{A}/verify", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["ok"] is True and rep["problem_count"] == 0
    assert rep["checkpoint_roots_checked"] >= 1 and rep["checkpoint_signatures_checked"] >= 1


async def test_verify_is_admin_only(client, approver_token):
    r = await client.post(f"{A}/verify", headers=auth_headers(approver_token))
    assert r.status_code == 403


async def test_verify_finds_an_altered_record(db_session, org_and_users):
    """Someone who owns the table can switch the trigger off - the chain still tells."""
    org_id = org_and_users["org"].id
    entries = await _write(db_session, org_id, 4)
    await audit_proofs.checkpoint(db_session, org_id)
    await db_session.execute(text("ALTER TABLE ai_audit_logs DISABLE TRIGGER ai_audit_logs_append_only"))
    await db_session.execute(text("UPDATE ai_audit_logs SET action = 'approved' WHERE id = :id"),
                             {"id": entries[1].id})
    await db_session.execute(text("ALTER TABLE ai_audit_logs ENABLE TRIGGER ai_audit_logs_append_only"))
    rep = await audit_proofs.verify_chain(db_session, org_id)
    assert rep["ok"] is False
    assert {"kind": "record_altered", "seq": entries[1].seq, "id": entries[1].id} in rep["problems"]


async def test_verify_finds_a_removed_record_and_proofs_refuse(db_session, org_and_users):
    org_id = org_and_users["org"].id
    entries = await _write(db_session, org_id, 4)
    await audit_proofs.checkpoint(db_session, org_id)
    await db_session.execute(text("SELECT set_config('provenza.allow_purge', 'on', true)"))
    await db_session.execute(text("DELETE FROM ai_audit_logs WHERE id = :id"), {"id": entries[1].id})
    await db_session.execute(text("SELECT set_config('provenza.allow_purge', 'off', true)"))
    rep = await audit_proofs.verify_chain(db_session, org_id)
    kinds = {p["kind"] for p in rep["problems"]}
    assert rep["ok"] is False and {"sequence_gap", "broken_link"} <= kinds
    with pytest.raises(audit_proofs.ProofError):
        await audit_proofs.inclusion_proof(db_session, org_id, entries[3].id)


async def test_beat_task_signs_only_logs_that_grew(db_session, org_and_users):
    org_id = org_and_users["org"].id
    await _write(db_session, org_id, 2)
    assert org_id in await audit_proofs.stale_orgs(db_session)
    await audit_proofs.checkpoint(db_session, org_id)
    assert org_id not in await audit_proofs.stale_orgs(db_session)
    n = (await db_session.execute(select(AuditCheckpoint).where(AuditCheckpoint.org_id == org_id))).scalars().all()
    assert len(n) == 1


def _signed_checkpoint(leaves, n, priv, pub, issued=None):
    issued = issued or datetime(2026, 10, 1, tzinfo=timezone.utc)
    fp = agent_signing.key_fingerprint(pub)
    root = ac.merkle_root(leaves[:n]).hex()
    st = ac.checkpoint_statement(org_id=1, tree_size=n, root_hash=root, issued_at=issued, key_fingerprint=fp,
                                 algorithm=agent_signing.SCHEME_CLASSIC)
    return {"org_id": 1, "tree_size": n, "root_hash": root, "issued_at": ac.format_ts(issued),
            "algorithm": agent_signing.SCHEME_CLASSIC, "statement": agent_signing.canonical_text(st),
            "signature": agent_signing.sign_payload(st, priv), "pq_signature": None, "public_key": pub,
            "pq_public_key": None, "key_fingerprint": fp}


def test_offline_tool_rejects_a_key_switch_and_unsigned_fields():
    leaves = [hashlib.sha256(bytes([i])).digest() for i in range(9)]
    real_priv, real_pub = agent_signing.generate_keypair()
    evil_priv, evil_pub = agent_signing.generate_keypair()
    old = _signed_checkpoint(leaves, 5, real_priv, real_pub)
    path = ac.hexes(ac.consistency_proof(5, leaves))
    honest = {"format": "provenza.audit.consistency/1", "old": old,
              "new": _signed_checkpoint(leaves, 9, real_priv, real_pub), "consistency_path": path}
    tool.check_consistency(honest, pinned=old)

    # an extension of the real history, but signed by someone else's key
    switched = dict(honest, new=_signed_checkpoint(leaves, 9, evil_priv, evil_pub))
    with pytest.raises(tool.Fail, match="different keys"):
        tool.check_consistency(switched, pinned=old)

    # fields shown to the user must be the signed ones
    with pytest.raises(tool.Fail, match="issued_at"):
        tool.check_checkpoint(dict(old, issued_at="2030-01-01T00:00:00.000000Z"))
