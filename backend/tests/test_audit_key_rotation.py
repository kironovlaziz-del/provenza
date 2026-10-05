# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Audit key rotation (docs/audit-proofs.md): a new key needs a quorum of
admins who each type its independently published fingerprint, a notice
period, and the old key's signed consent; verifiers additionally require
the new fingerprint from outside. Any admin can cancel.
"""

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.config import settings
from app.core.security import get_password_hash
from app.models.audit_log import AuditCheckpoint, AuditKeyHandover
from app.models.user import User, UserRole
from app.services import audit_proofs
from app.services.audit_service import AuditService
from tests.conftest import _login, auth_headers

K = "/api/v1/audit-logs/keys"
A = "/api/v1/audit-logs"
ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("provenza_audit_tool_rot", ROOT / "tools" / "provenza_audit.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


@pytest.fixture
def no_notice(monkeypatch):
    monkeypatch.setattr(settings, "AUDIT_KEY_ROTATION_NOTICE_HOURS", 0.0)
    monkeypatch.setattr(settings, "AUDIT_KEY_ROTATION_QUORUM", 2)


@pytest.fixture
async def admin2_token(client, db_session, org_and_users):
    u = User(org_id=org_and_users["org"].id, email="admin2@test.example.com", name="Admin Two",
             hashed_password=get_password_hash(org_and_users["password"]), role=UserRole.admin.value,
             status="active")
    db_session.add(u)
    await db_session.flush()
    return await _login(client, org_and_users["org"].slug, u.email, org_and_users["password"])


async def _seed(db, org_id, n=3):
    for i in range(n):
        await AuditService(db).log(org_id, None, "policy", i, "updated", {"i": i})


async def _propose(client, token):
    r = await client.post(f"{K}/rotations", json={"reason": "yearly rotation"}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    st = (await client.get(K, headers=auth_headers(token))).json()
    return r.json()["id"], st["pending"]["new_key"]["fingerprint"], st["current"]["fingerprint"]


async def test_full_rotation_and_offline_trust(client, db_session, org_and_users, admin_token, admin2_token, no_notice):
    org_id = org_and_users["org"].id
    await _seed(db_session, org_id)
    rid, new_fp, old_fp = await _propose(client, admin_token)
    assert new_fp != old_fp

    # the proposer alone is not a quorum
    r = await client.post(f"{K}/rotations/{rid}/complete", headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"]["code"] == "audit.rotation_quorum"

    # approving needs the fingerprint as published - a wrong one is refused
    r = await client.post(f"{K}/rotations/{rid}/approve", json={"fingerprint": old_fp},
                          headers=auth_headers(admin2_token))
    assert r.status_code == 422
    r = await client.post(f"{K}/rotations/{rid}/approve", json={"fingerprint": new_fp},
                          headers=auth_headers(admin2_token))
    assert r.status_code == 200, r.text
    r = await client.post(f"{K}/rotations/{rid}/approve", json={"fingerprint": new_fp},
                          headers=auth_headers(admin2_token))
    assert r.status_code == 409  # once per admin

    old_cp = (await client.get(f"{A}/integrity", headers=auth_headers(admin_token))).json()["checkpoint"]
    assert old_cp["key_fingerprint"] == old_fp

    r = await client.post(f"{K}/rotations/{rid}/complete", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    handover = r.json()
    assert handover["old_key_fingerprint"] == old_fp and handover["new_key_fingerprint"] == new_fp
    tool.check_handover(handover, org_id)

    st = (await client.get(K, headers=auth_headers(admin_token))).json()
    assert st["current"]["fingerprint"] == new_fp and st["pending"] is None and len(st["handovers"]) == 1
    latest = await audit_proofs.latest_checkpoint(db_session, org_id)
    assert latest.key_fingerprint == new_fp

    # offline: the old pin alone is not enough, old pin + confirmed new fingerprint is
    doc = (await client.get(f"{A}/consistency", params={"from_size": old_cp["tree_size"]},
                            headers=auth_headers(admin_token))).json()
    with pytest.raises(tool.TrustFail, match="not confirmed") as e:
        tool.check_consistency(doc, pinned=old_cp)
    assert any("handover" in line for line in e.value.lines)  # the trust chain explains it
    tool.check_consistency(doc, pinned=old_cp, pin=[new_fp])

    # without the handover the confirmed fingerprint alone is not enough either
    with pytest.raises(tool.TrustFail, match="no valid handover"):
        tool.check_consistency(dict(doc, key_handovers=[]), pinned=old_cp, pin=[new_fp])

    # a proof under the new key: verified when the new key is trusted
    log_id = (await AuditService(db_session).log(org_id, None, "policy", 9, "updated", None)).id
    proof = (await client.get(f"{A}/{log_id}/proof", headers=auth_headers(admin_token))).json()
    tool.check_proof(proof, pin=new_fp)
    with pytest.raises(tool.TrustFail):
        tool.check_proof(proof, pin=old_fp)

    rep = await audit_proofs.verify_chain(db_session, org_id)
    assert rep["ok"] is True, rep["problems"]
    assert rep["key_handovers"] == 1


async def test_notice_period_holds_the_change(client, db_session, org_and_users, admin_token, admin2_token,
                                              monkeypatch):
    monkeypatch.setattr(settings, "AUDIT_KEY_ROTATION_NOTICE_HOURS", 24.0)
    await _seed(db_session, org_and_users["org"].id)
    rid, new_fp, _ = await _propose(client, admin_token)
    await client.post(f"{K}/rotations/{rid}/approve", json={"fingerprint": new_fp}, headers=auth_headers(admin2_token))
    r = await client.post(f"{K}/rotations/{rid}/complete", headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"]["code"] == "audit.rotation_notice"
    st = (await client.get(K, headers=auth_headers(admin_token))).json()
    assert st["pending"]["ready"] is False and st["current"]["fingerprint"] != new_fp


async def test_any_admin_cancels_and_the_key_is_never_used(client, db_session, org_and_users, admin_token,
                                                          admin2_token, no_notice):
    org_id = org_and_users["org"].id
    await _seed(db_session, org_id)
    rid, new_fp, old_fp = await _propose(client, admin_token)
    r = await client.post(f"{K}/rotations", json={}, headers=auth_headers(admin2_token))
    assert r.status_code == 409 and r.json()["detail"] == "audit.rotation_pending"
    assert (await client.post(f"{K}/rotations/{rid}/cancel", headers=auth_headers(admin2_token))).status_code == 200
    r = await client.post(f"{K}/rotations/{rid}/approve", json={"fingerprint": new_fp},
                          headers=auth_headers(admin2_token))
    assert r.status_code == 409
    await _seed(db_session, org_id, 1)
    cp = await audit_proofs.checkpoint(db_session, org_id)
    assert cp.key_fingerprint == old_fp  # the cancelled key never signs


async def test_rotation_is_admin_only_and_needs_a_log(client, db_session, org_and_users, admin_token, approver_token):
    r = await client.post(f"{K}/rotations", json={}, headers=auth_headers(approver_token))
    assert r.status_code == 403
    # one admin cannot reach the default quorum of 2 (or there is nothing signed yet)
    r = await client.post(f"{K}/rotations", json={}, headers=auth_headers(admin_token))
    assert r.status_code == 409
    d = r.json()["detail"]
    assert (d if isinstance(d, str) else d["code"]) in ("audit.nothing_to_rotate", "audit.quorum_unreachable")


async def test_an_admin_added_after_the_proposal_cannot_approve(client, db_session, org_and_users, admin_token,
                                                                admin2_token, no_notice):
    await _seed(db_session, org_and_users["org"].id)
    rid, new_fp, _ = await _propose(client, admin_token)
    late = User(org_id=org_and_users["org"].id, email="late@test.example.com", name="Late",
                hashed_password=get_password_hash(org_and_users["password"]), role=UserRole.admin.value,
                status="active")
    db_session.add(late)
    await db_session.flush()
    token = await _login(client, org_and_users["org"].slug, late.email, org_and_users["password"])
    r = await client.post(f"{K}/rotations/{rid}/approve", json={"fingerprint": new_fp}, headers=auth_headers(token))
    assert r.status_code == 403 and r.json()["detail"] == "audit.rotation_not_eligible"


def test_offline_tool_refuses_a_forked_key():
    from datetime import datetime, timezone

    from app.core import agent_signing as sig
    from app.core import audit_chain as ac

    keys = [sig.generate_keypair() for _ in range(3)]
    fps = [sig.key_fingerprint(pub) for _, pub in keys]

    def handover(old, new):
        now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        st = ac.handover_statement(org_id=1, rotation_id=new, tree_size=3, root_hash="ab" * 32, issued_at=now,
                                   proposed_at=now, quorum=2, approvals=[1, 2], old_key_fingerprint=fps[old],
                                   old_algorithm="ed25519", new_key_fingerprint=fps[new], new_algorithm="ed25519")
        return {"org_id": 1, "rotation_id": new, "tree_size": 3, "root_hash": "ab" * 32,
                "issued_at": ac.format_ts(now), "statement": sig.canonical_text(st),
                "old_key_fingerprint": fps[old], "old_public_key": keys[old][1], "old_pq_public_key": None,
                "old_signature": sig.sign_payload(st, keys[old][0]), "old_pq_signature": None,
                "new_key_fingerprint": fps[new], "new_public_key": keys[new][1], "new_pq_public_key": None,
                "new_signature": sig.sign_payload(st, keys[new][0]), "new_pq_signature": None}

    tool.handover_links({"key_handovers": [handover(0, 1)]}, 1)
    with pytest.raises(tool.Fail, match="handed over twice"):
        tool.handover_links({"key_handovers": [handover(0, 1), handover(0, 2)]}, 1)


async def test_approvals_of_demoted_admins_do_not_count(client, db_session, org_and_users, admin_token, admin2_token,
                                                        no_notice):
    await _seed(db_session, org_and_users["org"].id)
    rid, new_fp, _ = await _propose(client, admin_token)
    await client.post(f"{K}/rotations/{rid}/approve", json={"fingerprint": new_fp}, headers=auth_headers(admin2_token))
    await db_session.execute(text("UPDATE users SET role = 'user' WHERE email = 'admin2@test.example.com'"))
    r = await client.post(f"{K}/rotations/{rid}/complete", headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"]["code"] == "audit.rotation_quorum"


async def test_handovers_are_append_only_and_verify_catches_a_bad_one(client, db_session, org_and_users, admin_token,
                                                                      admin2_token, no_notice):
    org_id = org_and_users["org"].id
    await _seed(db_session, org_id)
    rid, new_fp, _ = await _propose(client, admin_token)
    await client.post(f"{K}/rotations/{rid}/approve", json={"fingerprint": new_fp}, headers=auth_headers(admin2_token))
    assert (await client.post(f"{K}/rotations/{rid}/complete", headers=auth_headers(admin_token))).status_code == 200
    h = (await db_session.execute(select(AuditKeyHandover).where(AuditKeyHandover.org_id == org_id))).scalar_one()
    with pytest.raises(DBAPIError, match="append-only"):
        async with db_session.begin_nested():
            await db_session.execute(text("UPDATE audit_key_handovers SET new_fingerprint = 'x' WHERE id = :id"),
                                     {"id": h.id})
    # someone who can switch the trigger off swaps the new key's signature
    await db_session.execute(text("ALTER TABLE audit_key_handovers DISABLE TRIGGER audit_key_handovers_append_only"))
    await db_session.execute(text("UPDATE audit_key_handovers SET new_signature = old_signature WHERE id = :id"),
                             {"id": h.id})
    await db_session.execute(text("ALTER TABLE audit_key_handovers ENABLE TRIGGER audit_key_handovers_append_only"))
    db_session.expire_all()
    rep = await audit_proofs.verify_chain(db_session, org_id)
    assert "handover_signature" in {p["kind"] for p in rep["problems"]}


async def test_checkpoint_signed_by_a_key_nobody_handed_over_to_is_reported(db_session, org_and_users):
    org_id = org_and_users["org"].id
    await _seed(db_session, org_id)
    first = await audit_proofs.checkpoint(db_session, org_id)
    rogue = await audit_proofs.new_key(db_session, org_id)
    await _seed(db_session, org_id, 1)
    size = await audit_proofs.head(db_session, org_id)
    from app.core import audit_chain as ac
    from app.core.agent_signing import canonical_text

    leaves = await audit_proofs.leaves_of(db_session, org_id, size)
    now = ac.now_utc()
    st = ac.checkpoint_statement(org_id=org_id, tree_size=size, root_hash=ac.merkle_root(leaves).hex(), issued_at=now,
                                 key_fingerprint=rogue.fingerprint, algorithm=rogue.algorithm)
    s1, s2 = audit_proofs.sign_with(rogue, st)
    db_session.add(AuditCheckpoint(org_id=org_id, tree_size=size, root_hash=st["root_hash"], issued_at=now,
                                   statement=canonical_text(st), algorithm=rogue.algorithm, signature=s1,
                                   pq_signature=s2, key_id=rogue.id, public_key=rogue.public_key,
                                   pq_public_key=rogue.pq_public_key, key_fingerprint=rogue.fingerprint))
    await db_session.flush()
    rep = await audit_proofs.verify_chain(db_session, org_id)
    assert first.key_fingerprint != rogue.fingerprint
    assert "checkpoint_unexpected_key" in {p["kind"] for p in rep["problems"]}
