# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agents join with an admin-issued one-time token and prove they hold their
key (signed challenge); their rights come from the token's template. Keys
change only with proof: the agent's own rotation (old key consents, new key
proves possession) or a re-key token. Direct registration and unproven key
replacement are off by default.
"""

from datetime import datetime, timedelta, timezone

import pytest_asyncio
from sqlalchemy import select, update

from app.core.agent_signing import pq_available
from app.models.agent import Agent, AgentSigningKey
from app.models.enrollment import AgentEnrollment
from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers
from tests.enrollment_helpers import E, enroll, enroll_with, issue, new_keys, rotate

A = "/api/v1/agents"


@pytest_asyncio.fixture
async def strict(client, db_session):
    org = await _create_org_with_admin_and_approver(
        db_session, org_slug="enroll-org", admin_email="admin@enroll.example.com",
        approver_email="approver@enroll.example.com", relaxed_identity=False)
    token = await _login(client, org["org"].slug, org["admin"].email, org["password"])
    return {**org, "token": token}


async def test_an_agent_joins_with_the_templates_rights(client, db_session, strict):
    tok = await issue(client, strict["token"], name="billing-bot", capabilities=["payments"],
                      allowed_tools=["stripe.charge"], max_delegation_depth=1, owner_team="finance")
    assert tok["token"].startswith("pvz_enr_") and tok["state"] == "open"
    listed = (await client.get(f"{E}/tokens", headers=auth_headers(strict["token"]))).json()
    assert all("token" not in t for t in listed)  # shown once, never listed

    keys = new_keys()
    r = await enroll_with(client, tok["token"], keys)
    assert r.status_code == 200, r.text
    d = r.json()
    agent = (await db_session.execute(select(Agent).where(Agent.id == d["agent_id"]))).scalar_one()
    assert agent.capabilities == ["payments"] and agent.allowed_tools == ["stripe.charge"]
    assert agent.max_delegation_depth == 1 and agent.owner_team == "finance"
    assert agent.owner_user_id == strict["admin"].id and agent.key_origin == "agent"
    key = (await db_session.execute(select(AgentSigningKey).where(AgentSigningKey.agent_id == agent.id))).scalar_one()
    assert key.proof["kind"] == "enrollment" and key.proof["signature"]
    # it acts with its own API key
    r = await client.post(f"{A}/actions/check", headers={"X-Agent-Key": d["api_key"]},
                          json={"agent_id": agent.id, "tool_name": "stripe.charge", "input": {}})
    assert r.status_code == 200 and r.json()["decision"] == "allowed", r.text


async def test_an_agent_cannot_ask_for_rights(client, strict):
    tok = await issue(client, strict["token"], name="x")
    r = await enroll_with(client, tok["token"], new_keys(),
                          tamper=lambda b: b.update(capabilities=["admin"], allowed_tools=["*"]))
    assert r.status_code == 422


async def test_a_token_is_spent_by_use(client, strict):
    tok = await issue(client, strict["token"], name="once")
    assert (await enroll_with(client, tok["token"], new_keys())).status_code == 200
    r = await client.post(f"{E}/challenge", json={"token": tok["token"]})
    assert r.status_code == 401 and "enrollment.invalid_token" in r.text


async def test_proof_must_come_from_the_key_being_registered(client, db_session, strict):
    tok = await issue(client, strict["token"], name="pop")
    mine, other = new_keys(), new_keys()

    def swap_key(body):  # signature made with `mine`, registering `other`'s public key
        body["public_key"] = other["public_key"]

    r = await enroll_with(client, tok["token"], mine, tamper=swap_key)
    assert r.status_code == 401 and "enrollment.bad_proof" in r.text
    # the challenge was spent by the failed attempt
    ch_used = await client.post(f"{E}/enroll", json={
        "token": tok["token"], "challenge": "0" * 64, "public_key": mine["public_key"], "signature": "x" * 20})
    assert ch_used.status_code == 401 and "enrollment.bad_challenge" in ch_used.text


async def test_five_failed_proofs_spend_the_token(client, db_session, strict):
    tok = await issue(client, strict["token"], name="brute")

    def break_sig(body):
        body["signature"] = body["signature"][::-1]

    for _ in range(5):
        r = await enroll_with(client, tok["token"], new_keys(), tamper=break_sig)
        assert r.status_code == 401
    r = await client.post(f"{E}/challenge", json={"token": tok["token"]})
    assert r.status_code == 401


async def test_expired_and_revoked_tokens(client, db_session, strict):
    old = await issue(client, strict["token"], name="late")
    await db_session.execute(update(AgentEnrollment).where(AgentEnrollment.id == old["id"])
                             .values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))
    assert (await client.post(f"{E}/challenge", json={"token": old["token"]})).status_code == 401
    tok = await issue(client, strict["token"], name="nope")
    r = await client.post(f"{E}/tokens/{tok['id']}/revoke", headers=auth_headers(strict["token"]))
    assert r.status_code == 200 and r.json()["state"] == "revoked"
    assert (await client.post(f"{E}/challenge", json={"token": tok["token"]})).status_code == 401


async def test_direct_registration_and_unproven_keys_are_off(client, strict):
    r = await client.post(f"{A}/register", headers=auth_headers(strict["token"]), json={"name": "direct"})
    assert r.status_code == 403 and "agent.enrollment_required" in r.text
    a = await enroll(client, strict["token"], "keyed")
    r = await client.post(f"{A}/{a['id']}/signing-key", headers=auth_headers(strict["token"]),
                          json={"public_key": new_keys()["public_key"]})
    assert r.status_code == 403 and "agent.proof_required" in r.text


async def test_rotation_needs_the_old_and_the_new_key(client, db_session, strict):
    a = await enroll(client, strict["token"], "rot")
    # signed by a stranger instead of the current key: refused
    r, _ = await rotate(client, a, sign_old=new_keys())
    assert r.status_code == 401 and "old_key" in r.text
    r, new = await rotate(client, a)
    assert r.status_code == 200, r.text
    agent = (await db_session.execute(select(Agent).where(Agent.id == a["id"]))).scalar_one()
    assert agent.public_key == new["public_key"]
    key = (await db_session.execute(select(AgentSigningKey).where(
        AgentSigningKey.agent_id == a["id"], AgentSigningKey.retired_at.is_(None)))).scalar_one()
    assert key.proof["kind"] == "rotation" and key.proof["old_signature"] and key.proof["signature"]


async def test_a_user_session_cannot_rotate_an_agents_key(client, db_session, org_and_users, admin_token):
    # even in a relaxed organization: rotation is the agent's own act
    r = await client.post(f"{A}/register", headers=auth_headers(admin_token), json={"name": "legacy"})
    a = r.json()
    r = await client.post(f"{A}/{a['id']}/signing-key/challenge", headers=auth_headers(admin_token))
    assert r.status_code == 403


async def test_rekey_after_a_lost_key(client, db_session, strict):
    a = await enroll(client, strict["token"], "lost")
    key = (await client.get(f"{A}/{a['id']}/signing-keys", headers=auth_headers(strict["token"]))).json()[0]
    await client.post(f"{A}/{a['id']}/signing-keys/{key['id']}/revoke", headers=auth_headers(strict["token"]),
                      json={"reason": "laptop lost"})
    tok = await issue(client, strict["token"], purpose="rekey", agent_id=a["id"])
    keys = new_keys()
    r = await enroll_with(client, tok["token"], keys)
    assert r.status_code == 200, r.text
    new_api_key = r.json()["api_key"]
    assert r.json()["agent_id"] == a["id"] and new_api_key and new_api_key != a["api_key"]
    agent = (await db_session.execute(select(Agent).where(Agent.id == a["id"]))).scalar_one()
    assert agent.public_key == keys["public_key"]
    # a lost key usually means a lost API key too: the old one stops, the new one works
    body = {"agent_id": a["id"], "tool_name": "kb.search", "input": {}}
    assert (await client.post(f"{A}/actions/check", headers={"X-Agent-Key": a["api_key"]}, json=body)).status_code == 401
    assert (await client.post(f"{A}/actions/check", headers={"X-Agent-Key": new_api_key}, json=body)).status_code == 200


async def test_a_hybrid_template_refuses_a_classic_key(client, strict):
    if not pq_available():
        return
    tok = await issue(client, strict["token"], name="pq", require_hybrid=True)
    r = await enroll_with(client, tok["token"], new_keys(hybrid=False))
    assert r.status_code == 422 and "agent.pq_required" in r.text
    tok = await issue(client, strict["token"], name="pq2", require_hybrid=True)
    assert (await enroll_with(client, tok["token"], new_keys(hybrid=True))).status_code == 200


async def test_depth_zero_stays_zero(client, db_session, strict):
    a = await enroll(client, strict["token"], "leaf-only", max_delegation_depth=0)
    agent = (await db_session.execute(select(Agent).where(Agent.id == a["id"]))).scalar_one()
    assert agent.max_delegation_depth == 0


async def test_a_previous_key_cannot_come_back_through_rotation(client, strict):
    a = await enroll(client, strict["token"], "no-reuse")
    first = {k: a[k] for k in ("private_key", "public_key", "pq_private_key", "pq_public_key")}
    r, second = await rotate(client, a)
    assert r.status_code == 200
    # rotate back to the first key: signed properly by the current (second) key and by the first
    from tests.enrollment_helpers import sign_both
    from app.core.agent_signing import key_fingerprint

    hdr = {"X-Agent-Key": a["api_key"]}
    ch = (await client.post(f"{A}/{a['id']}/signing-key/challenge", headers=hdr)).json()
    statement = {"type": "provenza.agent.key_rotation", "v": 1, "challenge": ch["challenge"], "agent_id": a["id"],
                 "old_key_fingerprint": ch["old_key_fingerprint"],
                 "new_key_fingerprint": key_fingerprint(first["public_key"], None),
                 "new_public_key": first["public_key"], "new_pq_public_key": None}
    os_, _ = sign_both(second, statement)
    ns, _ = sign_both(first, statement)
    r = await client.post(f"{A}/{a['id']}/signing-key/rotate", headers=hdr, json={
        "challenge": ch["challenge"], "new_public_key": first["public_key"], "old_signature": os_, "new_signature": ns})
    assert r.status_code == 422 and "agent.key_in_use" in r.text


async def test_an_odd_challenge_is_refused_cleanly(client, strict):
    tok = await issue(client, strict["token"], name="odd")
    r = await client.post(f"{E}/enroll", json={"token": tok["token"], "challenge": "é" * 64,
                                                 "public_key": new_keys()["public_key"], "signature": "x" * 20})
    assert r.status_code == 422
