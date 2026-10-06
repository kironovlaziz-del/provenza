# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Strict agent identity by default, and signing-key revocation:

  - an organization without saved settings requires agent keys, refuses
    keyless agents and enforces agent-to-agent message checks;
  - a suspended agent's key no longer authenticates;
  - a revoked key is in the append-only revocation list and the audit log,
    can never be registered again, and signatures received from
    `untrusted_from` on are not trusted - earlier ones still are.
"""

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.models.audit_log import AIAuditLog
from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers
from tests.delegation_helpers import delegation_body
from tests.enrollment_helpers import enroll, enroll_with, issue, rotate

A = "/api/v1/agents"
ID = "/api/v1/agent-identity"


@pytest_asyncio.fixture
async def strict(client, db_session):
    org = await _create_org_with_admin_and_approver(
        db_session, org_slug="strict-org", admin_email="admin@strict.example.com",
        approver_email="approver@strict.example.com", relaxed_identity=False)
    token = await _login(client, org["org"].slug, org["admin"].email, org["password"])
    return {**org, "token": token}


async def _agent(client, token, name):
    # strict organizations have no direct registration: agents enroll with proof
    return await enroll(client, token, name, max_delegation_depth=3)


def K(agent):
    return {"X-Agent-Key": agent["api_key"]}


async def _check(client, headers, agent_id):
    return await client.post(f"{A}/actions/check", headers=headers,
                             json={"agent_id": agent_id, "tool_name": "kb.search", "input": {}})


# --- defaults --------------------------------------------------------------------------

async def test_defaults_are_strict(client, strict):
    ov = (await client.get(f"{ID}/", headers=auth_headers(strict["token"]))).json()
    assert ov["settings"]["require_agent_key"] is True
    assert ov["settings"]["allow_keyless_agents"] is False
    a2a = (await client.get("/api/v1/a2a/", headers=auth_headers(strict["token"]))).json()
    assert a2a["settings"]["mode"] == "enforce"


async def test_a_user_session_cannot_act_as_an_agent(client, strict):
    a = await _agent(client, strict["token"], "s1")
    r = await _check(client, auth_headers(strict["token"]), a["id"])
    assert r.status_code == 403 and "agent_key_required" in r.text
    assert (await _check(client, K(a), a["id"])).status_code == 200


async def test_a_suspended_agents_key_does_not_authenticate(client, strict):
    a = await _agent(client, strict["token"], "s2")
    r = await client.post(f"{A}/{a['id']}/kill", headers=auth_headers(strict["token"]), json={"reason": "test"})
    assert r.status_code == 200, r.text
    r = await _check(client, K(a), a["id"])
    assert r.status_code == 403 and "agent_inactive" in r.text


# --- revocation --------------------------------------------------------------------------

async def _keys(client, token, agent_id):
    return (await client.get(f"{A}/{agent_id}/signing-keys", headers=auth_headers(token))).json()


async def _revoke(client, token, agent_id, key_id, **body):
    return await client.post(f"{A}/{agent_id}/signing-keys/{key_id}/revoke", headers=auth_headers(token),
                             json={"reason": "rotated out", **body})


async def test_revoking_the_current_key_stops_the_agent(client, strict):
    a = await _agent(client, strict["token"], "s3")
    b = await _agent(client, strict["token"], "s3b")
    key = (await _keys(client, strict["token"], a["id"]))[0]
    r = await _revoke(client, strict["token"], a["id"], key["id"])
    assert r.status_code == 200, r.text
    # no signing key left, and keyless agents may not act
    body = delegation_body(a, b["id"], "t", ["read"])
    r = await client.post(f"{A}/{a['id']}/delegate", headers=K(a), json=body)
    assert r.status_code == 403 and "agent.key_required" in r.text
    # the revoked key can never come back - not even through a re-key enrollment
    tok = await issue(client, strict["token"], purpose="rekey", agent_id=a["id"])
    r = await enroll_with(client, tok["token"], {"private_key": a["private_key"], "public_key": a["public_key"],
                                                  "pq_private_key": None, "pq_public_key": None})
    assert r.status_code == 422 and "agent.key_revoked" in r.text
    # and it cannot be revoked twice
    assert (await _revoke(client, strict["token"], a["id"], key["id"])).status_code == 409


async def test_revocation_judges_signatures_by_when_they_arrived(client, db_session, strict):
    a = await _agent(client, strict["token"], "s4")
    b = await _agent(client, strict["token"], "s4b")
    old_key = (await _keys(client, strict["token"], a["id"]))[0]
    r = await client.post(f"{A}/{a['id']}/delegate", headers=K(a), json=delegation_body(a, b["id"], "t", ["read"]))
    assert r.status_code == 200, r.text
    hop_id = r.json()["hop_id"]

    # the agent moves to a new key itself, then the old one is retired in an orderly way
    r, _ = await rotate(client, a)
    assert r.status_code == 200, r.text
    assert (await _revoke(client, strict["token"], a["id"], old_key["id"])).status_code == 200
    ev = (await client.get(f"{A}/delegation-hops/{hop_id}/verification", headers=auth_headers(strict["token"]))).json()
    assert ev["revocation"] is not None and ev["trusted"] is True  # made before the revocation

    # a key known compromised since before that hop: the hop is no longer trusted
    c = await _agent(client, strict["token"], "s4c")
    r = await client.post(f"{A}/{c['id']}/delegate", headers=K(c), json=delegation_body(c, b["id"], "t", ["read"]))
    hop2 = r.json()["hop_id"]
    c_key = (await _keys(client, strict["token"], c["id"]))[0]
    r = await _revoke(client, strict["token"], c["id"], c_key["id"], compromised_since="2020-01-01T00:00:00Z")
    assert r.status_code == 200 and r.json()["untrusted_from"].startswith("2020-01-01")
    ev = (await client.get(f"{A}/delegation-hops/{hop2}/verification", headers=auth_headers(strict["token"]))).json()
    assert ev["server_verified"] is True and ev["trusted"] is False


async def test_the_revocation_list_is_append_only_and_audited(client, db_session, strict):
    a = await _agent(client, strict["token"], "s5")
    key = (await _keys(client, strict["token"], a["id"]))[0]
    rev = (await _revoke(client, strict["token"], a["id"], key["id"])).json()
    listed = (await client.get(f"{A}/key-revocations", headers=auth_headers(strict["token"]))).json()
    assert [r["fingerprint"] for r in listed] == [key["fingerprint"]]
    rec = (await db_session.execute(select(AIAuditLog).where(
        AIAuditLog.entity_type == "agent_key_revocation", AIAuditLog.entity_id == rev["id"]))).scalar_one()
    assert rec.metadata_json["fingerprint"] == key["fingerprint"]
    with pytest.raises(DBAPIError, match="append-only"):
        async with db_session.begin_nested():
            await db_session.execute(text("UPDATE agent_key_revocations SET reason = 'x' WHERE id = :id"),
                                     {"id": rev["id"]})


async def test_compromise_time_cannot_be_in_the_future(client, strict):
    a = await _agent(client, strict["token"], "s6")
    key = (await _keys(client, strict["token"], a["id"]))[0]
    r = await _revoke(client, strict["token"], a["id"], key["id"], compromised_since="2999-01-01T00:00:00Z")
    assert r.status_code == 422
