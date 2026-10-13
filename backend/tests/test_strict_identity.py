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
    assert "allow_keyless_agents" not in ov["settings"]      # there is no keyless mode at all
    a2a = (await client.get("/api/v1/a2a/", headers=auth_headers(strict["token"]))).json()
    assert a2a["settings"]["mode"] == "enforce"
    registry = (await client.get("/api/v1/tool-registry/settings", headers=auth_headers(strict["token"]))).json()
    assert registry["mode"] == "enforce"                       # an unregistered tool is refused


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



# --- signed action requests ---------------------------------------------------------------

def _signed_check(agent, *, tool="kb.search", input=None, nonce=None, issued_at=None, sign_input=None,
                  key=None):
    """A check request signed as the SDK signs it; sign_input/key let a test sign something else."""
    import secrets as _s
    import time as _t

    from app.core.agent_signing import sign_payload
    from app.pvp.model import PVPActionRequest

    body = {"agent_id": agent["id"], "tool_name": tool, "input": input or {},
            "nonce": nonce or _s.token_hex(16), "issued_at": int(_t.time()) if issued_at is None else issued_at}
    signed = PVPActionRequest(**{**body, "input": sign_input if sign_input is not None else body["input"]})
    body["signature"] = sign_payload(signed.signed_payload(), key or agent["private_key"])
    return body


async def test_an_agent_must_sign_its_checks(client, strict):
    a = await _agent(client, strict["token"], "sig1")
    r = await client.post(f"{A}/actions/check", headers=K(a),
                          json={"agent_id": a["id"], "tool_name": "kb.search", "input": {}, "signature": None})
    assert r.status_code == 401 and r.json()["detail"] == "action.signature_required"
    r = await client.post(f"{A}/actions/check", headers=K(a), json=_signed_check(a))
    assert r.status_code == 200, r.text


async def test_a_stolen_api_key_alone_gets_nothing(client, strict):
    a = await _agent(client, strict["token"], "sig2")
    other = await _agent(client, strict["token"], "sig3")
    # signed with another agent's key: refused
    r = await client.post(f"{A}/actions/check", headers=K(a), json=_signed_check(a, key=other["private_key"]))
    assert r.status_code == 401 and r.json()["detail"] == "action.invalid_signature"
    # the signature covers the arguments: changed arguments, refused
    r = await client.post(f"{A}/actions/check", headers=K(a),
                          json=_signed_check(a, input={"q": "drop table"}, sign_input={"q": "hello"}))
    assert r.status_code == 401 and r.json()["detail"] == "action.invalid_signature"


async def test_a_signed_check_cannot_be_replayed_or_kept_for_later(client, strict):
    import time as _t

    a = await _agent(client, strict["token"], "sig4")
    body = _signed_check(a)
    assert (await client.post(f"{A}/actions/check", headers=K(a), json=body)).status_code == 200
    r = await client.post(f"{A}/actions/check", headers=K(a), json=body)
    assert r.status_code == 409 and r.json()["detail"] == "action.replayed_request"
    r = await client.post(f"{A}/actions/check", headers=K(a), json=_signed_check(a, issued_at=int(_t.time()) - 600))
    assert r.status_code == 401 and r.json()["detail"] == "action.stale_request"
    r = await client.post(f"{A}/actions/check", headers=K(a), json=_signed_check(a, issued_at=int(_t.time()) + 600))
    assert r.status_code == 401 and r.json()["detail"] == "action.stale_request"


async def test_registration_without_the_agents_key_is_refused(client, db_session, strict):
    from app.models.agent_identity import AgentIdentitySettings

    row = (await db_session.execute(select(AgentIdentitySettings).where(
        AgentIdentitySettings.org_id == strict["org"].id))).scalar_one_or_none()
    if row is None:
        db_session.add(AgentIdentitySettings(org_id=strict["org"].id, require_agent_key=True,
                                             allow_direct_registration=True, rotation_grace_minutes=60))
    else:
        row.allow_direct_registration = True
    await db_session.flush()
    r = await client.post(f"{A}/register", headers=auth_headers(strict["token"]), json={
        "name": "nokey", "agent_type": "custom", "capabilities": [], "allowed_tools": [], "allowed_models": [],
        "max_delegation_depth": 1, "public_key": None})
    assert r.status_code == 422
