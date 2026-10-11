# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVPOrchestrator (app/pvp/orchestrator.py) and the REST adapter in front of it.

The REST endpoints' behaviour is pinned by the existing suites
(test_action_binding, test_delegation_*, test_agents_api, ...); these tests
cover what P2 adds:
  - the orchestrator speaks PVP: a check comes back as a PVPCheck, a recorded
    action converts to PVP evidence that verifies offline;
  - protocol rules the model leaves to the orchestrator keep their codes
    (self-delegation, signed without nonce, keyed record without check_id);
  - a body PVP refuses is a 422 that does not echo the refused input.
"""

import secrets
import time

import pytest

from app.core.agent_signing import sign_payload
from app.pvp import model as pvp
from app.pvp.orchestrator import PVPOrchestrator
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body, delegation_body

CHECK = "/api/v1/agents/actions/check"
RECORD = "/api/v1/agents/actions/record"


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register", json={
        "name": "orc-" + secrets.token_hex(3), "agent_type": "custom",
        "capabilities": ["read"], "allowed_tools": ["db.read"], "allowed_models": ["gpt-4o-mini"],
        "max_delegation_depth": 3,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# The orchestrator itself
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_check_record_and_evidence_through_the_orchestrator(client, admin_token, db_session, org_and_users):
    a = await _agent(client, admin_token)
    org_id = org_and_users["org"].id
    orc = PVPOrchestrator(db_session)

    req = pvp.PVPActionRequest(agent_id=a["id"], tool_name="db.read", input={"q": "select 1"})
    check = await orc.check(org_id, req)
    assert isinstance(check, pvp.PVPCheck)
    assert check.decision == "allowed" and check.input_sha256 == req.input_sha256
    assert check.expires_at > time.time()

    unsigned = pvp.PVPActionRecord(agent_id=a["id"], tool_name="db.read", check_id=check.check_id,
                                   input=req.input, output={"rows": 1})
    rec = unsigned.model_copy(update={"signature": sign_payload(unsigned.signed_payload(), a["private_key"])})
    action = await orc.record(org_id, rec)

    evidence = PVPOrchestrator.action_out(action)
    assert evidence.check_id == check.check_id
    assert pvp.PVPReceipt(action=evidence, check=check).problems() == []


@pytest.mark.asyncio
async def test_denied_check_is_still_issued_and_bound(client, admin_token, db_session, org_and_users):
    a = await _agent(client, admin_token)
    check = await PVPOrchestrator(db_session).check(
        org_and_users["org"].id, pvp.PVPActionRequest(agent_id=a["id"], tool_name="stripe.charge"))
    assert check.decision == "denied"
    assert len(check.check_id) >= 16   # recorded later as a refused attempt


# ---------------------------------------------------------------------------
# Rules the orchestrator owns keep their codes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_self_delegation_is_refused(client, admin_token):
    a = await _agent(client, admin_token)
    r = await client.post(f"/api/v1/agents/{a['id']}/delegate",
                          json=delegation_body(a, a["id"], "loop", ["read"]), headers=auth_headers(admin_token))
    assert r.status_code == 400 and r.json()["detail"] == "delegation.self"


@pytest.mark.asyncio
async def test_signed_delegation_without_nonce_is_refused(client, admin_token):
    a = await _agent(client, admin_token)
    b = await _agent(client, admin_token)
    body = delegation_body(a, b["id"], "t", ["read"])
    body.pop("nonce")
    r = await client.post(f"/api/v1/agents/{a['id']}/delegate", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 400, r.text
    assert "nonce" in r.json()["detail"]


@pytest.mark.asyncio
async def test_keyed_record_without_check_id_is_refused(client, admin_token):
    a = await _agent(client, admin_token)
    body = action_record_body(a, None, "db.read", {"q": 1})
    r = await client.post(RECORD, json=body, headers=auth_headers(admin_token))
    assert r.status_code == 401 and "check_id" in r.json()["detail"]


# ---------------------------------------------------------------------------
# What PVP refuses at the door
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_oversized_tool_name_is_a_422(client, admin_token):
    a = await _agent(client, admin_token)
    r = await client.post(CHECK, json={"agent_id": a["id"], "tool_name": "t" * 101}, headers=auth_headers(admin_token))
    assert r.status_code == 422
    assert r.json()["detail"][0]["loc"] == ["body", "tool_name"]


@pytest.mark.asyncio
async def test_non_finite_number_is_a_422_without_echo(client, admin_token):
    a = await _agent(client, admin_token)
    marker = "secret-" + secrets.token_hex(8)
    content = '{"agent_id": %d, "tool_name": "db.read", "input": {"x": NaN, "note": "%s"}}' % (a["id"], marker)
    r = await client.post(CHECK, content=content, headers={**auth_headers(admin_token),
                                                          "Content-Type": "application/json"})
    assert r.status_code == 422, r.text
    assert marker not in r.text


@pytest.mark.asyncio
async def test_action_type_must_be_a_token(client, admin_token):
    a = await _agent(client, admin_token)
    r = await client.post(CHECK, json={"agent_id": a["id"], "tool_name": "db.read", "action_type": "Tool Call"},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_delegation_lifetime_is_bounded(client, admin_token):
    a = await _agent(client, admin_token)
    b = await _agent(client, admin_token)
    body = delegation_body(a, b["id"], "t", ["read"], expires_in=pvp.MAX_DELEGATION_TTL + 1)
    r = await client.post(f"/api/v1/agents/{a['id']}/delegate", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 422
