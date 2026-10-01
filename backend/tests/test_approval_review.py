"""
ASI09 - human approval that can't be talked into a bad decision:
review packet (verified facts vs agent statements), approval bound to the
reviewed arguments, segregation of duties, expiry, typed confirmation for
high-risk cases and approval fatigue.
"""

import secrets

import pytest
from sqlalchemy import update

from app.models.agent import Agent
from app.services import agent_approval_service as approval_module
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body, delegation_body

A = "/api/v1/agents"


async def _agent(client, token, tools=("payments.charge",), caps=("read",)):
    r = await client.post(
        f"{A}/register",
        json={"name": "ap-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": list(caps),
              "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 2},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _gate(client, token, tool="payments.charge"):
    r = await client.post(f"{A}/policies/", json={"name": "gate-" + secrets.token_hex(2),
                                                  "rules": {"require_approval_tools": [tool]}, "priority": 100},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text


async def _pending(client, token, agent, inp, chain_id=None, tool="payments.charge"):
    chk = await client.post(f"{A}/actions/check",
                            json={"agent_id": agent["id"], "chain_id": chain_id, "tool_name": tool, "input": inp},
                            headers=auth_headers(token))
    assert chk.json()["decision"] == "pending_approval", chk.text
    rec = await client.post(f"{A}/actions/record",
                            json=action_record_body(agent, chk.json()["check_id"], tool, inp, chain_id=chain_id),
                            headers=auth_headers(token))
    assert rec.status_code == 200, rec.text
    return rec.json()["id"]


async def _review(client, token, action_id):
    r = await client.get(f"{A}/actions/{action_id}/review", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _approve(client, token, action_id, sha, confirmation=None):
    body = {"input_sha256": sha}
    if confirmation is not None:
        body["confirmation"] = confirmation
    return await client.post(f"{A}/actions/{action_id}/approve", json=body, headers=auth_headers(token))


async def _set_owner(db_session, agent_id, user_id):
    await db_session.execute(update(Agent).where(Agent.id == agent_id).values(owner_user_id=user_id))
    await db_session.commit()


class TestReviewPacket:
    @pytest.mark.asyncio
    async def test_packet_separates_verified_facts_from_agent_statements(self, client, admin_token, approver_token):
        await _gate(client, admin_token)
        root = await _agent(client, admin_token, tools=("payments.charge",), caps=("read", "write"))
        worker = await _agent(client, admin_token)
        d = await client.post(f"{A}/{root['id']}/delegate",
                              json=delegation_body(root, worker["id"], "Reconcile the monthly report", ["read"]),
                              headers=auth_headers(admin_token))
        chain_id = d.json()["chain_id"]
        action_id = await _pending(client, admin_token, worker, {"amount": 50000, "iban": "XX00 EVIL"}, chain_id)

        p = await _review(client, approver_token, action_id)
        assert p["action"]["input"] == {"amount": 50000, "iban": "XX00 EVIL"}
        assert len(p["verified"]["input_sha256"]) == 64
        assert p["verified"]["signature"] == {"present": True, "valid": True, "covers_these_arguments": True}
        assert p["verified"]["chain"]["delegated_by_agent_id"] == root["id"]
        # what the agents SAID lives in its own, explicitly unverified section
        texts = [s["text"] for s in p["unverified_statements"]]
        assert "Reconcile the monthly report" in texts
        assert p["reviewer"]["can_decide"] is True


class TestBinding:
    @pytest.mark.asyncio
    async def test_approval_must_carry_the_reviewed_hash(self, client, admin_token, approver_token):
        await _gate(client, admin_token)
        a = await _agent(client, admin_token)
        action_id = await _pending(client, admin_token, a, {"amount": 10})
        stale = await _approve(client, approver_token, action_id, "0" * 64)
        assert stale.status_code == 409 and "differ" in stale.text
        ok = await _approve(client, approver_token, action_id, (await _review(client, approver_token, action_id))["verified"]["input_sha256"])
        assert ok.status_code == 200 and ok.json()["policy_check_result"] == "allowed"
        decided = (await _review(client, approver_token, action_id))["decision"]
        assert decided["decision"] == "approved" and decided["decided_by"] is not None

    @pytest.mark.asyncio
    async def test_body_is_required(self, client, admin_token, approver_token):
        await _gate(client, admin_token)
        a = await _agent(client, admin_token)
        action_id = await _pending(client, admin_token, a, {"amount": 10})
        r = await client.post(f"{A}/actions/{action_id}/approve", headers=auth_headers(approver_token))
        assert r.status_code == 422


class TestSegregationOfDuties:
    @pytest.mark.asyncio
    async def test_owner_cannot_approve_own_agent(self, client, admin_token, approver_token, org_and_users, db_session):
        await _gate(client, admin_token)
        a = await _agent(client, admin_token)
        await _set_owner(db_session, a["id"], org_and_users["approver"].id)
        action_id = await _pending(client, admin_token, a, {"amount": 10})
        p = await _review(client, approver_token, action_id)
        assert p["reviewer"]["can_decide"] is False and "own" in p["reviewer"]["blocked_reason"]
        denied = await _approve(client, approver_token, action_id, p["verified"]["input_sha256"])
        assert denied.status_code == 403
        # another reviewer (the admin) can
        p2 = await _review(client, admin_token, action_id)
        assert (await _approve(client, admin_token, action_id, p2["verified"]["input_sha256"])).status_code == 200

    @pytest.mark.asyncio
    async def test_owner_may_still_deny(self, client, admin_token, approver_token, org_and_users, db_session):
        await _gate(client, admin_token)
        a = await _agent(client, admin_token)
        await _set_owner(db_session, a["id"], org_and_users["approver"].id)
        action_id = await _pending(client, admin_token, a, {"amount": 10})
        r = await client.post(f"{A}/actions/{action_id}/deny", json={"reason": "no"}, headers=auth_headers(approver_token))
        assert r.status_code == 200 and r.json()["policy_check_result"] == "denied"


class TestExpiryAndConfirmation:
    @pytest.mark.asyncio
    async def test_stale_approvals_expire(self, client, admin_token, approver_token, monkeypatch):
        await _gate(client, admin_token)
        a = await _agent(client, admin_token)
        action_id = await _pending(client, admin_token, a, {"amount": 10})
        monkeypatch.setattr(approval_module, "APPROVAL_TTL_HOURS", 0)
        p = await _review(client, approver_token, action_id)
        assert p["action"]["status"] == "denied" and p["decision"]["decision"] == "expired"
        assert (await _approve(client, approver_token, action_id, p["verified"]["input_sha256"])).status_code == 409
        pend = await client.get(f"{A}/approvals/pending", headers=auth_headers(approver_token))
        assert all(x["id"] != action_id for x in pend.json())

    @pytest.mark.asyncio
    async def test_high_risk_system_needs_typed_confirmation(self, client, admin_token, approver_token):
        await _gate(client, admin_token)
        a = await _agent(client, admin_token)
        inv = await client.get("/api/v1/inventory/", params={"limit": 100}, headers=auth_headers(admin_token))
        system = next(i for i in inv.json()["items"] if i["source_key"] == f"agent:{a['id']}")
        await client.patch(f"/api/v1/inventory/{system['id']}", json={"domain": "employment"},
                           headers=auth_headers(admin_token))
        action_id = await _pending(client, admin_token, a, {"amount": 10})
        p = await _review(client, approver_token, action_id)
        assert p["reviewer"]["requires_typed_confirmation"] and "high_risk_system" in p["reviewer"]["flags"]
        sha = p["verified"]["input_sha256"]
        assert (await _approve(client, approver_token, action_id, sha)).status_code == 400
        assert (await _approve(client, approver_token, action_id, sha, "wrong")).status_code == 400
        assert (await _approve(client, approver_token, action_id, sha, "payments.charge")).status_code == 200

    @pytest.mark.asyncio
    async def test_approval_fatigue_triggers_confirmation(self, client, admin_token, approver_token, monkeypatch):
        monkeypatch.setattr(approval_module, "FATIGUE_THRESHOLD", 2)
        await _gate(client, admin_token)
        a = await _agent(client, admin_token)
        for i in range(2):
            aid = await _pending(client, admin_token, a, {"amount": i})
            assert (await _approve(client, approver_token, aid,
                                   (await _review(client, approver_token, aid))["verified"]["input_sha256"])).status_code == 200
        aid = await _pending(client, admin_token, a, {"amount": 99})
        p = await _review(client, approver_token, aid)
        assert "fatigue" in p["reviewer"]["flags"]
        assert (await _approve(client, approver_token, aid, p["verified"]["input_sha256"])).status_code == 400
