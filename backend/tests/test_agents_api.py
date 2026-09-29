"""
API-level tests for the agent-governance endpoints (app/api/agents.py),
exercised over HTTP through the test client.

Focus areas beyond the happy path:
  - RBAC: register/kill/policy/approve are admin (or approver) only
  - org isolation: one org cannot see or touch another org's agents
  - the full delegate -> check -> approve flow over the wire
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient

from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers
from tests.delegation_helpers import action_record_body, delegation_body


async def _register_agent(client, token, **over):
    payload = {
        "name": "api-agent",
        "agent_type": "custom",
        "capabilities": ["read", "write"],
        "allowed_tools": ["openai.chat", "db.read"],
        "allowed_models": ["gpt-4o-mini"],
        "max_delegation_depth": 3,
    }
    payload.update(over)
    resp = await client.post("/api/v1/agents/register", json=payload, headers=auth_headers(token))
    return resp


class TestRegisterRBAC:
    @pytest.mark.asyncio
    async def test_admin_can_register(self, client, admin_token):
        resp = await _register_agent(client, admin_token)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # secrets returned once
        assert body["api_key"] and body["private_key"] and body["public_key"]

    @pytest.mark.asyncio
    async def test_non_admin_cannot_register(self, client, approver_token):
        # approver is not admin -> register is admin-only
        resp = await _register_agent(client, approver_token)
        assert resp.status_code == 403


class TestListAndGet:
    @pytest.mark.asyncio
    async def test_list_and_get(self, client, admin_token):
        reg = await _register_agent(client, admin_token, name="listme")
        agent_id = reg.json()["id"]
        lst = await client.get("/api/v1/agents/", headers=auth_headers(admin_token))
        assert lst.status_code == 200
        assert any(a["id"] == agent_id for a in lst.json()["items"])
        one = await client.get(f"/api/v1/agents/{agent_id}", headers=auth_headers(admin_token))
        assert one.status_code == 200 and one.json()["name"] == "listme"

    @pytest.mark.asyncio
    async def test_get_missing_is_404(self, client, admin_token):
        resp = await client.get("/api/v1/agents/999999", headers=auth_headers(admin_token))
        assert resp.status_code == 404


class TestOrgIsolation:
    @pytest.mark.asyncio
    async def test_other_org_cannot_get_agent(self, client, db_session, admin_token):
        # agent created in the default test org
        reg = await _register_agent(client, admin_token, name="secret-agent")
        agent_id = reg.json()["id"]

        # a second org + its admin, logging in over the same client
        other = await _create_org_with_admin_and_approver(
            db_session, org_slug="other-org", admin_email="other@x.com", approver_email="other2@x.com"
        )
        other_token = await _login(client, "other-org", "other@x.com", other["password"])

        # other org must NOT see or fetch the first org's agent
        resp = await client.get(f"/api/v1/agents/{agent_id}", headers=auth_headers(other_token))
        assert resp.status_code == 404
        lst = await client.get("/api/v1/agents/", headers=auth_headers(other_token))
        assert all(a["id"] != agent_id for a in lst.json()["items"])


class TestKillRBAC:
    @pytest.mark.asyncio
    async def test_admin_can_kill(self, client, admin_token):
        reg = await _register_agent(client, admin_token, name="killme")
        agent_id = reg.json()["id"]
        resp = await client.post(
            f"/api/v1/agents/{agent_id}/kill",
            json={"reason": "test", "cascade": True},
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 200
        assert agent_id in resp.json()["agents_stopped"]

    @pytest.mark.asyncio
    async def test_non_admin_cannot_kill(self, client, admin_token, approver_token):
        reg = await _register_agent(client, admin_token, name="killme2")
        agent_id = reg.json()["id"]
        resp = await client.post(
            f"/api/v1/agents/{agent_id}/kill",
            json={"reason": "x", "cascade": True},
            headers=auth_headers(approver_token),
        )
        assert resp.status_code == 403


class TestDelegateAndActionsFlow:
    @pytest.mark.asyncio
    async def test_delegate_then_check(self, client, admin_token):
        a = (await _register_agent(client, admin_token, name="root", capabilities=["read", "write"])).json()
        b = (await _register_agent(client, admin_token, name="child", capabilities=["read"])).json()

        # legit delegation (subset)
        deleg = await client.post(
            f"/api/v1/agents/{a['id']}/delegate",
            json=delegation_body(a, b["id"], "t", ["read"]),
            headers=auth_headers(admin_token),
        )
        assert deleg.status_code == 200, deleg.text
        chain_id = deleg.json()["chain_id"]

        # escalation is rejected over the wire
        bad = await client.post(
            f"/api/v1/agents/{a['id']}/delegate",
            json=delegation_body(a, b["id"], "bad", ["admin"]),
            headers=auth_headers(admin_token),
        )
        assert bad.status_code == 403

        # action check: disallowed tool -> denied
        chk = await client.post(
            "/api/v1/agents/actions/check",
            json={"agent_id": b["id"], "chain_id": chain_id, "tool_name": "stripe.charge", "input": {}},
            headers=auth_headers(admin_token),
        )
        assert chk.status_code == 200 and chk.json()["decision"] == "denied"

    @pytest.mark.asyncio
    async def test_pending_approval_flow_over_api(self, client, admin_token):
        agent = (await _register_agent(client, admin_token, name="worker")).json()
        # policy requiring approval for openai.chat
        pol = await client.post(
            "/api/v1/agents/policies/",
            json={"name": "gate", "rules": {"require_approval_tools": ["openai.chat"]}, "priority": 100},
            headers=auth_headers(admin_token),
        )
        assert pol.status_code == 200
        # check first -> pending_approval + a single-use check_id
        chk = await client.post(
            "/api/v1/agents/actions/check",
            json={"agent_id": agent["id"], "tool_name": "openai.chat", "input": {"model": "gpt-4o-mini"}},
            headers=auth_headers(admin_token),
        )
        assert chk.status_code == 200 and chk.json()["decision"] == "pending_approval"
        # record the action against that check, signed by the agent
        rec = await client.post(
            "/api/v1/agents/actions/record",
            json=action_record_body(agent, chk.json()["check_id"], "openai.chat", {"model": "gpt-4o-mini"}),
            headers=auth_headers(admin_token),
        )
        assert rec.status_code == 200
        action_id = rec.json()["id"]
        assert rec.json()["policy_check_result"] == "pending_approval"
        # approve it
        appr = await client.post(
            f"/api/v1/agents/actions/{action_id}/approve", headers=auth_headers(admin_token)
        )
        assert appr.status_code == 200 and appr.json()["policy_check_result"] == "allowed"


class TestPolicyRBAC:
    @pytest.mark.asyncio
    async def test_non_admin_cannot_create_policy(self, client, approver_token):
        resp = await client.post(
            "/api/v1/agents/policies/",
            json={"name": "x", "rules": {}, "priority": 100},
            headers=auth_headers(approver_token),
        )
        assert resp.status_code == 403
