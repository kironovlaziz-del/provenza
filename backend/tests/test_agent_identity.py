"""
Agent identity: agents authenticate with their own key (X-Agent-Key), act
only as themselves, never reach admin/UI endpoints; rotation with grace,
revocation, and the require_agent_key organization setting.
"""

import secrets
from datetime import datetime, timezone

import pytest

from app.core.agent_signing import content_hash, sign_payload
from tests.conftest import auth_headers

A = "/api/v1/agents"
ID = "/api/v1/agent-identity"


async def _agent(client, token):
    r = await client.post(
        f"{A}/register",
        json={"name": "id-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
              "allowed_tools": ["kb.search"], "allowed_models": [], "max_delegation_depth": 2},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("api_key"), "registration must return the agent's api_key once"
    return body


def K(agent_or_key):
    key = agent_or_key if isinstance(agent_or_key, str) else agent_or_key["api_key"]
    return {"X-Agent-Key": key}


async def _settings(client, token, require=False, grace=60):
    r = await client.put(ID + "/settings", json={"require_agent_key": require, "rotation_grace_minutes": grace},
                         headers=auth_headers(token))
    assert r.status_code == 200, r.text


async def _check(client, headers, agent_id):
    return await client.post(f"{A}/actions/check",
                             json={"agent_id": agent_id, "chain_id": None, "tool_name": "kb.search", "input": {}},
                             headers=headers)


class TestAuthentication:
    @pytest.mark.asyncio
    async def test_agent_key_acts_as_itself(self, client, admin_token):
        await _settings(client, admin_token)
        a = await _agent(client, admin_token)
        r = await _check(client, K(a), a["id"])
        assert r.status_code == 200 and r.json()["decision"] == "allowed", r.text
        me = await client.get(ID + "/me", headers=K(a))
        assert me.status_code == 200 and me.json()["agent_id"] == a["id"]

    @pytest.mark.asyncio
    async def test_impersonation_is_refused_and_recorded(self, client, admin_token):
        await _settings(client, admin_token)
        a, b = await _agent(client, admin_token), await _agent(client, admin_token)
        r = await _check(client, K(a), b["id"])
        assert r.status_code == 403 and "agent_mismatch" in r.text
        inc = await client.get(f"{A}/incidents/", params={"incident_type": "agent_impersonation_attempt"},
                               headers=auth_headers(admin_token))
        items = inc.json()["items"] if isinstance(inc.json(), dict) else inc.json()
        assert any(i["agent_id"] == a["id"] for i in items)

    @pytest.mark.asyncio
    async def test_impersonation_in_a2a_envelope(self, client, admin_token):
        a, b = await _agent(client, admin_token), await _agent(client, admin_token)
        env = {"type": "a2a_message", "from_agent_id": b["id"], "to_agent_id": a["id"], "chain_id": None,
               "message_type": "x", "payload_sha256": content_hash("hi"), "nonce": secrets.token_hex(16),
               "issued_at": datetime.now(timezone.utc).isoformat()}
        r = await client.post("/api/v1/a2a/send", json={"envelope": env, "signature": sign_payload(env, b["private_key"]),
                                                        "payload": "hi"}, headers=K(a))
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_delegate_path_binding(self, client, admin_token):
        a, b = await _agent(client, admin_token), await _agent(client, admin_token)
        r = await client.post(f"{A}/{b['id']}/delegate", json={}, headers=K(a))
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_agent_key_never_opens_admin_or_ui_endpoints(self, client, admin_token):
        a = await _agent(client, admin_token)
        for method, path, body in (("GET", f"{A}/", None), ("GET", ID + "/", None),
                                   ("PUT", "/api/v1/injection/settings", {"mode": "off", "threshold": 60}),
                                   ("POST", f"{ID}/agents/{a['id']}/rotate", None)):
            r = await client.request(method, path, json=body, headers=K(a))
            assert r.status_code in (401, 403), (path, r.status_code, r.text)

    @pytest.mark.asyncio
    async def test_bad_key_and_no_credentials(self, client):
        assert (await _check(client, K("nope-" + secrets.token_hex(8)), 1)).status_code == 401
        assert (await _check(client, {}, 1)).status_code == 401


class TestKeyLifecycle:
    @pytest.mark.asyncio
    async def test_rotation_with_grace(self, client, admin_token):
        await _settings(client, admin_token, grace=60)
        a = await _agent(client, admin_token)
        r = await client.post(f"{ID}/agents/{a['id']}/rotate", headers=auth_headers(admin_token))
        assert r.status_code == 200 and r.json()["previous_key_valid_until"], r.text
        new = r.json()["api_key"]
        assert (await _check(client, K(a), a["id"])).status_code == 200      # old key, inside grace
        assert (await _check(client, K(new), a["id"])).status_code == 200

    @pytest.mark.asyncio
    async def test_rotation_without_grace(self, client, admin_token):
        await _settings(client, admin_token, grace=0)
        a = await _agent(client, admin_token)
        new = (await client.post(f"{ID}/agents/{a['id']}/rotate", headers=auth_headers(admin_token))).json()["api_key"]
        assert (await _check(client, K(a), a["id"])).status_code == 401
        assert (await _check(client, K(new), a["id"])).status_code == 200

    @pytest.mark.asyncio
    async def test_revoke_then_reissue(self, client, admin_token):
        a = await _agent(client, admin_token)
        assert (await client.post(f"{ID}/agents/{a['id']}/revoke", headers=auth_headers(admin_token))).status_code == 200
        assert (await _check(client, K(a), a["id"])).status_code == 401
        assert (await client.post(f"{ID}/agents/{a['id']}/revoke", headers=auth_headers(admin_token))).status_code == 409
        new = (await client.post(f"{ID}/agents/{a['id']}/rotate", headers=auth_headers(admin_token))).json()["api_key"]
        assert (await _check(client, K(new), a["id"])).status_code == 200
        row = next(x for x in (await client.get(ID + "/", headers=auth_headers(admin_token))).json()["agents"]
                   if x["agent_id"] == a["id"])
        assert row["key_revoked_at"] is None and row["key_last_used_at"]


class TestRequireAgentKey:
    @pytest.mark.asyncio
    async def test_user_session_cannot_act_for_agents(self, client, admin_token, approver_token):
        a = await _agent(client, admin_token)
        await _settings(client, admin_token, require=True)
        try:
            r = await _check(client, auth_headers(admin_token), a["id"])
            assert r.status_code == 403 and "agent_key_required" in r.text
            assert (await _check(client, K(a), a["id"])).status_code == 200
            # the UI keeps working: listing, the tester, settings
            assert (await client.get(f"{A}/", headers=auth_headers(admin_token))).status_code == 200
            assert (await client.post("/api/v1/injection/scan", json={"text": "hi"},
                                      headers=auth_headers(approver_token))).status_code == 200
        finally:
            await _settings(client, admin_token, require=False)

    @pytest.mark.asyncio
    async def test_settings_validation_and_roles(self, client, admin_token, approver_token):
        bad = {"require_agent_key": False, "rotation_grace_minutes": 5000}
        assert (await client.put(ID + "/settings", json=bad, headers=auth_headers(admin_token))).status_code == 422
        ok = {"require_agent_key": False, "rotation_grace_minutes": 60}
        assert (await client.put(ID + "/settings", json=ok, headers=auth_headers(approver_token))).status_code == 403
        assert (await client.get(ID + "/", headers=auth_headers(approver_token))).status_code == 200
