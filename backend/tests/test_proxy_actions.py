"""
Gateway actions an egress proxy executes (app/pvp/proxy_actions.py): the
proxy brings the agent's request, the server judges it as its gateway would
- a refusal is recorded at once - and reserves an allowed check for that
proxy only; the proxy reports what it did (metadata, its receipt), or that
it refused after all under the signed policy. Here for HTTP tools; the
proxy itself is tested in proxy/internal/egress and test_egress_proxy_go.py.
"""

import pytest
from sqlalchemy import select

from app.core.agent_signing import content_hash
from app.models.agent_action import AgentAction
from app.models.egress_proxy import EgressRedemption
from app.models.http_tool import HttpTool
from tests.conftest import auth_headers
from tests.test_proxy_witness import ProxyKey
from tests.test_sealed_credentials import E, P, Proxy, _proxy

T = "/api/v1/http-tools"


async def _tool(client, token, db_session, source="sealed"):
    r = await client.post(T, json={"name": "crm.set_tier", "method": "PATCH",
                                   "url": "https://crm.example/customers/{id}",
                                   "input_schema": {"type": "object", "required": ["id"],
                                                    "properties": {"id": {"type": ["string", "integer"]},
                                                                   "tier": {"type": "string"}}}},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    row = await db_session.get(HttpTool, r.json()["id"])
    row.credential_source = source
    await db_session.commit()
    return r.json()


async def _agent(client, token, tools=("crm.set_tier",)):
    r = await client.post("/api/v1/agents/register", json={
        "name": "pa-bot", "agent_type": "custom", "capabilities": [], "allowed_tools": list(tools),
        "allowed_models": [], "max_delegation_depth": 1}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _call(client, agent, args):
    headers = {"X-Agent-Key": agent["api_key"]}
    return client._signed({"agent_id": agent["id"], "tool_name": "crm.set_tier", "input": args}, headers), headers


async def _plan(client, proxy: Proxy, agent, args=None):
    body, headers = _call(client, agent, args if args is not None else {"id": "c/42", "tier": "gold"})
    return await client.post(f"{P}/http-tools/plan", json=body, headers={**headers, **proxy.headers})


@pytest.mark.asyncio
async def test_the_proxy_gets_a_plan_and_records_what_it_did(client, admin_token, db_session):
    proxy = await _proxy(client, admin_token)
    tool = await _tool(client, admin_token, db_session)
    agent = await _agent(client, admin_token)
    r = await _plan(client, proxy, agent)
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["decision"] == "allowed" and plan["action_type"] == "tool_call"
    assert plan["definition"]["url"] == "https://crm.example/customers/{id}" and plan["digest"] == tool["digest"]
    assert plan["arguments"] == {"id": "c/42", "tier": "gold"}
    assert plan["input_sha256"] == content_hash(plan["arguments"]) and plan["permit"]
    assert plan["credential"] == {"object": "http_tool", "id": tool["id"], "source": "sealed", "header": "Authorization"}
    # reserved for this proxy: another proxy cannot complete it, it cannot be planned twice
    other = await _proxy(client, admin_token, "host-b")
    done = {"check_id": plan["check_id"], "status": 200, "output": {"status": 200, "response_bytes": 28,
                                                                     "response_sha256": "a" * 64}}
    assert (await client.post(f"{P}/complete", json=done, headers=other.headers)).status_code == 404
    r = await client.post(f"{P}/complete", json=done, headers=proxy.headers)
    assert r.status_code == 200, r.text
    action = await db_session.get(AgentAction, r.json()["action_id"])
    assert (action.executed_by, action.action_type, action.tool_name, action.policy_check_result) == (
        "egress_proxy", "tool_call", "crm.set_tier", "allowed")
    assert action.input_data == {"id": "c/42", "tier": "gold"} and action.output_data["response_bytes"] == 28
    assert (await client.post(f"{P}/complete", json=done, headers=proxy.headers)).status_code == 409


@pytest.mark.asyncio
async def test_a_refusal_is_recorded_at_plan_time(client, admin_token, db_session):
    proxy = await _proxy(client, admin_token)
    await _tool(client, admin_token, db_session)
    agent = await _agent(client, admin_token, tools=())
    plan = (await _plan(client, proxy, agent)).json()
    assert plan["decision"] == "denied" and "check_id" not in plan and "definition" not in plan
    action = await db_session.get(AgentAction, plan["action_id"])
    assert action.executed_by == "egress_proxy" and action.policy_check_result == "denied"
    # arguments the tool's schema refuses
    agent = await _agent(client, admin_token)
    plan = (await _plan(client, proxy, agent, {"tier": "gold"})).json()
    assert plan["decision"] == "denied" and "missing argument 'id'" in plan["reason"]
    assert (await db_session.execute(select(EgressRedemption))).scalars().all() == []


@pytest.mark.asyncio
async def test_the_proxy_refusing_after_the_plan_is_recorded_with_its_receipt(client, admin_token, db_session):
    proxy = await _proxy(client, admin_token)
    await _tool(client, admin_token, db_session)
    agent = await _agent(client, admin_token)
    key = ProxyKey()
    key.key, key.public = proxy.signing, proxy.public
    plan = (await _plan(client, proxy, agent)).json()
    receipt = key.receipt(check_id=plan["check_id"], agent_id=agent["id"], chain_id=None, action_type="tool_call",
                          tool_name="crm.set_tier", input_sha256=plan["input_sha256"],
                          output_sha256=content_hash(None), decision="denied")
    r = await client.post(f"{P}/complete", json={"check_id": plan["check_id"], "status": 0, "receipt": receipt,
                                                 "enforcement": {"decision": "denied", "reason": "not signed"}},
                          headers=proxy.headers)
    assert r.status_code == 200, r.text
    action = await db_session.get(AgentAction, r.json()["action_id"])
    assert action.policy_check_result == "denied" and action.output_data is None
    assert action.reason == "refused by the egress proxy under the signed policy: not signed"
    assert action.witness and action.witness["statement"]["decision"] == "denied"


@pytest.mark.asyncio
async def test_the_plan_needs_the_proxy_and_the_agents_own_key(client, admin_token, db_session):
    proxy = await _proxy(client, admin_token)
    await _tool(client, admin_token, db_session)
    agent = await _agent(client, admin_token)
    body, headers = _call(client, agent, {"id": 1})
    assert (await client.post(f"{P}/http-tools/plan", json=body, headers=headers)).status_code == 401
    r = await client.post(f"{P}/http-tools/plan", json=body, headers=proxy.headers)
    assert r.status_code == 401 and r.json()["detail"] == "egress.agent_key_invalid"
    # another agent's request with this agent's key
    other = await _agent(client, admin_token)
    r = await client.post(f"{P}/http-tools/plan", json=body,
                          headers={**proxy.headers, "X-Agent-Key": other["api_key"]})
    assert r.status_code == 403
    # an output that is not metadata
    plan = (await _plan(client, proxy, agent)).json()
    big = {"check_id": plan["check_id"], "status": 200, "output": {"body": "x" * 5000}}
    assert (await client.post(f"{P}/complete", json=big, headers=proxy.headers)).status_code == 422


@pytest.mark.asyncio
async def test_the_proxy_keys_are_listed_for_sealing_only_with_their_signature(client, admin_token):
    await _proxy(client, admin_token)
    keys = (await client.get(f"{E}/proxy-keys", headers=auth_headers(admin_token))).json()
    assert keys and all(k["encryption_key_signature"] for k in keys)


async def _llm(client, token, db_session, models=("gpt-p",)):
    from app.models.ai_provider import AIProvider

    p = (await client.post("/api/v1/providers/", json={"name": "keyed", "type": "openai"},
                           headers=auth_headers(token))).json()
    row = await db_session.get(AIProvider, p["id"])
    row.credential_source = "sealed"
    await db_session.commit()
    assert (await client.post("/api/v1/gateway/routes", json={"model": "gpt-p", "provider_id": p["id"]},
                              headers=auth_headers(token))).status_code == 200
    r = await client.post("/api/v1/agents/register", json={
        "name": "llm-bot", "agent_type": "custom", "capabilities": [], "allowed_tools": [],
        "allowed_models": list(models), "max_delegation_depth": 1}, headers=auth_headers(token))
    return p, r.json()


META = {"model": "gpt-p", "messages": 2, "messages_sha256": "c" * 64, "max_tokens": 999999}


@pytest.mark.asyncio
async def test_an_llm_call_is_planned_from_metadata_and_recorded_with_its_gateway_call(client, admin_token,
                                                                                         db_session):
    from app.models.gateway import GatewayCall

    proxy = await _proxy(client, admin_token)
    provider, agent = await _llm(client, admin_token, db_session)
    r = await client.post(f"{P}/llm/plan", json=META, headers={**proxy.headers, "X-Agent-Key": agent["api_key"]})
    plan = r.json()
    assert plan["decision"] == "allowed", plan
    assert plan["input"] == {"model": "gpt-p", "provider": "keyed", "messages": 2, "messages_sha256": "c" * 64,
                             "max_tokens": 4096}      # capped by the gateway
    assert plan["provider"]["type"] == "openai" and plan["credential"]["source"] == "sealed"
    assert plan["upstream_model"] == "gpt-p" and plan["self_hosted_only"] is False
    # a message's content is not even accepted
    bad = await client.post(f"{P}/llm/plan", json={**META, "content": "x"},
                            headers={**proxy.headers, "X-Agent-Key": agent["api_key"]})
    assert bad.status_code == 422
    done = await client.post(f"{P}/complete", json={"check_id": plan["check_id"], "status": 200, "duration_ms": 120,
                                                    "output": {"finish_reason": "stop", "prompt_tokens": 9,
                                                               "completion_tokens": 3, "response_sha256": "d" * 64}},
                             headers=proxy.headers)
    assert done.status_code == 200 and done.json()["call_id"], done.text
    call = await db_session.get(GatewayCall, done.json()["call_id"])
    assert (call.status, call.completion_tokens, call.latency_ms, call.provider_id, call.action_id) == (
        "completed", 3, 120, provider["id"], done.json()["action_id"])


@pytest.mark.asyncio
async def test_a_refused_llm_call_comes_back_as_the_gateways_error(client, admin_token, db_session):
    proxy = await _proxy(client, admin_token)
    _, agent = await _llm(client, admin_token, db_session, models=())
    r = await client.post(f"{P}/llm/plan", json=META, headers={**proxy.headers, "X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200
    out = r.json()
    assert out["decision"] == "refused" and out["status"] == 403 and out["error"]["code"] == "model_not_allowed"
    # the same model straight to this server's gateway, by an agent that may use it: refused, no key here
    allowed = (await client.post("/api/v1/agents/register", json={
        "name": "llm-bot-2", "agent_type": "custom", "capabilities": [], "allowed_tools": [],
        "allowed_models": ["gpt-p"], "max_delegation_depth": 1}, headers=auth_headers(admin_token))).json()
    direct = await client.post("/api/v1/gateway/v1/chat/completions", json={
        "model": "gpt-p", "messages": [{"role": "user", "content": "x"}]}, headers={"X-Agent-Key": allowed["api_key"]})
    assert direct.status_code == 409 and direct.json()["error"]["code"] == "credential_at_proxy"


@pytest.mark.asyncio
async def test_an_mcp_server_behind_the_proxies_is_synced_and_called_by_them(client, admin_token, db_session):
    from app.models.mcp import MCPServer, MCPTool
    from app.pvp.mcp_gateway import definition_of, digest_of

    proxy = await _proxy(client, admin_token)
    created = (await client.post("/api/v1/mcp-servers", json={"slug": "orders", "name": "Orders",
                                                              "url": "https://mcp.example/mcp"},
                                 headers=auth_headers(admin_token))).json()
    # the server's own credential-less upstream is not the proxies' to sync
    r = await client.post(f"{P}/mcp/sync", json={"server_id": created["id"], "tools": []}, headers=proxy.headers)
    assert r.status_code == 404
    row = await db_session.get(MCPServer, created["id"])
    row.credential_source = "sealed"
    await db_session.commit()
    cfg = (await client.get(f"{P}/config", headers=proxy.headers)).json()
    assert [s["slug"] for s in cfg["mcp_servers"]] == ["orders"]
    tool = {"name": "lookup", "description": "Look up", "inputSchema": {"type": "object"}}
    r = await client.post(f"{P}/mcp/sync", json={"server_id": row.id, "tools": [tool], "detected_version": "2026-07-28"},
                          headers=proxy.headers)
    assert r.status_code == 200 and r.json()["added"] == 1, r.text
    t = (await db_session.execute(select(MCPTool).where(MCPTool.server_id == row.id))).scalar_one()
    assert (await client.post(f"/api/v1/mcp-servers/{row.id}/tools/{t.id}/approve",
                              headers=auth_headers(admin_token))).status_code == 200
    agent = await _agent(client, admin_token, tools=("orders.lookup",))
    h = {**proxy.headers, "X-Agent-Key": agent["api_key"]}
    live = digest_of(definition_of(tool))
    out = (await client.post(f"{P}/mcp/plan", json={"name": "orders.lookup", "arguments": {"id": 7},
                                                    "live_digest": live}, headers=h)).json()
    assert out["decision"] == "allowed" and out["upstream_name"] == "lookup" and out["pinned_digest"] == live
    assert out["credential"] == {"object": "mcp_server", "id": row.id, "source": "sealed", "header": "Authorization"}
    # the definition the proxy sees upstream is not the approved one: refused and recorded (the
    # Tool Registry entry drifts, so the tool is not served until it is approved again)
    out = (await client.post(f"{P}/mcp/plan", json={"name": "orders.lookup", "arguments": {}, "live_digest": "e" * 64},
                             headers=h)).json()
    assert out["decision"] == "refused" and "Refused by Provenza" in out["result"]["content"][0]["text"]
    unknown = (await client.post(f"{P}/mcp/plan", json={"name": "orders.nope", "arguments": {}}, headers=h)).json()
    assert unknown["decision"] == "error" and unknown["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_an_a2a_peer_behind_the_proxies_is_synced_and_planned_by_them(client, admin_token, db_session,
                                                                            monkeypatch):
    from app.core.config import settings
    from app.models.a2a_gateway import A2APeer

    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "")
    proxy = await _proxy(client, admin_token)
    created = (await client.post("/api/v1/a2a-peers", json={
        "slug": "helper", "name": "Helper", "card_url": "https://helper.example/card"},
        headers=auth_headers(admin_token))).json()
    r = await client.post(f"{P}/a2a/sync", json={"peer_id": created["id"], "card": {}}, headers=proxy.headers)
    assert r.status_code == 404        # a peer this server reaches itself
    row = await db_session.get(A2APeer, created["id"])
    row.credential_source = "sealed"
    await db_session.commit()
    card = {"name": "Helper", "description": "d", "version": "1", "capabilities": {}, "skills": [],
            "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
            "supportedInterfaces": [{"url": "https://helper.example/a2a", "protocolBinding": "JSONRPC",
                                     "protocolVersion": "1.0"}]}
    r = await client.post(f"{P}/a2a/sync", json={"peer_id": row.id, "card": card}, headers=proxy.headers)
    assert r.status_code == 200 and r.json()["synced"] and r.json()["status"] == "pending", r.text
    assert (await client.post(f"/api/v1/a2a-peers/{row.id}/approve",
                              headers=auth_headers(admin_token))).status_code == 200
    agent = await _agent(client, admin_token, tools=("a2a.helper",))
    h = {**proxy.headers, "X-Agent-Key": agent["api_key"]}
    send = {"jsonrpc": "2.0", "id": 5, "method": "SendMessage", "params": {"message": {
        "messageId": "m1", "role": "ROLE_USER", "parts": [{"text": "hi"}]}}}
    plan = (await client.post(f"{P}/a2a/plan", json={"slug": "helper", "body": send, "a2a_version": "1.0",
                                                     "live_card": card}, headers=h)).json()
    assert plan["decision"] == "allowed" and plan["request"]["url"] == "https://helper.example/a2a"
    assert plan["request"]["body"]["method"] == "SendMessage" and plan["canonical"] == "SendMessage"
    # a changed card: refused and recorded, answered as the gateway answers
    other = {**card, "description": "changed"}
    out = (await client.post(f"{P}/a2a/plan", json={"slug": "helper", "body": send, "a2a_version": "1.0",
                                                    "live_card": other}, headers=h)).json()
    assert out["decision"] == "reply" and out["response"]["error"]["code"] == -32000
    # a version the gateway does not speak
    out = (await client.post(f"{P}/a2a/plan", json={"slug": "helper", "body": send, "a2a_version": "9"},
                             headers=h)).json()
    assert out["decision"] == "reply" and "Version not supported" in out["response"]["error"]["message"]
