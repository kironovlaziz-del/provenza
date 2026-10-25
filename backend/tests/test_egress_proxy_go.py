# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The egress proxy (proxy/, Go) against THIS server, end to end: the real
binary, the real endpoints, a fake upstream. Both modes:

  mediated  the agent sends its key; the proxy checks, redeems, forwards with
            the credential sealed to it - this server cannot open it - and completes;
  SDK       the Python SDK's proxy_check, then the proxy redeems that check.

The server is reached over real HTTP through a small bridge to the ASGI app,
so the test keeps its one database transaction. Needs the go command;
a proxy that does not build is a failure, never a skip.
"""

import asyncio
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.models.agent_action import AgentAction
from app.models.egress_proxy import EgressRoute
from app.models.ai_provider import AIProvider
from app.models.gateway import GatewayCall
from app.models.a2a_gateway import A2APeer, A2ATask
from app.models.agent import Agent
from app.models.http_tool import HttpTool
from app.models.mcp import MCPServer, MCPTool
from app.pvp.http_tools import HttpToolGateway
from app.pvp import sealed
from app.services import credentials
from tests import signer
from tests.conftest import auth_headers

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from provenza.proxy import descriptor  # noqa: E402

SECRET = "Bearer sk_live_go_" + "y" * 16


@pytest.fixture(scope="module")
def proxy_binary(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("needs the go command")
    binary = tmp_path_factory.mktemp("proxy") / "provenza-proxy"
    build = subprocess.run(["go", "build", "-o", str(binary), "."], cwd=ROOT / "proxy", capture_output=True,
                           text=True, timeout=600)
    assert build.returncode == 0, f"the proxy does not build: {build.stderr[-500:]}"
    return binary


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _http_server(handle):
    """A minimal HTTP/1.1 server in this event loop: handle(method, target, headers, body) -> (status, headers, body)."""
    async def serve(reader, writer):
        try:
            line = (await reader.readline()).decode()
            method, target, _ = line.split(" ", 2)
            headers = {}
            while (h := (await reader.readline()).decode().rstrip("\r\n")):
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
            size = int(next((v for k, v in headers.items() if k.lower() == "content-length"), "0"))
            body = await reader.readexactly(size) if size else b""
            status, out_headers, out = await handle(method, target, headers, body)
            head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(out)}\r\nConnection: close\r\n"
            head += "".join(f"{k}: {v}\r\n" for k, v in out_headers.items())
            writer.write(head.encode() + b"\r\n" + out)
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    return server, f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"


@pytest.mark.asyncio
async def test_the_go_proxy_against_this_server(client, admin_token, db_session, tmp_path, proxy_binary, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "127.0.0.1")   # the fake peer's endpoint
    seen = []

    async def upstream(method, target, headers, body):
        seen.append((method, target, headers, body))
        if target.startswith("/customers/"):
            return 200, {"Content-Type": "application/json"}, b'{"customer":{"tier":"gold"}}'
        if target in ("/peer-card", "/a2a"):
            if headers.get("Authorization") != "Bearer peer_" + "p" * 20:
                return 401, {}, b""
            if method == "GET":
                return 200, {"Content-Type": "application/json"}, json.dumps({
                    "name": "Helper", "description": "Summarizes", "version": "1", "capabilities": {},
                    "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"], "skills": [],
                    "supportedInterfaces": [{"url": up_base[0] + "/a2a", "protocolBinding": "JSONRPC",
                                             "protocolVersion": "1.0"}]}).encode()
            msg = json.loads(body)
            task = {"id": "task-77", "contextId": "ctx-1", "status": {"state": "TASK_STATE_COMPLETED"},
                    "artifacts": [{"artifactId": "a1", "parts": [{"text": "the summary"}]}]}
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"jsonrpc": "2.0", "id": msg["id"], "result": {"task": task}}).encode()
        if target == "/mcp":
            msg = json.loads(body)
            if headers.get("Authorization") != "Bearer mcp_" + "m" * 20:
                return 401, {}, b""
            result = {"server/discover": {"supportedVersions": ["2026-07-28"]},
                      "tools/list": {"tools": [{"name": "lookup", "description": "Look up an order",
                                                "inputSchema": {"type": "object"}}]},
                      "tools/call": {"content": [{"type": "text", "text": "order 7: shipped"}]}}.get(msg["method"])
            if result is None:
                return 404, {}, b""
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"jsonrpc": "2.0", "id": msg.get("id"), "result": result}).encode()
        if target == "/v1/chat/completions":
            return 200, {"Content-Type": "application/json"}, json.dumps({
                "choices": [{"message": {"role": "assistant", "content": "the answer"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 3}}).encode()
        return 201, {"Content-Type": "application/json"}, b'{"id":"ch_1"}'

    async def bridge(method, target, headers, body):   # real HTTP -> this test's app and transaction
        keep = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length", "connection")}
        r = await client.request(method, target, headers=keep, content=body)
        return r.status_code, {"Content-Type": r.headers.get("content-type", "application/json")}, r.content

    up_base = []
    up_server, up_url = await _http_server(upstream)
    up_base.append(up_url)
    api_server, api_url = await _http_server(bridge)

    r = await client.post("/api/v1/egress/routes", json={
        "slug": "stripe", "name": "Stripe", "upstream_url": "https://api.stripe.com", "methods": ["GET", "POST"],
        "path_prefixes": ["/v1/charges"], "credential_source": "sealed"},
        headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    route = await db_session.get(EgressRoute, r.json()["id"])
    route.upstream_url = up_url        # the API refuses loopback upstreams (SSRF); the fake one is local
    await db_session.flush()
    proxy = (await client.post("/api/v1/egress/proxies", json={"name": "go"}, headers=auth_headers(admin_token))).json()
    agent = (await client.post("/api/v1/agents/register", json={
        "name": "go-proxy-bot", "agent_type": "custom", "capabilities": ["pay"],
        "allowed_tools": ["proxy.stripe", "crm.set_tier"],
        "allowed_models": ["gpt-proxy"], "max_delegation_depth": 2}, headers=auth_headers(admin_token))).json()
    provider = (await client.post("/api/v1/providers/", json={"name": "OpenAI via proxy", "type": "openai"},
                                  headers=auth_headers(admin_token))).json()
    provider_row = await db_session.get(AIProvider, provider["id"])
    provider_row.base_url = up_url + "/v1"             # loopback, as for the route
    await db_session.flush()
    assert (await client.post("/api/v1/gateway/routes", json={"model": "gpt-proxy", "provider_id": provider["id"]},
                              headers=auth_headers(admin_token))).status_code == 200
    tool = (await client.post("/api/v1/http-tools", json={
        "name": "crm.set_tier", "method": "PATCH", "url": "https://crm.example/customers/{id}",
        "input_schema": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"},
                                                                           "tier": {"type": "string"}}}},
        headers=auth_headers(admin_token))).json()
    tool_row = await db_session.get(HttpTool, tool["id"])
    tool_row.url = up_url + "/customers/{id}"          # loopback, as for the route
    await HttpToolGateway(db_session).pin(tool_row, None)
    await db_session.flush()

    mcp = (await client.post("/api/v1/mcp-servers", json={"slug": "orders", "name": "Orders",
                                                         "url": "https://mcp.example/mcp"},
                             headers=auth_headers(admin_token))).json()
    mcp_row = await db_session.get(MCPServer, mcp["id"])
    mcp_row.url, mcp_row.credential_source = up_url + "/mcp", "sealed"   # its credential goes to the proxies
    await db_session.flush()
    peer = (await client.post("/api/v1/a2a-peers", json={"slug": "helper", "name": "Helper",
                                                         "card_url": "https://helper.example/peer-card"},
                              headers=auth_headers(admin_token))).json()
    peer_row = await db_session.get(A2APeer, peer["id"])
    peer_row.card_url, peer_row.credential_source = up_url + "/peer-card", "sealed"
    await db_session.flush()
    agent_row = await db_session.get(Agent, agent["id"])
    agent_row.allowed_tools = sorted(set(agent_row.allowed_tools or []) | {"orders.lookup", "a2a.helper"})
    await db_session.flush()

    port = _free_port()
    cfg = tmp_path / "proxy.json"
    cfg.write_text(json.dumps({"server_url": api_url, "listen": f"127.0.0.1:{port}"}))
    proc = await asyncio.create_subprocess_exec(str(proxy_binary), "-config", str(cfg),
                                                env={**os.environ, "PROVENZA_PROXY_KEY": proxy["key"]},
                                                stderr=asyncio.subprocess.PIPE)
    try:
        base = f"http://127.0.0.1:{port}"
        async with httpx.AsyncClient(base_url=base, timeout=30) as agent_http:
            for _ in range(100):           # until it has the route table and listens
                try:
                    await agent_http.get("/")
                    break
                except httpx.TransportError:
                    assert proc.returncode is None, (await proc.stderr.read()).decode()
                    await asyncio.sleep(0.1)

            # the proxy registered its encryption key; the credential is sealed to it as the browser
            # seals it, and only the envelope reaches this server
            [pk] = (await client.get("/api/v1/egress/proxy-keys", headers=auth_headers(admin_token))).json()
            assert pk["proxy_id"] == proxy["id"] and pk["encryption_key_fingerprint"].startswith("SHA256:")
            env = sealed.seal(SECRET, pk["encryption_key"], sealed.context(
                route.org_id, "route", route.id, proxy["id"], credentials.upstream_of("route", route)))
            r = await signer.seal(client, admin_token, f"/api/v1/egress/credentials/route/{route.id}", [env])
            assert r.status_code == 200 and r.json()["sealed_for"] == [proxy["id"]], r.text
            assert SECRET not in json.dumps((await client.get("/api/v1/egress-proxy/credentials",
                                                              headers={"X-Proxy-Key": proxy["key"]})).json())

            # mediated: the agent's own key, the sealed credential upstream
            body = b'{"amount":1000,"currency":"usd"}'
            resp = await agent_http.post("/stripe/v1/charges", content=body, headers={
                "X-Agent-Key": agent["api_key"], "Authorization": "Bearer agent-own"})
            assert resp.status_code == 201 and resp.content == b'{"id":"ch_1"}', resp.text
            method, target, headers, sent = seen[-1]
            assert (method, target, sent, headers.get("Authorization")) == ("POST", "/v1/charges", body, SECRET)
            assert "X-Agent-Key" not in headers

            # an HTTP tool whose credential is sealed: called through the proxy (/_tools/call),
            # the request built by the proxy from the pinned definition
            tool_secret = "Bearer crm_" + "q" * 20
            env = sealed.seal(tool_secret, pk["encryption_key"], sealed.context(
                tool_row.org_id, "http_tool", tool_row.id, proxy["id"], credentials.upstream_of("http_tool", tool_row)))
            r = await signer.seal(client, admin_token, f"/api/v1/egress/credentials/http_tool/{tool_row.id}",
                                  [env])
            assert r.status_code == 200, r.text
            call_headers = {"X-Agent-Key": agent["api_key"]}
            call = client._signed({"agent_id": agent["id"], "tool_name": "crm.set_tier",
                                   "input": {"id": "c/42", "tier": "gold"}}, call_headers)
            resp = await agent_http.post("/_tools/call", json=call, headers=call_headers)
            assert resp.status_code == 200, resp.text
            out = resp.json()
            assert out["decision"] == "allowed" and out.get("status") == 200, out
            assert out["body"] == {"customer": {"tier": "gold"}}
            method, target, headers, sent = seen[-1]
            assert (method, target, headers.get("Authorization")) == ("PATCH", "/customers/c%2F42", tool_secret)
            assert json.loads(sent) == {"id": "c/42", "tier": "gold"} and headers.get("Provenza-Permit")
            tool_action = await db_session.get(AgentAction, out["action_id"])
            assert tool_action.executed_by == "egress_proxy" and tool_action.witness is not None
            assert tool_action.output_data["status"] == 200 and "body" not in tool_action.output_data
            # the same call straight to this server's gateway: refused, the credential is not here
            call = client._signed({"agent_id": agent["id"], "tool_name": "crm.set_tier", "input": {"id": "x"}},
                                  call_headers)
            direct = (await client.post("/api/v1/http-tools/call", json=call, headers=call_headers)).json()
            assert direct["decision"] == "denied" and "egress proxies" in direct["reason"]

            # a chat completion with the connection's key sealed to the proxy: the prompt and the answer
            # stay between the agent, the proxy and the provider
            env = sealed.seal("sk-sealed-openai", pk["encryption_key"], sealed.context(
                provider_row.org_id, "provider", provider_row.id, proxy["id"],
                credentials.upstream_of("provider", provider_row)))
            assert (await signer.seal(client, admin_token, f"/api/v1/egress/credentials/provider/{provider_row.id}",
                                      [env])).status_code == 200
            resp = await agent_http.post("/_llm/v1/chat/completions", json={
                "model": "gpt-proxy", "messages": [{"role": "user", "content": "the secret prompt"}]},
                headers={"Authorization": f"Bearer {agent['api_key']}"})
            assert resp.status_code == 200, resp.text
            answer = resp.json()
            assert answer["choices"][0]["message"]["content"] == "the answer" and answer["usage"]["total_tokens"] == 12
            method, target, headers, sent = seen[-1]
            assert (target, headers.get("Authorization")) == ("/v1/chat/completions", "Bearer sk-sealed-openai")
            assert json.loads(sent)["messages"] == [{"role": "user", "content": "the secret prompt"}]
            llm_action = await db_session.get(AgentAction, answer["provenza"]["action_id"])
            assert (llm_action.executed_by, llm_action.action_type, llm_action.tool_name) == (
                "egress_proxy", "model_call", "llm.gpt-proxy")
            assert llm_action.output_data["completion_tokens"] == 3 and llm_action.witness is not None
            assert "secret" not in json.dumps(llm_action.input_data) + json.dumps(llm_action.output_data)
            call_row = (await db_session.execute(select(GatewayCall).where(
                GatewayCall.action_id == llm_action.id))).scalar_one()
            assert (call_row.status, call_row.prompt_tokens, call_row.provider_id) == ("completed", 9, provider_row.id)
            # straight to this server's gateway: refused, the key is not here
            direct = await client.post("/api/v1/gateway/v1/chat/completions", json={
                "model": "gpt-proxy", "messages": [{"role": "user", "content": "x"}]},
                headers={"X-Agent-Key": agent["api_key"]})
            assert direct.status_code == 409 and direct.json()["error"]["code"] == "credential_at_proxy"

            # MCP: a server whose credential is sealed to the proxy - synced by the proxy, called through it
            env = sealed.seal("Bearer mcp_" + "m" * 20, pk["encryption_key"], sealed.context(
                mcp_row.org_id, "mcp_server", mcp_row.id, proxy["id"], credentials.upstream_of("mcp_server", mcp_row)))
            assert (await signer.seal(client, admin_token, f"/api/v1/egress/credentials/mcp_server/{mcp_row.id}",
                                      [env])).status_code == 200
            rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "orders.lookup", "arguments": {"id": 7}}}
            agent_mcp = {"Authorization": f"Bearer {agent['api_key']}"}
            first = (await agent_http.post("/_mcp", json=rpc, headers=agent_mcp)).json()
            assert first["error"]["code"] == -32602          # not approved yet; the miss made the proxy sync it
            tool_row = None
            for _ in range(100):
                tool_row = (await db_session.execute(select(MCPTool).where(
                    MCPTool.server_id == mcp_row.id))).scalar_one_or_none()
                if tool_row is not None:
                    break
                await asyncio.sleep(0.05)
            assert tool_row is not None and tool_row.exposed_name == "orders.lookup"
            r = await client.post(f"/api/v1/mcp-servers/{mcp_row.id}/tools/{tool_row.id}/approve",
                                  headers=auth_headers(admin_token))
            assert r.status_code == 200, r.text
            # tools/list comes from this server (relayed); the call is the proxy's
            listed = (await agent_http.post("/_mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                            headers=agent_mcp)).json()
            assert [t["name"] for t in listed["result"]["tools"]] == ["orders.lookup"]
            done = (await agent_http.post("/_mcp", json=rpc, headers=agent_mcp)).json()
            assert done["result"]["content"][0]["text"] == "order 7: shipped", done
            mcp_action = (await db_session.execute(select(AgentAction).where(
                AgentAction.agent_id == agent["id"], AgentAction.tool_name == "orders.lookup",
                AgentAction.policy_check_result == "allowed"))).scalar_one()
            assert mcp_action.executed_by == "egress_proxy" and mcp_action.witness is not None
            assert "shipped" not in json.dumps(mcp_action.output_data)
            # this server's own sync cannot reach it
            r = await client.post(f"/api/v1/mcp-servers/{mcp_row.id}/sync", headers=auth_headers(admin_token))
            assert r.status_code == 409 and r.json()["detail"] == "mcp.synced_by_proxy"

            # A2A: a peer whose credential is sealed to the proxy - its card synced by the proxy, messages
            # sent by it; the server reads the answer as its gateway does
            env = sealed.seal("Bearer peer_" + "p" * 20, pk["encryption_key"], sealed.context(
                peer_row.org_id, "a2a_peer", peer_row.id, proxy["id"], credentials.upstream_of("a2a_peer", peer_row)))
            assert (await signer.seal(client, admin_token, f"/api/v1/egress/credentials/a2a_peer/{peer_row.id}",
                                      [env])).status_code == 200
            send = {"jsonrpc": "2.0", "id": "r1", "method": "SendMessage", "params": {"message": {
                "messageId": "m1", "role": "ROLE_USER", "parts": [{"text": "summarize this"}]}}}
            a2a_headers = {"Authorization": f"Bearer {agent['api_key']}", "A2A-Version": "1.0"}
            first = await agent_http.post("/_a2a/helper", json=send, headers=a2a_headers)
            assert first.status_code == 404      # not synced nor approved yet; the miss made the proxy sync it
            for _ in range(100):
                await db_session.refresh(peer_row)
                if peer_row.card_digest:
                    break
                await asyncio.sleep(0.05)
            assert peer_row.card_digest and peer_row.endpoint_url == up_url + "/a2a", peer_row.last_error
            assert (await client.post(f"/api/v1/a2a-peers/{peer_row.id}/approve",
                                      headers=auth_headers(admin_token))).status_code == 200
            card = (await agent_http.get("/_a2a/helper/.well-known/agent-card.json", headers=a2a_headers)).json()
            assert card["supportedInterfaces"][0]["url"].endswith("/_a2a/helper")
            done = (await agent_http.post("/_a2a/helper", json=send, headers=a2a_headers)).json()
            assert done["result"]["task"]["id"] == "task-77", done
            assert done["result"]["task"]["artifacts"][0]["parts"][0]["text"] == "the summary"
            a2a_action = (await db_session.execute(select(AgentAction).where(
                AgentAction.agent_id == agent["id"], AgentAction.tool_name == "a2a.helper",
                AgentAction.policy_check_result == "allowed"))).scalar_one()
            assert a2a_action.executed_by == "egress_proxy" and a2a_action.witness is not None
            assert "the summary" not in json.dumps(a2a_action.output_data)
            # the task is the agent's now: another agent cannot read it
            owner = (await db_session.execute(select(A2ATask.agent_id).where(A2ATask.task_id == "task-77"))).scalar()
            assert owner == agent["id"]
            r = await client.post(f"/api/v1/a2a-peers/{peer_row.id}/sync", headers=auth_headers(admin_token))
            assert r.status_code == 409 and r.json()["detail"] == "a2a.synced_by_proxy"
            seen_before = len(seen)

            # outside the route: refused by the proxy itself, nothing leaves
            resp = await agent_http.delete("/stripe/v1/charges", headers={"X-Agent-Key": agent["api_key"]})
            assert resp.status_code == 405 and len(seen) == seen_before

            # SDK mode: the Python SDK's descriptor is exactly what the Go proxy redeems
            desc = descriptor("stripe", "GET", "/v1/charges/ch_1", query="expand%5B%5D=customer")
            chk = (await client.post("/api/v1/agents/actions/check", json={
                "agent_id": agent["id"], "action_type": "proxy", "tool_name": "proxy.stripe", "input": desc},
                headers={"X-Agent-Key": agent["api_key"]})).json()
            assert chk["decision"] == "allowed", chk
            resp = await agent_http.get("/stripe/v1/charges/ch_1?expand%5B%5D=customer",
                                        headers={"X-Provenza-Check-Id": chk["check_id"]})
            assert resp.status_code == 201, resp.text
            assert seen[-1][1] == "/v1/charges/ch_1?expand%5B%5D=customer"
            # a check spent is spent
            resp = await agent_http.get("/stripe/v1/charges/ch_1?expand%5B%5D=customer",
                                        headers={"X-Provenza-Check-Id": chk["check_id"]})
            assert resp.status_code == 403 and len(seen) == seen_before + 1
    finally:
        proc.terminate()
        await proc.wait()
        up_server.close()
        api_server.close()

    actions = (await db_session.execute(select(AgentAction).where(
        AgentAction.agent_id == agent["id"]).order_by(AgentAction.id))).scalars().all()
    actions = [a for a in actions if a.action_type == "proxy"]
    assert [(a.policy_check_result, a.executed_by) for a in actions] == [
        ("allowed", "egress_proxy"), ("allowed", "egress_proxy")]
    assert actions[0].output_data == {"status": 201, "response_sha256": hashlib.sha256(b'{"id":"ch_1"}').hexdigest(),
                                      "response_bytes": 13}
    assert actions[1].input_data == desc
