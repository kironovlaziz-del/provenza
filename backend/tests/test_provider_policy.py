# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
"Self-hosted AI providers only" (app/services/provider_policy.py): the
setting, the early refusal of obvious cloud connections by the gateway and
the connection pages, the connect-time check that a host name cannot talk
around, and agents' direct calls to cloud AI services.
"""

import ipaddress
import json
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
from sqlalchemy import select

from app.core import outbound
from app.core.config import settings
from app.models.agent import Agent
from app.models.agent_action import AgentIncident
from app.models.ai_provider import AIProvider
from app.models.audit_log import AIAuditLog as AuditLog
from app.services import provider_adapters, provider_policy
from tests.conftest import auth_headers
from tests.test_gateway import _chat, _setup, fake, msgs  # noqa: F401  (fake is a fixture)
from tests.test_pvp_egress import _agent as _egress_agent, _check as _egress_check

P = "/api/v1/providers"


async def _policy(client, token, policy):
    r = await client.put(f"{P}/policy", json={"policy": policy}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _provider(client, token, **fields):
    body = {"name": "conn-" + secrets.token_hex(3), "type": "openai", "api_key": "sk-test-123",
            "default_model": "gpt-4o-mini", **fields}
    r = await client.post(f"{P}/", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def allow(monkeypatch):
    def _set(value: str):
        monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", value)
    _set("")
    return _set


def fake_dns(monkeypatch, table):
    def infos(host, port):
        if host not in table:
            raise socket.gaierror("unknown host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in table[host]]

    async def agetaddrinfo(host, port, **kw):
        return infos(host, port)

    monkeypatch.setattr(outbound.anyio, "getaddrinfo", agetaddrinfo)
    monkeypatch.setattr(outbound.socket, "getaddrinfo", lambda host, port, **kw: infos(host, port))


class _ModelServer:
    """An OpenAI-compatible model server on 127.0.0.1 - "self-hosted"."""

    def __init__(self):
        self.prompts = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.prompts.append(body["messages"][-1]["content"])
                out = json.dumps({"choices": [{"message": {"content": "local answer"}, "finish_reason": "stop"}],
                                  "usage": {"prompt_tokens": 3, "completion_tokens": 2}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# --------------------------------------------------------------------- unit

class TestInternalOnlyGuard:
    def test_public_addresses_refused_internal_allowlisted_pass(self, allow):
        allow("10.0.0.0/8")
        assert outbound.check_addresses("llm.corp", ["10.1.2.3"], internal_only=True) == ["10.1.2.3"]
        for public in ("8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111"):
            with pytest.raises(outbound.OutboundBlocked, match="self-hosted"):
                outbound.check_addresses("api.example.com", [public], internal_only=True)
        # one public record refuses the whole name
        with pytest.raises(outbound.OutboundBlocked):
            outbound.check_addresses("mixed.corp", ["10.1.2.3", "8.8.8.8"], internal_only=True)
        # internal-only does not widen anything: a private address still needs the operator's allowlist
        with pytest.raises(outbound.OutboundBlocked, match="OUTBOUND_PRIVATE_ALLOWLIST"):
            outbound.check_addresses("other.corp", ["192.168.1.5"], internal_only=True)

    def test_internal_only_never_uses_the_outbound_proxy(self, monkeypatch):
        monkeypatch.setattr(settings, "OUTBOUND_PROXY", "http://proxy.corp.local:3128")
        client = outbound.guarded_async_client(internal_only=True, timeout=5)
        assert isinstance(client._transport._pool._network_backend, outbound._GuardedAsyncBackend)
        assert not client._mounts

    def test_cloud_reason(self):
        assert provider_policy.cloud_reason("openai", None)
        assert provider_policy.cloud_reason("anthropic", "  ")
        assert provider_policy.cloud_reason("custom", "https://8.8.8.8/v1")
        assert provider_policy.cloud_reason("openai", "http://10.0.0.5:8000/v1") is None
        assert provider_policy.cloud_reason("openai", "https://llm.corp.local/v1") is None  # connect time decides

    def test_scope_selects_the_internal_client(self):
        with provider_policy.scope(True):
            internal = provider_adapters._get_client()
        with provider_policy.scope(False):
            shared = provider_adapters._get_client()
        assert internal is not shared
        assert internal._transport._pool._network_backend._internal_only is True
        assert provider_policy.self_hosted_only() is False


# ------------------------------------------------------------------ setting

@pytest.mark.asyncio
async def test_policy_setting_is_admin_only_and_audited(client, admin_token, approver_token, db_session):
    r = await client.get(f"{P}/policy", headers=auth_headers(approver_token))
    assert r.status_code == 200 and r.json()["policy"] == "any"
    r = await client.put(f"{P}/policy", json={"policy": "self_hosted"}, headers=auth_headers(approver_token))
    assert r.status_code == 403
    r = await client.put(f"{P}/policy", json={"policy": "local"}, headers=auth_headers(admin_token))
    assert r.status_code == 422

    cloud = await _provider(client, admin_token)
    out = await _policy(client, admin_token, "self_hosted")
    assert out["policy"] == "self_hosted"
    assert [c["id"] for c in out["cloud_connections"]] == [cloud["id"]]
    entry = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "ai_provider_policy_changed").order_by(AuditLog.id.desc())
    )).scalars().first()
    assert entry is not None and entry.metadata_json == {"before": "any", "after": "self_hosted"}
    assert (await _policy(client, admin_token, "any"))["policy"] == "any"


# ------------------------------------------------------------- connections

@pytest.mark.asyncio
async def test_listing_a_cloud_connections_models_is_refused(client, admin_token):
    cloud = await _provider(client, admin_token)
    await _policy(client, admin_token, "self_hosted")
    try:
        r = await client.get(f"{P}/{cloud['id']}/models", headers=auth_headers(admin_token))
        assert r.status_code == 403
    finally:
        await _policy(client, admin_token, "any")


# ------------------------------------------------------------------ gateway

@pytest.mark.asyncio
async def test_gateway_refuses_a_cloud_route(client, admin_token, db_session, fake):
    agent, _provider_id, _route = await _setup(client, admin_token, db_session)
    await _policy(client, admin_token, "self_hosted")
    try:
        r = await _chat(client, agent, msgs(("user", "hello")))
        assert r.status_code == 403 and r.json()["error"]["code"] == "provider_not_self_hosted", r.text
        assert fake.calls == []
    finally:
        await _policy(client, admin_token, "any")


@pytest.mark.asyncio
async def test_gateway_calls_a_self_hosted_route_through_the_internal_client(client, admin_token, db_session,
                                                                            monkeypatch):
    seen = []

    async def chat(*args):
        seen.append(provider_policy.self_hosted_only())
        return "ok", "stop", {}, {"prompt_tokens": 1, "completion_tokens": 1}

    from app.services import gateway_adapters
    monkeypatch.setattr(gateway_adapters, "chat", chat)
    agent, provider_id, _route = await _setup(client, admin_token, db_session)
    p = await db_session.get(AIProvider, provider_id)
    p.base_url = "http://10.0.0.5:8000/v1"
    await db_session.commit()
    await _policy(client, admin_token, "self_hosted")
    try:
        r = await _chat(client, agent, msgs(("user", "hello")))
        assert r.status_code == 200, r.text
        assert seen == [True]
    finally:
        await _policy(client, admin_token, "any")


@pytest.mark.asyncio
async def test_gateway_reaches_a_self_hosted_model_server(client, admin_token, db_session, allow):
    allow("127.0.0.1")
    server = _ModelServer()
    agent, provider_id, _route = await _setup(client, admin_token, db_session)
    p = await db_session.get(AIProvider, provider_id)
    p.base_url = server.url
    await db_session.commit()
    await _policy(client, admin_token, "self_hosted")
    try:
        r = await _chat(client, agent, msgs(("user", "summarize the plan")))
        assert r.status_code == 200, r.text
        assert r.json()["choices"][0]["message"]["content"] == "local answer"
        assert server.prompts == ["summarize the plan"]
    finally:
        await _policy(client, admin_token, "any")
        server.close()


@pytest.mark.asyncio
async def test_a_host_name_cannot_talk_around_the_policy(client, admin_token, db_session, allow, monkeypatch):
    # looks internal, resolves to the internet: refused at connect time, nothing sent
    fake_dns(monkeypatch, {"llm.corp.example": ["93.184.216.34"]})
    agent, provider_id, _route = await _setup(client, admin_token, db_session)
    p = await db_session.get(AIProvider, provider_id)
    p.base_url = "https://llm.corp.example/v1"
    await db_session.commit()
    await _policy(client, admin_token, "self_hosted")
    try:
        r = await _chat(client, agent, msgs(("user", "hello")))
        assert r.status_code == 502 and "self-hosted" in r.json()["error"]["message"], r.text
    finally:
        await _policy(client, admin_token, "any")


# -------------------------------------------------------------- agent egress

@pytest.mark.asyncio
async def test_agents_cannot_call_cloud_ai_services_directly(client, admin_token, db_session):
    agent = await _egress_agent(client, admin_token)
    assert (await _egress_check(client, agent, "api.openai.com"))["decision"] == "allowed"
    await _policy(client, admin_token, "self_hosted")
    try:
        out = await _egress_check(client, agent, "api.openai.com")
        assert out["decision"] == "denied" and "self-hosted" in out["reason"]
        assert out["incident_type"] == provider_policy.INCIDENT
        # a host the catalog does not know as an AI service is not judged here
        assert (await _egress_check(client, agent, "llm.corp.internal"))["decision"] == "allowed"
    finally:
        await _policy(client, admin_token, "any")
