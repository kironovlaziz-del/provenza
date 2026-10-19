"""
LLM gateway: OpenAI-compatible endpoint behind agent identity - routing,
model allowlist, rate limit, max_tokens cap, logging of the call (never of
its content), admin API.
The provider is replaced by a fake; nothing leaves the test process.
"""

import secrets

import pytest
from sqlalchemy import update

from app.core.crypto import encrypt_secret
from app.models.agent import Agent
from app.models.ai_provider import AIProvider
from app.services import gateway_adapters
from tests.conftest import auth_headers

A = "/api/v1/agents"
G = "/api/v1/gateway"
CHAT = G + "/v1/chat/completions"


class FakeProvider:
    def __init__(self, reply="The report is ready.", usage=(12, 5)):
        self.reply, self.usage, self.calls = reply, usage, []

    async def __call__(self, ptype, key, base, model, messages, params):
        self.calls.append({"type": ptype, "key": key, "model": model, "messages": messages, "params": params})
        return self.reply, "stop", {"fake": True}, {"prompt_tokens": self.usage[0], "completion_tokens": self.usage[1]}


@pytest.fixture
def fake(monkeypatch):
    f = FakeProvider()
    monkeypatch.setattr(gateway_adapters, "chat", f)
    return f


async def _agent(client, token, models=("gpt-4o-mini",)):
    r = await client.post(
        f"{A}/register",
        json={"name": "gw-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
              "allowed_tools": [], "allowed_models": list(models), "max_delegation_depth": 2},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _setup(client, token, db, models=("gpt-4o-mini",), route="gpt-4o-mini", upstream=None, **settings):
    a = await _agent(client, token, models)
    org_id = (await db.get(Agent, a["id"])).org_id
    p = AIProvider(org_id=org_id, name="fake-" + secrets.token_hex(3), type="openai", status="active",
                   default_model="gpt-4o-mini", api_key_encrypted=encrypt_secret("sk-test-123"))
    db.add(p)
    await db.commit()
    await db.refresh(p)
    body = {"enabled": True, "rpm_per_agent": 60, "max_tokens_cap": 4096}
    body.update(settings)
    r = await client.put(G + "/settings", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    r = await client.post(G + "/routes", json={"model": route, "provider_id": p.id, "upstream_model": upstream},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return a, p.id, r.json()["id"]


async def _cleanup_route(client, token, route_id):
    await client.post(f"{G}/routes/{route_id}/disable", headers=auth_headers(token))


def msgs(*pairs):
    return [{"role": r, "content": c} for r, c in pairs]


async def _chat(client, agent, messages, model="gpt-4o-mini", bearer=False, **extra):
    headers = {"Authorization": f"Bearer {agent['api_key']}"} if bearer else {"X-Agent-Key": agent["api_key"]}
    return await client.post(CHAT, json={"model": model, "messages": messages, **extra}, headers=headers)


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_completion_logged_without_content_openai_shape(self, client, admin_token, db_session, fake):
        a, pid, rid = await _setup(client, admin_token, db_session, upstream="gpt-4o-mini-2024")
        try:
            r = await _chat(client, a, msgs(("system", "Be brief."), ("user", "Email john.doe@example.com the report")),
                            bearer=True)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["object"] == "chat.completion" and body["choices"][0]["message"]["content"] == "The report is ready."
            assert body["usage"]["total_tokens"] == 17 and body["model"] == "gpt-4o-mini"
            sent = fake.calls[0]
            assert sent["key"] == "sk-test-123" and sent["model"] == "gpt-4o-mini-2024"
            assert sent["messages"][1]["content"] == "Email john.doe@example.com the report"   # forwarded as sent
            assert body["provenza"] == {"call_id": body["provenza"]["call_id"]}
            ov = (await client.get(G + "/", headers=auth_headers(admin_token)))
            call = next(c for c in ov.json()["calls"] if c["id"] == body["provenza"]["call_id"])
            assert call["status"] == "completed" and call["prompt_tokens"] == 12 and call["model"] == "gpt-4o-mini"
            assert "john.doe@example.com" not in ov.text                                       # the content is not kept
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_models_lists_allowed_and_routed(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session, models=("gpt-4o-mini", "claude-x"))
        try:
            r = await client.get(G + "/v1/models", headers={"X-Agent-Key": a["api_key"]})
            assert r.status_code == 200 and [m["id"] for m in r.json()["data"]] == ["gpt-4o-mini"]
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_max_tokens_is_capped(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session, max_tokens_cap=100)
        try:
            await _chat(client, a, msgs(("user", "hi")), max_tokens=5000)
            await _chat(client, a, msgs(("user", "hi")), max_tokens=10)
            assert [c["params"]["max_tokens"] for c in fake.calls] == [100, 10]
        finally:
            await _cleanup_route(client, admin_token, rid)


class TestRefusals:
    @pytest.mark.asyncio
    async def test_identity_model_and_route(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session, models=("gpt-4o-mini", "unrouted-model"))
        try:
            # a user's JWT is not an agent key
            r = await client.post(CHAT, json={"model": "gpt-4o-mini", "messages": msgs(("user", "hi"))},
                                  headers=auth_headers(admin_token))
            assert r.status_code == 401
            r = await _chat(client, a, msgs(("user", "hi")), model="gpt-5-secret")
            assert r.status_code == 403 and r.json()["error"]["code"] == "model_not_allowed"
            r = await _chat(client, a, msgs(("user", "hi")), model="unrouted-model")
            assert r.status_code == 404 and r.json()["error"]["code"] == "model_not_routed"
            assert (await _chat(client, a, msgs(("user", "hi")), stream=True)).status_code == 400
            assert fake.calls == []
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_quarantined_agent(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            await db_session.execute(update(Agent).where(Agent.id == a["id"]).values(status="quarantined"))
            await db_session.commit()
            r = await _chat(client, a, msgs(("user", "hi")))
            assert r.status_code == 403 and r.json()["error"]["code"] == "agent_not_active"
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_rate_limit(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session, rpm_per_agent=2)
        try:
            assert (await _chat(client, a, msgs(("user", "1")))).status_code == 200
            assert (await _chat(client, a, msgs(("user", "2")))).status_code == 200
            r = await _chat(client, a, msgs(("user", "3")))
            assert r.status_code == 429 and r.json()["error"]["type"] == "rate_limit_error"
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_provider_failure_is_502_and_logged(self, client, admin_token, db_session, monkeypatch):
        from app.services.provider_adapters import ProviderCallError

        async def boom(*args):
            raise ProviderCallError("Provider returned 500: upstream down")
        monkeypatch.setattr(gateway_adapters, "chat", boom)
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            r = await _chat(client, a, msgs(("user", "hi")))
            assert r.status_code == 502 and "upstream down" in r.json()["error"]["message"]
        finally:
            await _cleanup_route(client, admin_token, rid)


class TestAdmin:
    @pytest.mark.asyncio
    async def test_routes_settings_roles(self, client, admin_token, approver_token, db_session, fake):
        a, pid, rid = await _setup(client, admin_token, db_session, route="gpt-4o*")
        try:
            assert (await _chat(client, a, msgs(("user", "hi")))).status_code == 200   # glob route
            dup = await client.post(G + "/routes", json={"model": "gpt-4o*", "provider_id": pid}, headers=auth_headers(admin_token))
            assert dup.status_code == 409
            assert (await client.post(G + "/routes", json={"model": "x", "provider_id": 99999999},
                                      headers=auth_headers(admin_token))).status_code == 404
            for bad in ({"enabled": True, "rpm_per_agent": 0, "max_tokens_cap": 4096},
                        {"enabled": True, "rpm_per_agent": 60, "max_tokens_cap": 1}):
                assert (await client.put(G + "/settings", json=bad, headers=auth_headers(admin_token))).status_code == 422
            assert (await client.put(G + "/settings", json={"enabled": False, "rpm_per_agent": 60, "max_tokens_cap": 4096},
                                     headers=auth_headers(approver_token))).status_code == 403
            assert (await client.get(G + "/", headers=auth_headers(approver_token))).status_code == 200
            # an agent key never opens the admin side
            assert (await client.get(G + "/", headers={"X-Agent-Key": a["api_key"]})).status_code in (401, 403)
        finally:
            await _cleanup_route(client, admin_token, rid)
        assert (await client.post(f"{G}/routes/{rid}/disable", headers=auth_headers(admin_token))).status_code == 409
