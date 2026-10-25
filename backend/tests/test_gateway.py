"""
LLM gateway: OpenAI-compatible endpoint behind agent identity - routing,
model allowlist, rate limit, max_tokens cap, logging of the call (never of
its content), admin API. Every call is a PVP action ("model_call" on
"llm.<model>") decided by the orchestrator.
The provider is replaced by a fake; nothing leaves the test process.
"""

import secrets

import pytest
from sqlalchemy import select, update

from app.core.agent_signing import content_hash
from app.models.agent import Agent
from app.models.agent_action import AgentAction, ActionCheck
from app.models.ai_provider import AIProvider
from app.models.gateway import GatewayCall
from app.services import gateway_adapters
from tests import signer
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
                   default_model="gpt-4o-mini")   # no key: this server holds none (app/pvp/sealed.py)
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


async def _chat(client, agent, messages, model="gpt-4o-mini", bearer=False, headers_extra=None, **extra):
    headers = {"Authorization": f"Bearer {agent['api_key']}"} if bearer else {"X-Agent-Key": agent["api_key"]}
    headers.update(headers_extra or {})
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
            assert sent["key"] is None and sent["model"] == "gpt-4o-mini-2024"   # no key here
            assert sent["messages"][1]["content"] == "Email john.doe@example.com the report"   # forwarded as sent
            assert set(body["provenza"]) == {"call_id", "action_id"}
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


class TestPVP:
    """The gateway is a PVP executor: the orchestrator decides, the gateway
    executes and records; content never reaches the action."""

    @staticmethod
    async def _policy(client, token, agent, rules):
        r = await client.post("/api/v1/agents/policies/", json={"name": "llm rules", "agent_id": agent["id"],
                                                                "rules": rules}, headers=auth_headers(token))
        assert r.status_code == 200, r.text

    @pytest.mark.asyncio
    async def test_a_completion_is_an_action_without_content(self, client, admin_token, db_session, fake):
        a, pid, rid = await _setup(client, admin_token, db_session)
        try:
            messages = msgs(("user", "Card 4111 1111 1111 1111, summarize"))
            r = await _chat(client, a, messages)
            assert r.status_code == 200, r.text
            action = await db_session.get(AgentAction, r.json()["provenza"]["action_id"])
            assert action.action_type == "model_call" and action.tool_name == "llm.gpt-4o-mini"
            assert action.executed_by == "llm_gateway" and action.policy_check_result == "allowed"
            assert action.check_id is not None
            assert action.input_data["messages_sha256"] == content_hash(messages)
            assert action.input_data["messages"] == 1 and action.input_data["model"] == "gpt-4o-mini"
            assert action.output_data["completion_tokens"] == 5 and "response_sha256" in action.output_data
            assert "4111" not in str(action.input_data) + str(action.output_data)
            call = await db_session.get(GatewayCall, r.json()["provenza"]["call_id"])
            assert call.action_id == action.id
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_agent_policy_denies_a_model(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            await self._policy(client, admin_token, a, {"deny_tool_patterns": ["llm.gpt-4o*"]})
            r = await _chat(client, a, msgs(("user", "hi")))
            assert r.status_code == 403 and r.json()["error"]["code"] == "policy_denied", r.text
            assert fake.calls == []
            action = (await db_session.execute(select(AgentAction).where(AgentAction.agent_id == a["id"]))
                      ).scalar_one()
            assert action.policy_check_result == "denied" and action.executed_by == "llm_gateway"
            call = (await db_session.execute(select(GatewayCall).where(GatewayCall.agent_id == a["id"]))
                    ).scalar_one()
            assert call.status == "denied" and call.action_id == action.id
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_model_calls_can_need_approval(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            await self._policy(client, admin_token, a, {"require_approval_tool_patterns": ["llm.*"]})
            r = await _chat(client, a, msgs(("user", "hi")))
            assert r.status_code == 403 and r.json()["error"]["code"] == "approval_required", r.text
            assert fake.calls == []
            action = (await db_session.execute(select(AgentAction).where(AgentAction.agent_id == a["id"]))
                      ).scalar_one()
            assert action.policy_check_result == "pending_approval"
            assert f"action #{action.id}" in r.json()["error"]["message"]
            call = (await db_session.execute(select(GatewayCall).where(GatewayCall.agent_id == a["id"]))
                    ).scalar_one()
            assert call.status == "pending_approval"
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_a_tool_allow_list_does_not_block_models(self, client, admin_token, db_session, fake):
        # the model's right is allowed_models / models.allow; a tool allow list governs tools
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            await self._policy(client, admin_token, a, {"allow_only_tool_patterns": ["kb.*"]})
            r = await _chat(client, a, msgs(("user", "hi")))
            assert r.status_code == 200, r.text
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_model_calls_need_a_known_chain(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            for bad in ("abc", "0", "-1", "1e3", " 7", "99999999999"):
                r = await _chat(client, a, msgs(("user", "hi")), headers_extra={"X-Provenza-Chain-Id": bad})
                assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_chain_id", bad
            r = await _chat(client, a, msgs(("user", "hi")), headers_extra={"X-Provenza-Chain-Id": "987654"})
            assert r.status_code in (403, 404), r.text
            assert fake.calls == []
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_checks_are_counted_as_decisions(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            assert (await _chat(client, a, msgs(("user", "hi")))).status_code == 200
            check = (await db_session.execute(select(ActionCheck).where(ActionCheck.agent_id == a["id"]))
                     ).scalar_one()
            assert check.action_type == "model_call" and check.tool_name == "llm.gpt-4o-mini"
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_the_live_view_shows_a_model_call_once(self, client, admin_token, db_session, fake):
        from sqlalchemy import text
        from app.core import obs_hooks

        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            r = await _chat(client, a, msgs(("user", "hi")))
            assert r.status_code == 200, r.text
            rows = (await db_session.execute(text(
                "SELECT event_type FROM agent_events_v WHERE agent_id = :a ORDER BY event_type"), {"a": a["id"]}
            )).scalars().all()
            assert rows == ["action.checked", "llm.call"]
            action = await db_session.get(AgentAction, r.json()["provenza"]["action_id"])
            assert obs_hooks.to_event(action) is None      # published as llm.call, not twice
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_model_calls_are_not_counted_as_behaviour(self, client, admin_token, db_session, fake):
        from datetime import datetime, timedelta, timezone
        from app.services.behavior_monitor import BehaviorMonitor

        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            for i in range(3):
                assert (await _chat(client, a, msgs(("user", str(i))))).status_code == 200
            since = datetime.now(timezone.utc) - timedelta(hours=1)
            attempts, *_ = await BehaviorMonitor(db_session)._count(a["id"], since)
            assert attempts == 0
        finally:
            await _cleanup_route(client, admin_token, rid)


class TestApprovedCallsRunOnce:
    """A held call runs when the agent repeats exactly that call after a
    person approved it - once, and never with other arguments."""

    @staticmethod
    async def _hold(client, token, db, agent):
        r = await client.post("/api/v1/agents/policies/", json={"name": "approve llm", "agent_id": agent["id"],
                                                                "rules": {"require_approval_tool_patterns": ["llm.*"]}},
                              headers=auth_headers(token))
        assert r.status_code == 200, r.text

    @staticmethod
    async def _pending(db, agent_id):
        return (await db.execute(select(AgentAction).where(AgentAction.agent_id == agent_id,
                                                           AgentAction.policy_check_result == "pending_approval")
                                 .order_by(AgentAction.id.desc()))).scalars().first()

    @staticmethod
    async def _decision(client, agent, action_id):
        r = await client.get(f"{A}/actions/{action_id}/decision", headers={"X-Agent-Key": agent["api_key"]})
        assert r.status_code == 200, r.text
        return r.json()

    @pytest.mark.asyncio
    async def test_approved_call_runs_once_with_the_same_arguments(self, client, admin_token, approver_token,
                                                                    db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            await self._hold(client, admin_token, db_session, a)
            m = msgs(("user", "send the report"))
            assert (await _chat(client, a, m)).json()["error"]["code"] == "approval_required"
            held = await self._pending(db_session, a["id"])
            assert (await self._decision(client, a, held.id))["decision"] == "pending_approval"

            r = await signer.approve(client, approver_token, held.id, content_hash(held.input_data))
            assert r.status_code == 200, r.text
            d = await self._decision(client, a, held.id)
            assert d["decision"] == "approved" and d["redeemable_until"] and not d["used"]

            # other arguments: still held, the approval is not touched
            other = await _chat(client, a, msgs(("user", "send ALL the reports")))
            assert other.json()["error"]["code"] == "approval_required"
            assert fake.calls == []

            ok = await _chat(client, a, m)
            assert ok.status_code == 200, ok.text
            assert len(fake.calls) == 1
            ran = await db_session.get(AgentAction, ok.json()["provenza"]["action_id"])
            assert ran.policy_check_result == "allowed" and ran.executed_by == "llm_gateway"
            assert f"action #{held.id}" in ran.reason
            check = await db_session.get(ActionCheck, ran.check_id)
            assert check.decision == "allowed" and "approval #" in check.reason
            assert (await self._decision(client, a, held.id))["used"] is True

            again = await _chat(client, a, m)
            assert again.status_code == 403 and again.json()["error"]["code"] == "approval_required"
            assert len(fake.calls) == 1
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_a_denial_still_wins_after_approval(self, client, admin_token, approver_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            await self._hold(client, admin_token, db_session, a)
            m = msgs(("user", "x"))
            await _chat(client, a, m)
            held = await self._pending(db_session, a["id"])
            r = await signer.approve(client, approver_token, held.id, content_hash(held.input_data))
            assert r.status_code == 200, r.text
            await db_session.execute(update(Agent).where(Agent.id == a["id"]).values(status="suspended"))
            await db_session.commit()
            r = await _chat(client, a, m)
            assert r.status_code == 403 and r.json()["error"]["code"] == "agent_not_active"
            from app.models.approval import AgentActionApproval
            approval = (await db_session.execute(select(AgentActionApproval).where(
                AgentActionApproval.action_id == held.id))).scalar_one()
            await db_session.refresh(approval)
            assert fake.calls == [] and approval.redeemed_at is None     # not spent on a refused call
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_only_the_agent_itself_reads_its_decision(self, client, admin_token, db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session)
        b = await _agent(client, admin_token)
        try:
            await self._hold(client, admin_token, db_session, a)
            await _chat(client, a, msgs(("user", "x")))
            held = await self._pending(db_session, a["id"])
            r = await client.get(f"{A}/actions/{held.id}/decision", headers={"X-Agent-Key": b["api_key"]})
            assert r.status_code == 404
        finally:
            await _cleanup_route(client, admin_token, rid)

    @pytest.mark.asyncio
    async def test_an_executor_refusal_does_not_use_up_the_approval(self, client, admin_token, approver_token,
                                                                    db_session, fake):
        a, _, rid = await _setup(client, admin_token, db_session, rpm_per_agent=1)
        try:
            await self._hold(client, admin_token, db_session, a)
            m = msgs(("user", "x"))
            await _chat(client, a, m)                                   # held: counts for the rate limit
            held = await self._pending(db_session, a["id"])
            r = await signer.approve(client, approver_token, held.id, content_hash(held.input_data))
            assert r.status_code == 200, r.text
            r = await _chat(client, a, m)
            assert r.status_code == 429, r.text                         # refused by the executor
            assert (await self._decision(client, a, held.id))["used"] is False
            body = {"enabled": True, "rpm_per_agent": 60, "max_tokens_cap": 4096}
            assert (await client.put(G + "/settings", json=body, headers=auth_headers(admin_token))).status_code == 200
            assert (await _chat(client, a, m)).status_code == 200
            assert len(fake.calls) == 1
        finally:
            await _cleanup_route(client, admin_token, rid)
