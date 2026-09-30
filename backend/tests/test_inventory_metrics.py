"""
Trust metrics on inventory systems: computed on the fly from the events other
modules record (agent actions, AI requests, shadow-AI sightings).
"""

import secrets
from datetime import datetime, timezone

import pytest

from app.models.ai_request import AIRequest
from app.models.shadow_ai_sighting import ShadowAISighting
from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers
from tests.delegation_helpers import action_record_body

BASE = "/api/v1/inventory"


async def _system_for(client, token, source_key):
    r = await client.get(BASE + "/", params={"limit": 100}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    for item in r.json()["items"]:
        if item["source_key"] == source_key:
            return item
    raise AssertionError(f"{source_key} not in inventory")


async def _metrics(client, token, system_id, **params):
    r = await client.get(f"{BASE}/{system_id}/metrics", params=params, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _agent(client, token):
    r = await client.post(
        "/api/v1/agents/register",
        json={"name": "m-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
              "allowed_tools": ["db.read"], "allowed_models": [], "max_delegation_depth": 1},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _act(client, token, agent, tool, inp):
    chk = await client.post("/api/v1/agents/actions/check",
                            json={"agent_id": agent["id"], "tool_name": tool, "input": inp},
                            headers=auth_headers(token))
    assert chk.status_code == 200, chk.text
    rec = await client.post("/api/v1/agents/actions/record",
                            json=action_record_body(agent, chk.json()["check_id"], tool, inp),
                            headers=auth_headers(token))
    assert rec.status_code == 200, rec.text
    return rec.json()


class TestAgentMetrics:
    @pytest.mark.asyncio
    async def test_counts_allowed_and_denied_actions(self, client, admin_token):
        a = await _agent(client, admin_token)
        await _act(client, admin_token, a, "db.read", {"q": 1})
        await _act(client, admin_token, a, "db.read", {"q": 2})
        await _act(client, admin_token, a, "stripe.charge", {"amount": 5})  # not an allowed tool
        system = await _system_for(client, admin_token, f"agent:{a['id']}")
        m = await _metrics(client, admin_token, system["id"])
        assert m["source"] == "agent_actions"
        assert m["counts"]["actions"] == 3
        assert m["counts"]["allowed"] == 2
        assert m["counts"]["denied"] == 1
        assert m["rates"]["denial_rate"] == pytest.approx(1 / 3, abs=0.001)
        assert m["last_activity_at"]
        assert ("open_incidents" in m["signals"]) == (m["counts"]["open_incidents"] > 0)
        assert "no_recent_activity" not in m["signals"]

    @pytest.mark.asyncio
    async def test_idle_production_agent_is_flagged(self, client, admin_token):
        a = await _agent(client, admin_token)
        system = await _system_for(client, admin_token, f"agent:{a['id']}")
        m = await _metrics(client, admin_token, system["id"])
        assert m["counts"]["actions"] == 0
        assert "no_recent_activity" in m["signals"]


class TestProviderMetrics:
    @pytest.mark.asyncio
    async def test_block_rate_and_pending_requests(self, client, admin_token, db_session):
        prov = await client.post(
            "/api/v1/providers/",
            json={"name": "Metrics LLM", "type": "openai", "api_key": "sk-metrics"},
            headers=auth_headers(admin_token),
        )
        assert prov.status_code in (200, 201), prov.text
        system = await _system_for(client, admin_token, f"provider:{prov.json()['id']}")
        for status, n in (("completed", 8), ("blocked", 3), ("pending_approval", 1)):
            for _ in range(n):
                db_session.add(AIRequest(org_id=system["org_id"], provider_id=prov.json()["id"],
                                         status=status, purpose="metrics_test"))
        await db_session.commit()

        m = await _metrics(client, admin_token, system["id"])
        assert m["source"] == "ai_requests"
        assert m["counts"]["requests"] == 12
        assert m["counts"]["blocked"] == 3
        assert m["rates"]["block_rate"] == pytest.approx(0.25)
        assert "high_block_rate" in m["signals"]
        assert "requests_awaiting_approval" in m["signals"]


class TestShadowMetrics:
    @pytest.mark.asyncio
    async def test_sightings_and_distinct_users(self, client, admin_token, db_session):
        probe = await client.get(BASE + "/summary", headers=auth_headers(admin_token))
        assert probe.status_code == 200
        manual = await client.post(BASE + "/", json={"name": "probe"}, headers=auth_headers(admin_token))
        org_id = manual.json()["org_id"]
        now = datetime.now(timezone.utc)
        db_session.add(ShadowAISighting(org_id=org_id, tool_name="Midjourney", status="new",
                                        seen_count=5, user_hint="alice@corp.example", last_seen_at=now))
        db_session.add(ShadowAISighting(org_id=org_id, tool_name="midjourney", status="reviewing",
                                        seen_count=2, user_hint="bob@corp.example", last_seen_at=now))
        await db_session.commit()

        system = await _system_for(client, admin_token, "shadow:midjourney")
        m = await _metrics(client, admin_token, system["id"])
        assert m["source"] == "shadow_ai_sightings"
        assert m["counts"]["reports"] == 2
        assert m["counts"]["times_seen"] == 7
        assert m["counts"]["distinct_users"] == 2
        assert "shadow_still_in_use" in m["signals"]


class TestMetricsEdges:
    @pytest.mark.asyncio
    async def test_manual_system_has_no_activity_source(self, client, admin_token):
        r = await client.post(BASE + "/", json={"name": "paper-only"}, headers=auth_headers(admin_token))
        m = await _metrics(client, admin_token, r.json()["id"])
        assert m["source"] is None and m["signals"] == [] and m["counts"] == {}

    @pytest.mark.asyncio
    async def test_days_is_validated(self, client, admin_token):
        r = await client.post(BASE + "/", json={"name": "window"}, headers=auth_headers(admin_token))
        bad = await client.get(f"{BASE}/{r.json()['id']}/metrics", params={"days": 0},
                               headers=auth_headers(admin_token))
        assert bad.status_code == 422
        ok = await _metrics(client, admin_token, r.json()["id"], days=7)
        assert ok["window_days"] == 7

    @pytest.mark.asyncio
    async def test_other_org_gets_404(self, client, admin_token, db_session):
        r = await client.post(BASE + "/", json={"name": "private"}, headers=auth_headers(admin_token))
        await _create_org_with_admin_and_approver(
            db_session, org_slug="inv-metrics-other",
            admin_email="admin@inv-metrics.example.com", approver_email="approver@inv-metrics.example.com",
        )
        await db_session.commit()
        other = await _login(client, "inv-metrics-other", "admin@inv-metrics.example.com", "TestPass123!")
        resp = await client.get(f"{BASE}/{r.json()['id']}/metrics", headers=auth_headers(other))
        assert resp.status_code == 404
