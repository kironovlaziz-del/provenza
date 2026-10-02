"""
Agent telemetry retention (Queue & Retention): old policy checks are deleted
unless something still refers to them, old agent/LLM content is erased while
the rows stay, "keep indefinitely" disables both, and omitted settings keep
their value.
"""

import secrets
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction
from tests.conftest import auth_headers

Q = "/api/v1/queue"
BASE = {"queue_ttl_seconds": 900, "approval_ttl_hours": 72, "raw_prompt_retention_days": None}


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register",
                          json={"name": "ret-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
                                "allowed_tools": ["db.read"], "allowed_models": [], "max_delegation_depth": 1},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _check(org_id, agent_id, age_days):
    when = datetime.now(timezone.utc) - timedelta(days=age_days)
    c = ActionCheck(token=secrets.token_urlsafe(24), org_id=org_id, agent_id=agent_id, tool_name="db.read",
                    input_sha256="0" * 64, decision="allowed", reason="ok", expires_at=when + timedelta(minutes=5))
    if hasattr(ActionCheck, "created_at"):
        c.created_at = when
    return c


async def _settings(client, token, **over):
    r = await client.put(Q + "/settings", json={**BASE, **over}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


class TestTelemetryRetention:
    @pytest.mark.asyncio
    async def test_checks_and_content(self, client, admin_token, db_session):
        agent_id = await _agent(client, admin_token)
        org_id = (await db_session.get(Agent, agent_id)).org_id
        old_free, old_used, fresh = _check(org_id, agent_id, 40), _check(org_id, agent_id, 40), _check(org_id, agent_id, 1)
        db_session.add_all([old_free, old_used, fresh])
        await db_session.flush()
        old_action = AgentAction(org_id=org_id, agent_id=agent_id, action_type="tool_call", tool_name="db.read",
                                 input_data={"customer": "jane@example.com"}, output_data={"rows": 1},
                                 policy_check_result="allowed", check_id=old_used.id,
                                 created_at=datetime.now(timezone.utc) - timedelta(days=40))
        new_action = AgentAction(org_id=org_id, agent_id=agent_id, action_type="tool_call", tool_name="db.read",
                                 input_data={"q": "recent"}, policy_check_result="allowed")
        db_session.add_all([old_action, new_action])
        await db_session.flush()
        ids = {"free": old_free.id, "used": old_used.id, "fresh": fresh.id, "old_action": old_action.id,
               "new_action": new_action.id}
        await db_session.commit()

        # keep indefinitely: nothing happens
        s = await _settings(client, admin_token, agent_check_retention_days=None, agent_content_retention_days=None)
        assert s["agent_check_retention_days"] is None
        r = (await client.post(Q + "/sweep", headers=auth_headers(admin_token))).json()
        assert r["purged_checks"] == 0 and r["scrubbed_content"] == 0

        await _settings(client, admin_token, agent_check_retention_days=30, agent_content_retention_days=30)
        r = (await client.post(Q + "/sweep", headers=auth_headers(admin_token))).json()
        assert r["purged_checks"] >= 1 and r["scrubbed_content"] >= 1

        db_session.expire_all()
        left = set((await db_session.execute(
            select(ActionCheck.id).where(ActionCheck.id.in_([ids["free"], ids["used"], ids["fresh"]])))).scalars())
        assert left == {ids["used"], ids["fresh"]}          # referenced and recent checks stay
        rows = {a.id: a for a in (await db_session.execute(
            select(AgentAction).where(AgentAction.id.in_([ids["old_action"], ids["new_action"]])))).scalars()}
        assert ids["old_action"] in rows                     # the row stays for the audit trail
        assert not rows[ids["old_action"]].input_data and not rows[ids["old_action"]].output_data
        assert rows[ids["old_action"]].tool_name == "db.read"
        assert rows[ids["new_action"]].input_data == {"q": "recent"}

        sweeps = (await client.get(Q + "/", headers=auth_headers(admin_token))).json()["sweeps"]
        assert sweeps[0]["purged_checks"] >= 1

    @pytest.mark.asyncio
    async def test_omitted_settings_are_kept_and_validated(self, client, admin_token):
        await _settings(client, admin_token, agent_check_retention_days=45, agent_content_retention_days=120)
        s = await _settings(client, admin_token)              # only the original three keys
        assert s["agent_check_retention_days"] == 45 and s["agent_content_retention_days"] == 120
        bad = await client.put(Q + "/settings", json={**BASE, "agent_check_retention_days": 0}, headers=auth_headers(admin_token))
        assert bad.status_code == 422
