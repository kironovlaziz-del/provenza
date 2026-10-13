"""
Tests for the rejected-escalation views (feedback from a GTWY engineer:
log every rejected escalation separately, and surface repeat offenders).

The escalation data was already written by delegation_service; these test
the new ways to query it: filter incidents by type, unresolved-only, and
the per-agent escalation summary (worst offender first).
"""

import pytest

from tests.conftest import auth_headers
from app.models.agent_action import AgentIncident
from app.services.agent_registry import AgentRegistry
from tests.agent_keys import agent_create, register

pytestmark = pytest.mark.asyncio


async def _make_agent(db, org_id, name):
    """Create a real agent via the registry so incident FKs resolve."""
    reg = AgentRegistry(db)
    agent, _, _ = await register(reg, org_id, None, agent_create(name=name, capabilities=["read"]))
    return agent.id


async def _add_incident(db, org_id, agent_id, itype, resolved=False):
    inc = AgentIncident(
        org_id=org_id, chain_id=None, agent_id=agent_id,
        incident_type=itype, severity="critical",
        details={"escalated": ["write"], "parent_had": ["read"]},
        resolved=resolved,
    )
    db.add(inc)
    await db.flush()
    return inc


class TestIncidentTypeFilter:
    async def test_filter_by_type_returns_only_that_type(self, client, db_session, org_and_users, admin_token):
        org_id = org_and_users["org"].id
        a1 = await _make_agent(db_session, org_id, "a1")
        a2 = await _make_agent(db_session, org_id, "a2")
        await _add_incident(db_session, org_id, a1, "capability_escalation")
        await _add_incident(db_session, org_id, a1, "depth_exceeded")
        await _add_incident(db_session, org_id, a2, "capability_escalation")
        await db_session.commit()

        resp = await client.get(
            "/api/v1/agents/incidents/?incident_type=capability_escalation",
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 2
        assert all(i["incident_type"] == "capability_escalation" for i in items)

    async def test_no_filter_returns_all(self, client, db_session, org_and_users, admin_token):
        org_id = org_and_users["org"].id
        a1 = await _make_agent(db_session, org_id, "b1")
        await _add_incident(db_session, org_id, a1, "capability_escalation")
        await _add_incident(db_session, org_id, a1, "depth_exceeded")
        await db_session.commit()

        resp = await client.get("/api/v1/agents/incidents/", headers=auth_headers(admin_token))
        assert resp.status_code == 200
        assert resp.json()["total"] == 2


class TestUnresolvedFilter:
    async def test_unresolved_only(self, client, db_session, org_and_users, admin_token):
        org_id = org_and_users["org"].id
        a1 = await _make_agent(db_session, org_id, "c1")
        await _add_incident(db_session, org_id, a1, "capability_escalation", resolved=False)
        await _add_incident(db_session, org_id, a1, "capability_escalation", resolved=True)
        await db_session.commit()

        resp = await client.get(
            "/api/v1/agents/incidents/?unresolved_only=true",
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1


class TestEscalationSummary:
    async def test_repeat_offender_counts_and_order(self, client, db_session, org_and_users, admin_token):
        org_id = org_and_users["org"].id
        heavy = await _make_agent(db_session, org_id, "heavy")
        light = await _make_agent(db_session, org_id, "light")
        for _ in range(3):
            await _add_incident(db_session, org_id, heavy, "capability_escalation")
        await _add_incident(db_session, org_id, light, "capability_escalation")
        await _add_incident(db_session, org_id, heavy, "depth_exceeded")  # not counted
        await db_session.commit()

        resp = await client.get(
            "/api/v1/agents/incidents/escalation-summary",
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 200
        agents = resp.json()["agents"]
        assert agents[0]["agent_id"] == heavy
        assert agents[0]["attempts"] == 3
        assert agents[1]["agent_id"] == light
        assert agents[1]["attempts"] == 1

    async def test_summary_counts_only_escalations(self, client, db_session, org_and_users, admin_token):
        org_id = org_and_users["org"].id
        a1 = await _make_agent(db_session, org_id, "d1")
        await _add_incident(db_session, org_id, a1, "capability_escalation")
        await _add_incident(db_session, org_id, a1, "depth_exceeded")
        await _add_incident(db_session, org_id, a1, "policy_violation")
        await db_session.commit()

        resp = await client.get(
            "/api/v1/agents/incidents/escalation-summary",
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 200
        agents = resp.json()["agents"]
        total = sum(a["attempts"] for a in agents)
        assert total == 1  # only the capability_escalation
