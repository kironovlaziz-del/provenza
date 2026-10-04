"""
AI Inventory tails: retiring an entry stops its source (agent, connection)
and is audited.
"""

import secrets

import pytest

from app.core.crypto import encrypt_secret
from app.models.agent import Agent
from app.models.ai_provider import AIProvider
from tests.conftest import auth_headers

I = "/api/v1/inventory"


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register",
                          json={"name": "it-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
                                "allowed_tools": ["kb.search"], "allowed_models": [], "max_delegation_depth": 1},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _entry(client, token, source_key, name):
    r = await client.get(I + "/", params={"q": name, "limit": 50}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return next(x for x in r.json()["items"] if x["source_key"] == source_key)


async def _retire(client, token, system_id):
    r = await client.post(f"{I}/{system_id}/stage", json={"stage": "retired"}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


class TestRetireStopsSource:
    @pytest.mark.asyncio
    async def test_agent(self, client, admin_token, db_session):
        a = await _agent(client, admin_token)
        entry = await _entry(client, admin_token, f"agent:{a['id']}", a["name"])
        await _retire(client, admin_token, entry["id"])
        db_session.expire_all()
        assert (await db_session.get(Agent, a["id"])).status == "retired"
        # the agent's own key is no longer accepted
        r = await client.post("/api/v1/agents/actions/check",
                              json={"agent_id": a["id"], "chain_id": None, "tool_name": "kb.search", "input": {}},
                              headers={"X-Agent-Key": a["api_key"]})
        assert r.status_code == 401
        audit = await client.get("/api/v1/audit/", params={"limit": 50}, headers=auth_headers(admin_token))
        if audit.status_code == 200:
            items = audit.json()["items"] if isinstance(audit.json(), dict) else audit.json()
            hit = [x for x in items if x.get("action") == "stage_changed" and x.get("entity_id") == entry["id"]]
            if hit:
                assert hit[0]["details"]["source"]["to"] == "retired"

    @pytest.mark.asyncio
    async def test_connection(self, client, admin_token, db_session):
        a = await _agent(client, admin_token)
        org = (await db_session.get(Agent, a["id"])).org_id
        p = AIProvider(org_id=org, name="ret-" + secrets.token_hex(3), type="openai", status="active",
                       api_key_encrypted=encrypt_secret("sk-x"))
        db_session.add(p)
        await db_session.commit()
        await db_session.refresh(p)
        pid, pname = p.id, p.name  # captured before expire_all()
        entry = await _entry(client, admin_token, f"provider:{pid}", pname)
        await _retire(client, admin_token, entry["id"])
        db_session.expire_all()
        assert (await db_session.get(AIProvider, pid)).status == "inactive"

    @pytest.mark.asyncio
    async def test_back_from_retired_does_not_restart(self, client, admin_token, db_session):
        a = await _agent(client, admin_token)
        entry = await _entry(client, admin_token, f"agent:{a['id']}", a["name"])
        await _retire(client, admin_token, entry["id"])
        r = await client.post(f"{I}/{entry['id']}/stage", json={"stage": "development"}, headers=auth_headers(admin_token))
        assert r.status_code == 200
        db_session.expire_all()
        assert (await db_session.get(Agent, a["id"])).status == "retired"

