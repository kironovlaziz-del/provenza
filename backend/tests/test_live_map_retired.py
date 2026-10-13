"""A retired agent leaves the live map, with the edges that touch it."""

import pytest

from app.models.agent import Agent
from app.models.delegation import DelegationChain, DelegationHop
from tests.conftest import auth_headers


@pytest.mark.asyncio
async def test_retired_agents_are_not_on_the_map(client, db_session, org_and_users, admin_token):
    org_id = org_and_users["org"].id
    a = Agent(org_id=org_id, name="keeper", status="active", api_key_hash="a" * 64, capabilities=[], allowed_tools=[], allowed_models=[])
    b = Agent(org_id=org_id, name="gone", status="active", api_key_hash="b" * 64, capabilities=[], allowed_tools=[], allowed_models=[])
    db_session.add_all([a, b])
    await db_session.flush()
    chain = DelegationChain(org_id=org_id, root_agent_id=a.id, status="active")
    db_session.add(chain)
    await db_session.flush()
    db_session.add(DelegationHop(org_id=org_id, chain_id=chain.id, from_agent_id=a.id, to_agent_id=b.id,
                                 delegated_capabilities=[], depth=1))
    await db_session.flush()

    g = (await client.get("/api/v1/agents/graph", headers=auth_headers(admin_token))).json()
    assert {n["name"] for n in g["nodes"]} >= {"keeper", "gone"} and len(g["edges"]) == 1

    b.status = "retired"
    await db_session.flush()
    g = (await client.get("/api/v1/agents/graph", headers=auth_headers(admin_token))).json()
    names = {n["name"] for n in g["nodes"]}
    assert "keeper" in names and "gone" not in names
    assert g["edges"] == []
