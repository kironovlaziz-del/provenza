"""
Integration tests for AgentRegistry (app/services/agent_registry.py)
against the transactional test DB.

Covers registration (secrets returned once, only hash+public key stored),
org-scoped lookup/isolation, and the kill-switch cascade that suspends an
agent and terminates its active chains.
"""

import pytest
import pytest_asyncio

from app.services.agent_registry import AgentRegistry
from app.models.agent import Agent
from app.models.delegation import DelegationChain
from app.core.security import hash_api_key
from tests.conftest import _create_org_with_admin_and_approver
from tests.agent_keys import agent_create, register


@pytest_asyncio.fixture
async def two_orgs(db_session):
    """Two separate orgs, to prove cross-tenant isolation."""
    a = await _create_org_with_admin_and_approver(db_session, org_slug="org-a", admin_email="a@x.com", approver_email="a2@x.com")
    b = await _create_org_with_admin_and_approver(db_session, org_slug="org-b", admin_email="b@x.com", approver_email="b2@x.com")
    return a, b


class TestRegister:
    @pytest.mark.asyncio
    async def test_register_returns_secrets_once_and_stores_hash(self, db_session, org_and_users):
        org = org_and_users["org"]
        admin = org_and_users["admin"]
        reg = AgentRegistry(db_session)
        agent, raw_key, priv = await register(reg, 
            org.id, admin.id,
            agent_create(name="a1", capabilities=["read"], allowed_tools=["openai.chat"],
                        allowed_models=["gpt-4o-mini"], max_delegation_depth=2),
        )
        # secrets returned
        assert raw_key and priv
        # only the HASH is stored, never the raw key
        assert agent.api_key_hash == hash_api_key(raw_key)
        assert agent.api_key_hash != raw_key
        # public key stored, private key is NOT on the model
        assert agent.public_key
        assert not hasattr(agent, "private_key") or getattr(agent, "private_key", None) is None
        assert agent.status == "active"

    @pytest.mark.asyncio
    async def test_authenticate_by_raw_key(self, db_session, org_and_users):
        org = org_and_users["org"]
        reg = AgentRegistry(db_session)
        agent, raw_key, _ = await register(reg, org.id, None, agent_create(name="a2"))
        found = await reg.authenticate(org.id, raw_key)
        assert found is not None and found.id == agent.id
        # wrong key resolves to nothing
        assert await reg.authenticate(org.id, "aict_wrongkey") is None


class TestIsolation:
    @pytest.mark.asyncio
    async def test_get_agent_is_org_scoped(self, db_session, two_orgs):
        a, b = two_orgs
        reg = AgentRegistry(db_session)
        agent_a, _, _ = await register(reg, a["org"].id, None, agent_create(name="only-in-a"))
        # org B cannot fetch org A's agent
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            await reg.get_agent(agent_a.id, b["org"].id)

    @pytest.mark.asyncio
    async def test_list_is_org_scoped(self, db_session, two_orgs):
        a, b = two_orgs
        reg = AgentRegistry(db_session)
        await register(reg, a["org"].id, None, agent_create(name="a-agent"))
        await register(reg, b["org"].id, None, agent_create(name="b-agent"))
        items_a, total_a = await reg.list_agents(a["org"].id)
        names_a = {x.name for x in items_a}
        assert "a-agent" in names_a and "b-agent" not in names_a


class TestKillSwitch:
    @pytest.mark.asyncio
    async def test_kill_suspends_and_cascades(self, db_session, org_and_users):
        org = org_and_users["org"]
        reg = AgentRegistry(db_session)
        agent, _, _ = await register(reg, org.id, None, agent_create(name="rooter"))
        # an active chain rooted at this agent
        chain = DelegationChain(org_id=org.id, root_agent_id=agent.id, status="active")
        db_session.add(chain)
        await db_session.flush()

        stopped, terminated = await reg.kill_agent(agent.id, org.id, "compromise", cascade=True)
        assert stopped == [agent.id]
        assert terminated == 1

        # agent is suspended, chain terminated
        refreshed = await reg.get_agent(agent.id, org.id)
        assert refreshed.status == "suspended"
        await db_session.refresh(chain)
        assert chain.status == "terminated"

    @pytest.mark.asyncio
    async def test_kill_without_cascade_leaves_chains(self, db_session, org_and_users):
        org = org_and_users["org"]
        reg = AgentRegistry(db_session)
        agent, _, _ = await register(reg, org.id, None, agent_create(name="rooter2"))
        chain = DelegationChain(org_id=org.id, root_agent_id=agent.id, status="active")
        db_session.add(chain)
        await db_session.flush()

        stopped, terminated = await reg.kill_agent(agent.id, org.id, "x", cascade=False)
        assert terminated == 0
        await db_session.refresh(chain)
        assert chain.status == "active"  # untouched
