"""
Integration tests for DelegationService (app/services/delegation_service.py).

Covers the real chain/hop lifecycle against the DB: root delegation
creates a chain, a legitimate subset delegation is accepted, capability
escalation and depth-exceed are rejected AND raise incidents + mark the
chain violated, and the chain detail read returns ordered hops.
"""

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

from app.services.agent_registry import AgentRegistry
from app.services.delegation_service import DelegationService
from app.models.agent_action import AgentIncident
from tests.agent_keys import agent_create, register


@pytest_asyncio.fixture
async def agents(db_session, org_and_users):
    """Three agents in one org with a capability ladder."""
    org = org_and_users["org"]
    reg = AgentRegistry(db_session)
    a, _, _ = await register(reg, org.id, None, agent_create(
        name="root", capabilities=["read", "write", "delegate"], max_delegation_depth=3))
    b, _, _ = await register(reg, org.id, None, agent_create(
        name="mid", capabilities=["read", "write"], max_delegation_depth=3))
    c, _, _ = await register(reg, org.id, None, agent_create(
        name="leaf", capabilities=["read"], max_delegation_depth=1))
    return {"org": org, "a": a, "b": b, "c": c}


class TestLegitimateDelegation:
    @pytest.mark.asyncio
    async def test_root_delegation_creates_chain(self, db_session, agents):
        svc = DelegationService(db_session)
        chain, hop = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="analyze", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
        )
        assert chain.id is not None
        assert chain.status == "active"
        assert hop.depth == 1
        assert chain.total_hops == 1
        assert set(hop.delegated_capabilities) == {"read", "write"}

    @pytest.mark.asyncio
    async def test_second_hop_within_grant(self, db_session, agents):
        svc = DelegationService(db_session)
        chain, hop1 = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="t", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
        )
        # b delegates a subset (read) of what it was granted (read, write) to c
        chain2, hop2 = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["b"].id, to_agent_id=agents["c"].id,
            task="t2", delegated_capabilities=["read"], signature=None, chain_id=chain.id,
        )
        assert hop2.depth == 2
        assert chain2.max_depth_reached == 2
        assert chain2.total_hops == 2


class TestEscalation:
    @pytest.mark.asyncio
    async def test_escalation_rejected_and_incident_raised(self, db_session, agents):
        svc = DelegationService(db_session)
        # a delegates read+write to b (ok)
        chain, _ = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="t", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
        )
        # b tries to delegate "delegate" cap it was never granted -> escalation
        with pytest.raises(HTTPException) as exc:
            await svc.delegate(
                org_id=agents["org"].id, from_agent_id=agents["b"].id, to_agent_id=agents["c"].id,
                task="bad", delegated_capabilities=["read", "delegate"], signature=None, chain_id=chain.id,
            )
        assert exc.value.status_code == 403
        # an incident was recorded and the chain marked violated
        result = await db_session.execute(
            select(AgentIncident).where(AgentIncident.chain_id == chain.id,
                                        AgentIncident.incident_type == "capability_escalation")
        )
        assert result.scalar_one_or_none() is not None
        await db_session.refresh(chain)
        assert chain.status == "violated"

    @pytest.mark.asyncio
    async def test_root_cannot_delegate_beyond_own_caps(self, db_session, agents):
        svc = DelegationService(db_session)
        # a has read/write/delegate; try to delegate "admin" it never had
        with pytest.raises(HTTPException) as exc:
            await svc.delegate(
                org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
                task="x", delegated_capabilities=["admin"], signature=None, chain_id=None,
            )
        assert exc.value.status_code == 403


class TestDepth:
    @pytest.mark.asyncio
    async def test_depth_limit_enforced(self, db_session, org_and_users):
        org = org_and_users["org"]
        reg = AgentRegistry(db_session)
        # shallow agent: max depth 1
        a, _, _ = await register(reg, org.id, None, agent_create(name="d0", capabilities=["read"], max_delegation_depth=1))
        b, _, _ = await register(reg, org.id, None, agent_create(name="d1", capabilities=["read"], max_delegation_depth=1))
        c, _, _ = await register(reg, org.id, None, agent_create(name="d2", capabilities=["read"], max_delegation_depth=1))
        svc = DelegationService(db_session)
        chain, _ = await svc.delegate(
            org_id=org.id, from_agent_id=a.id, to_agent_id=b.id,
            task="t", delegated_capabilities=["read"], signature=None, chain_id=None,
        )
        # b has max_delegation_depth=1, second hop would be depth 2 -> denied
        with pytest.raises(HTTPException) as exc:
            await svc.delegate(
                org_id=org.id, from_agent_id=b.id, to_agent_id=c.id,
                task="t2", delegated_capabilities=["read"], signature=None, chain_id=chain.id,
            )
        assert exc.value.status_code == 403


class TestChainDetail:
    @pytest.mark.asyncio
    async def test_detail_returns_ordered_hops(self, db_session, agents):
        svc = DelegationService(db_session)
        chain, _ = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="t", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
        )
        await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["b"].id, to_agent_id=agents["c"].id,
            task="t2", delegated_capabilities=["read"], signature=None, chain_id=chain.id,
        )
        detail = await svc.get_chain_detail(chain.id, agents["org"].id)
        assert detail["chain"].id == chain.id
        assert len(detail["hops"]) == 2
        assert [h.depth for h in detail["hops"]] == [1, 2]
