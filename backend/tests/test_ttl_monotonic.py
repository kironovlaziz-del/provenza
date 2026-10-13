"""
Tests for monotonic TTL shrinkage in delegation (feedback from an
automation PhD on the Dev.to writeup): a delegation can never outlive the
delegation that authorized it. Symmetric to the capability subset check —
time only shrinks down a chain, never grows.
"""

import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from sqlalchemy import select

from app.services.agent_registry import AgentRegistry
from app.services.delegation_service import DelegationService
from app.models.agent_action import AgentIncident
from tests.agent_keys import agent_create, register

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def agents(db_session, org_and_users):
    org = org_and_users["org"]
    reg = AgentRegistry(db_session)
    a, _, _ = await register(reg, org.id, None, agent_create(
        name="root", capabilities=["read", "write", "delegate"], max_delegation_depth=3))
    b, _, _ = await register(reg, org.id, None, agent_create(
        name="mid", capabilities=["read", "write"], max_delegation_depth=3))
    c, _, _ = await register(reg, org.id, None, agent_create(
        name="leaf", capabilities=["read"], max_delegation_depth=1))
    return {"org": org, "a": a, "b": b, "c": c}


def _in(minutes):
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


class TestTTLMonotonic:
    async def test_child_within_parent_ttl_is_accepted(self, db_session, agents):
        svc = DelegationService(db_session)
        parent_exp = _in(10)
        # root -> b, expires in 10 min
        chain, hop_b = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="t", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
            expires_at=parent_exp,
        )
        # b -> c, expires in 5 min (within parent's 10) -> OK
        chain2, hop_c = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["b"].id, to_agent_id=agents["c"].id,
            task="t2", delegated_capabilities=["read"], signature=None, chain_id=chain.id,
            expires_at=_in(5),
        )
        assert hop_c.id is not None
        assert hop_c.expires_at <= parent_exp

    async def test_child_exceeding_parent_ttl_is_rejected(self, db_session, agents):
        svc = DelegationService(db_session)
        parent_exp = _in(5)
        chain, _ = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="t", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
            expires_at=parent_exp,
        )
        # b tries to grant c a LONGER ttl than it holds -> rejected
        with pytest.raises(HTTPException) as exc:
            await svc.delegate(
                org_id=agents["org"].id, from_agent_id=agents["b"].id, to_agent_id=agents["c"].id,
                task="t2", delegated_capabilities=["read"], signature=None, chain_id=chain.id,
                expires_at=_in(60),  # way past parent's 5 min
            )
        assert exc.value.status_code == 403
        assert "TTL escalation" in str(exc.value.detail)

    async def test_ttl_escalation_raises_incident_and_violates_chain(self, db_session, agents):
        svc = DelegationService(db_session)
        chain, _ = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="t", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
            expires_at=_in(5),
        )
        with pytest.raises(HTTPException):
            await svc.delegate(
                org_id=agents["org"].id, from_agent_id=agents["b"].id, to_agent_id=agents["c"].id,
                task="t2", delegated_capabilities=["read"], signature=None, chain_id=chain.id,
                expires_at=_in(60),
            )
        # incident recorded
        res = await db_session.execute(
            select(AgentIncident).where(AgentIncident.incident_type == "ttl_escalation")
        )
        incidents = list(res.scalars().all())
        assert len(incidents) >= 1
        # chain marked violated
        await db_session.refresh(chain)
        assert chain.status == "violated"

    async def test_child_without_expiry_inherits_parent(self, db_session, agents):
        svc = DelegationService(db_session)
        parent_exp = _in(10)
        chain, _ = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="t", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
            expires_at=parent_exp,
        )
        # b -> c with NO expiry, but parent is bounded -> child inherits parent's expiry
        _, hop_c = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["b"].id, to_agent_id=agents["c"].id,
            task="t2", delegated_capabilities=["read"], signature=None, chain_id=chain.id,
            expires_at=None,
        )
        assert hop_c.expires_at == parent_exp

    async def test_root_without_expiry_allows_any_child_ttl(self, db_session, agents):
        svc = DelegationService(db_session)
        # root -> b with NO expiry (unbounded)
        chain, _ = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["a"].id, to_agent_id=agents["b"].id,
            task="t", delegated_capabilities=["read", "write"], signature=None, chain_id=None,
            expires_at=None,
        )
        # b -> c can set any expiry, since parent has no bound
        _, hop_c = await svc.delegate(
            org_id=agents["org"].id, from_agent_id=agents["b"].id, to_agent_id=agents["c"].id,
            task="t2", delegated_capabilities=["read"], signature=None, chain_id=chain.id,
            expires_at=_in(120),
        )
        assert hop_c.expires_at is not None
