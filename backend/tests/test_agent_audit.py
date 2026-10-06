"""
Integration tests for AgentAudit (app/services/agent_audit.py).

Covers action check against real agent/policy rows, recording (including
that denied actions ARE recorded and raise incidents), and the
approve/deny flow for pending actions.
"""

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

from app.services.agent_registry import AgentRegistry
from app.services.agent_audit import AgentAudit
from app.schemas.agent import AgentCreate
from app.models.agent import AgentPolicy
from app.models.agent_action import AgentAction, AgentIncident


@pytest_asyncio.fixture
async def agent(db_session, org_and_users):
    org = org_and_users["org"]
    reg = AgentRegistry(db_session)
    a, _, _ = await reg.register(org.id, None, AgentCreate(
        name="worker", capabilities=["read"], allowed_tools=["openai.chat", "db.read"],
        allowed_models=["gpt-4o-mini"], max_delegation_depth=2))
    return {"org": org, "agent": a}


class TestCheck:
    @pytest.mark.asyncio
    async def test_allowed_action(self, db_session, agent):
        audit = AgentAudit(db_session)
        d = await audit.check(agent["org"].id, agent["agent"].id, None, "tool_call",
                              "openai.chat", {"model": "gpt-4o-mini"})
        assert d.result == "allowed"

    @pytest.mark.asyncio
    async def test_denied_tool(self, db_session, agent):
        audit = AgentAudit(db_session)
        d = await audit.check(agent["org"].id, agent["agent"].id, None, "tool_call",
                              "stripe.charge", {})
        assert d.result == "denied"

    @pytest.mark.asyncio
    async def test_pending_approval_from_policy(self, db_session, agent):
        # policy requiring approval for openai.chat
        pol = AgentPolicy(org_id=agent["org"].id, name="gate", enabled=True, priority=100,
                          rules={"require_approval_tools": ["openai.chat"]})
        db_session.add(pol)
        await db_session.flush()
        audit = AgentAudit(db_session)
        d = await audit.check(agent["org"].id, agent["agent"].id, None, "tool_call",
                              "openai.chat", {"model": "gpt-4o-mini"})
        assert d.result == "pending_approval"


class TestRecord:
    @pytest.mark.asyncio
    async def test_denied_action_recorded_with_incident(self, db_session, agent):
        audit = AgentAudit(db_session)
        d = await audit.check(agent["org"].id, agent["agent"].id, None, "tool_call", "stripe.charge", {})
        action = await audit.record(agent["org"].id, agent["agent"].id, None, "tool_call",
                                    "stripe.charge", {}, None, None, None, decision=d)
        assert action.policy_check_result == "denied"
        # an incident was raised
        res = await db_session.execute(
            select(AgentIncident).where(AgentIncident.agent_id == agent["agent"].id)
        )
        assert res.scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_allowed_action_recorded_no_incident(self, db_session, agent):
        audit = AgentAudit(db_session)
        d = await audit.check(agent["org"].id, agent["agent"].id, None, "tool_call",
                              "openai.chat", {"model": "gpt-4o-mini"})
        action = await audit.record(agent["org"].id, agent["agent"].id, None, "tool_call",
                                    "openai.chat", {"model": "gpt-4o-mini"}, {"ok": True}, None, 120, decision=d)
        assert action.policy_check_result == "allowed"
        res = await db_session.execute(
            select(AgentIncident).where(AgentIncident.agent_id == agent["agent"].id)
        )
        assert res.scalar_one_or_none() is None


class TestApproveDeny:
    async def _make_pending(self, db_session, agent):
        pol = AgentPolicy(org_id=agent["org"].id, name="gate", enabled=True, priority=100,
                          rules={"require_approval_tools": ["openai.chat"]})
        db_session.add(pol)
        await db_session.flush()
        audit = AgentAudit(db_session)
        d = await audit.check(agent["org"].id, agent["agent"].id, None, "tool_call",
                              "openai.chat", {"model": "gpt-4o-mini"})
        action = await audit.record(agent["org"].id, agent["agent"].id, None, "tool_call",
                                    "openai.chat", {"model": "gpt-4o-mini"}, None, None, None, decision=d)
        return audit, action

    @pytest.mark.asyncio
    async def test_approve_pending(self, db_session, agent):
        audit, action = await self._make_pending(db_session, agent)
        assert action.policy_check_result == "pending_approval"
        approved = await audit.approve_action(action.id, agent["org"].id)
        assert approved.policy_check_result == "allowed"
        assert "approved" in (approved.reason or "").lower()

    @pytest.mark.asyncio
    async def test_deny_pending_raises_incident(self, db_session, agent):
        audit, action = await self._make_pending(db_session, agent)
        denied = await audit.deny_action(action.id, agent["org"].id, "too risky")
        assert denied.policy_check_result == "denied"
        res = await db_session.execute(
            select(AgentIncident).where(AgentIncident.agent_id == agent["agent"].id)
        )
        assert res.scalar_one_or_none() is not None

    @pytest.mark.asyncio
    async def test_cannot_approve_non_pending(self, db_session, agent):
        audit = AgentAudit(db_session)
        d = await audit.check(agent["org"].id, agent["agent"].id, None, "tool_call",
                              "openai.chat", {"model": "gpt-4o-mini"})
        action = await audit.record(agent["org"].id, agent["agent"].id, None, "tool_call",
                                    "openai.chat", {"model": "gpt-4o-mini"}, None, None, None, decision=d)
        # this action is 'allowed', not pending -> approving is a 409
        with pytest.raises(HTTPException) as exc:
            await audit.approve_action(action.id, agent["org"].id)
        assert exc.value.status_code == 409
