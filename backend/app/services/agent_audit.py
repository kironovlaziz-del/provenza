# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent, AgentPolicy
from app.models.delegation import DelegationChain, DelegationHop
from app.models.agent_action import AgentAction, AgentIncident, ActionCheck
from app.core.agent_signing import content_hash
from app.services.agent_policy_engine import (
    check_action,
    AgentView,
    ChainView,
    ActionContext,
    ALLOWED,
    DENIED,
    Decision,
)

# How long a /actions/check verdict stays usable for /actions/record.
CHECK_TTL_SECONDS = 300


class AgentAudit:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_agent(self, agent_id: int, org_id: int) -> Agent:
        result = await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
        )
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return agent

    async def _chain_view(self, chain_id: Optional[int], agent_id: int, agent: Agent) -> ChainView:
        if chain_id is None:
            return ChainView(max_depth_reached=0, granted_capabilities=list(agent.capabilities or []))
        result = await self.db.execute(
            select(DelegationChain).where(
                DelegationChain.id == chain_id, DelegationChain.org_id == agent.org_id
            )
        )
        chain = result.scalar_one_or_none()
        if not chain:
            # an unknown chain, or one belonging to another organization
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delegation chain not found")
        # capabilities granted to this agent within the chain
        hop_result = await self.db.execute(
            select(DelegationHop)
            .where(DelegationHop.chain_id == chain_id, DelegationHop.to_agent_id == agent_id)
            .order_by(DelegationHop.depth.desc())
        )
        hop = hop_result.scalars().first()
        granted = (
            list(hop.delegated_capabilities)
            if hop and hop.delegated_capabilities is not None
            else list(agent.capabilities or [])
        )
        expiry = hop.expires_at if hop else None
        return ChainView(
            max_depth_reached=chain.max_depth_reached or 0,
            status=chain.status,
            granted_capabilities=granted,
            delegation_expires_at=expiry,
        )

    async def _custom_policies(self, org_id: int, agent_id: int) -> List[dict]:
        """Enabled agent policies that apply: those scoped to this agent
        plus org-wide ones (agent_id IS NULL), highest priority first."""
        result = await self.db.execute(
            select(AgentPolicy).where(
                AgentPolicy.org_id == org_id,
                AgentPolicy.enabled == True,  # noqa: E712
                ((AgentPolicy.agent_id == agent_id) | (AgentPolicy.agent_id.is_(None))),
            ).order_by(AgentPolicy.priority.desc())
        )
        return [
            {"id": p.id, "name": p.name, "rules": p.rules or {}}
            for p in result.scalars().all()
        ]

    async def check(
        self,
        org_id: int,
        agent_id: int,
        chain_id: Optional[int],
        action_type: Optional[str],
        tool_name: Optional[str],
        input_data: dict,
        action_capabilities: List[str],
        tool_version: Optional[str] = None,
        tool_digest: Optional[str] = None,
    ):
        """Run the policy engine for a proposed action. Returns the
        Decision (does not persist - use record() for that)."""
        agent = await self._get_agent(agent_id, org_id)
        agent_view = AgentView(
            allowed_tools=list(agent.allowed_tools or []),
            allowed_models=list(agent.allowed_models or []),
            max_delegation_depth=agent.max_delegation_depth,
            status=agent.status,
        )
        chain_view = await self._chain_view(chain_id, agent_id, agent)
        ctx = ActionContext(
            tool_name=tool_name,
            action_type=action_type,
            input_data=input_data or {},
            action_capabilities=action_capabilities or [],
        )
        policies = await self._custom_policies(org_id, agent_id)
        decision = check_action(agent_view, chain_view, ctx, policies)
        # ASI04: Tool Registry (also records usage when the policy already denied)
        from app.services.supply_chain import SupplyChain
        supply = await SupplyChain(self.db).verify(org_id, agent_id, tool_name, tool_version, tool_digest)
        if decision.result == DENIED:
            return decision
        if supply is not None:
            return supply
        # ASI01: injected instructions in the arguments, tainted chain
        from app.services.injection_guard import InjectionGuard
        decision = await InjectionGuard(self.db).apply(org_id, agent_id, chain_id, tool_name, input_data, decision)
        # ASI05: shell / eval / SQL / traversal shapes in the arguments, code tools
        from app.services.code_exec_guard import CodeExecGuard
        return await CodeExecGuard(self.db).apply(org_id, agent_id, chain_id, tool_name, input_data, decision)

    async def record(
        self,
        org_id: int,
        agent_id: int,
        chain_id: Optional[int],
        action_type: Optional[str],
        tool_name: Optional[str],
        input_data: dict,
        output_data: Optional[dict],
        signature: Optional[str],
        duration_ms: Optional[int],
        decision=None,
        check_id: Optional[int] = None,
        signed_payload: Optional[dict] = None,
        signer_public_key: Optional[str] = None,
        pq_signature: Optional[str] = None,
        signer_pq_public_key: Optional[str] = None,
    ) -> AgentAction:
        """
        Persist an action row. If a Decision is supplied, its verdict and
        reason are stored, and a denial with an incident_type also raises
        an AgentIncident. Recording happens for denied actions too - the
        record of what an agent TRIED is the whole point.
        """
        action = AgentAction(
            org_id=org_id,
            agent_id=agent_id,
            chain_id=chain_id,
            action_type=action_type,
            tool_name=tool_name,
            input_data=input_data,
            output_data=output_data,
            policy_check_result=decision.result if decision else None,
            policy_id=decision.matched_policy_id if decision else None,
            reason=decision.reason if decision else None,
            signature=signature,
            duration_ms=duration_ms,
            check_id=check_id,
            signed_payload=signed_payload,
            signer_public_key=signer_public_key if signature else None,
            pq_signature=pq_signature if signature else None,
            signer_pq_public_key=signer_pq_public_key if signature else None,
        )
        self.db.add(action)

        if decision and decision.result == DENIED and decision.incident_type:
            self.db.add(
                AgentIncident(
                    org_id=org_id,
                    chain_id=chain_id,
                    agent_id=agent_id,
                    incident_type=decision.incident_type,
                    severity="high" if decision.incident_type == "depth_exceeded" else "critical",
                    details={"tool": tool_name, "reason": decision.reason},
                )
            )

        await self.db.commit()
        await self.db.refresh(action)
        return action

    async def issue_check(
        self,
        org_id: int,
        agent_id: int,
        chain_id: Optional[int],
        action_type: Optional[str],
        tool_name: Optional[str],
        input_data: dict,
        action_capabilities: List[str],
        decision,
    ) -> ActionCheck:
        """Persist a verdict as a single-use, short-lived check bound to
        exactly this action. The returned token is what the agent must
        present to /actions/record."""
        chk = ActionCheck(
            token=secrets.token_urlsafe(32),
            org_id=org_id,
            agent_id=agent_id,
            chain_id=chain_id,
            action_type=action_type,
            tool_name=tool_name,
            input_sha256=content_hash(input_data or {}),
            action_capabilities=sorted(action_capabilities or []),
            decision=decision.result,
            reason=decision.reason,
            incident_type=decision.incident_type,
            policy_id=decision.matched_policy_id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=CHECK_TTL_SECONDS),
        )
        self.db.add(chk)
        await self.db.commit()
        await self.db.refresh(chk)
        return chk

    async def consume_check(
        self,
        org_id: int,
        token: str,
        *,
        agent_id: int,
        chain_id: Optional[int],
        action_type: Optional[str],
        tool_name: Optional[str],
        input_data: dict,
    ):
        """Validate and burn a check token for a recorded action. Returns
        (check, Decision-from-check-time). Raises 404 unknown / 409 reused /
        400 expired / 400 mismatch; a mismatch also raises an
        `action_mismatch` incident, because recording something other than
        what was checked is exactly the attack this binding exists for."""
        res = await self.db.execute(
            select(ActionCheck)
            .where(ActionCheck.token == token, ActionCheck.org_id == org_id)
            .with_for_update()
        )
        chk = res.scalar_one_or_none()
        if not chk:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown check_id")
        if chk.used_at is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="check_id already used")
        now = datetime.now(timezone.utc)
        if chk.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="check_id expired; call /actions/check again",
            )

        mismatched = [
            name for name, checked, recorded in (
                ("agent_id", chk.agent_id, agent_id),
                ("chain_id", chk.chain_id, chain_id),
                ("action_type", chk.action_type, action_type),
                ("tool_name", chk.tool_name, tool_name),
                ("input", chk.input_sha256, content_hash(input_data or {})),
            )
            if checked != recorded
        ]
        chk.used_at = now  # burned either way - no probing with one token
        if mismatched:
            self.db.add(
                AgentIncident(
                    org_id=org_id,
                    chain_id=chk.chain_id,
                    agent_id=chk.agent_id,
                    incident_type="action_mismatch",
                    severity="critical",
                    details={
                        "check_id": chk.id,
                        "mismatched": mismatched,
                        "checked_tool": chk.tool_name,
                        "recorded_tool": tool_name,
                        "recorded_by_agent": agent_id,
                    },
                )
            )
            await self.db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Recorded action does not match its check: {', '.join(mismatched)}",
            )

        decision = Decision(
            result=chk.decision,
            reason=chk.reason or "",
            incident_type=chk.incident_type,
            matched_policy_id=chk.policy_id,
        )
        return chk, decision

    async def _get_action(self, action_id: int, org_id: int) -> AgentAction:
        result = await self.db.execute(
            select(AgentAction).where(
                AgentAction.id == action_id, AgentAction.org_id == org_id
            )
        )
        action = result.scalar_one_or_none()
        if not action:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
        return action

    async def approve_action(self, action_id: int, org_id: int) -> AgentAction:
        """
        Approve a pending action so the agent may proceed. Only actions in
        'pending_approval' can be approved; approving flips the verdict to
        'allowed' and records who/when in the reason. Anything else is a
        409 (you can't approve an already-decided action).
        """
        action = await self._get_action(action_id, org_id)
        if action.policy_check_result != "pending_approval":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Action is '{action.policy_check_result}', not pending approval",
            )
        action.policy_check_result = "allowed"
        action.reason = (action.reason or "") + " | approved by human reviewer"
        await self.db.commit()
        await self.db.refresh(action)
        return action

    async def deny_action(self, action_id: int, org_id: int, reason: Optional[str]) -> AgentAction:
        """Deny a pending action. Flips it to 'denied' and raises a
        policy_violation incident so the refusal is on the audit trail."""
        action = await self._get_action(action_id, org_id)
        if action.policy_check_result != "pending_approval":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Action is '{action.policy_check_result}', not pending approval",
            )
        action.policy_check_result = "denied"
        action.reason = (action.reason or "") + f" | denied by human reviewer: {reason or 'no reason given'}"
        self.db.add(
            AgentIncident(
                org_id=org_id,
                chain_id=action.chain_id,
                agent_id=action.agent_id,
                incident_type="policy_violation",
                severity="high",
                details={"tool": action.tool_name, "reason": "denied at human approval"},
            )
        )
        await self.db.commit()
        await self.db.refresh(action)
        return action

    async def list_actions(
        self, org_id: int, chain_id: Optional[int] = None, agent_id: Optional[int] = None,
        result_filter: Optional[str] = None, skip: int = 0, limit: int = 50,
    ) -> Tuple[List[AgentAction], int]:
        from sqlalchemy import func as sqlfunc
        base = select(AgentAction).where(AgentAction.org_id == org_id)
        if chain_id is not None:
            base = base.where(AgentAction.chain_id == chain_id)
        if agent_id is not None:
            base = base.where(AgentAction.agent_id == agent_id)
        if result_filter is not None:
            base = base.where(AgentAction.policy_check_result == result_filter)
        total = await self.db.scalar(select(sqlfunc.count()).select_from(base.subquery()))
        result = await self.db.execute(
            base.order_by(AgentAction.created_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)
