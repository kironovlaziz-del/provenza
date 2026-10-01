# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Human approval of agent actions - OWASP Agentic Top 10, ASI09
(human-agent trust exploitation).

The attack: an agent (or a prompt injected into it) presents a dangerous
action in harmless words, and a tired reviewer clicks "approve". Defences:

  1. The reviewer sees VERIFIED facts - the exact arguments and their hash,
     the signature check, chain context, the policy that fired, the system's
     risk tier, the agent's recent denial rate - separated from UNVERIFIED
     text written by agents (chain task, delegation task descriptions).
  2. Approval is bound to the arguments: the reviewer submits the hash of
     what they saw; any difference is refused.
  3. Segregation of duties: an agent's owner cannot approve it, unless no
     other admin/approver exists in the organization (then flagged).
  4. Pending approvals expire (APPROVAL_TTL_HOURS) - a stale approval is a risk.
  5. High-risk cases and approval fatigue (many approvals in a short time)
     require typing the tool name to confirm.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import content_hash, verify_payload
from app.models.agent import Agent, AgentPolicy
from app.models.agent_action import AgentAction, AgentIncident
from app.models.ai_system import AISystem
from app.models.approval import AgentActionApproval
from app.models.delegation import DelegationChain, DelegationHop
from app.models.user import User

APPROVAL_TTL_HOURS = float(os.getenv("APPROVAL_TTL_HOURS", "24"))
FATIGUE_WINDOW_MINUTES = 10
FATIGUE_THRESHOLD = 10
HIGH_RISK_TIERS = ("high", "unacceptable")
REVIEWER_ROLES = ("admin", "approver")


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class AgentApprovalService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ helpers
    async def _action(self, org_id: int, action_id: int) -> AgentAction:
        action = (await self.db.execute(
            select(AgentAction)
            .where(AgentAction.id == action_id, AgentAction.org_id == org_id)
            .execution_options(populate_existing=True)
        )).scalar_one_or_none()
        if not action:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
        return action

    @staticmethod
    def expires_at(action: AgentAction) -> datetime:
        created = _aware(action.created_at) or datetime.now(timezone.utc)
        return created + timedelta(hours=APPROVAL_TTL_HOURS)

    async def _expire_if_stale(self, action: AgentAction) -> bool:
        """Deny a pending action whose approval window has passed."""
        if action.policy_check_result != "pending_approval":
            return False
        if datetime.now(timezone.utc) < self.expires_at(action):
            return False
        action.policy_check_result = "denied"
        action.reason = (action.reason or "") + " | approval window expired"
        self.db.add(AgentActionApproval(
            org_id=action.org_id, action_id=action.id, decision="expired",
            input_sha256=content_hash(action.input_data or {}), reason="approval window expired",
        ))
        self.db.add(AgentIncident(
            org_id=action.org_id, chain_id=action.chain_id, agent_id=action.agent_id,
            incident_type="approval_expired", severity="low",
            details={"action_id": action.id, "tool": action.tool_name, "ttl_hours": APPROVAL_TTL_HOURS},
        ))
        await self.db.commit()
        return True

    async def expire_stale(self, org_id: int) -> int:
        pending = (await self.db.execute(
            select(AgentAction).where(AgentAction.org_id == org_id,
                                      AgentAction.policy_check_result == "pending_approval")
        )).scalars().all()
        expired = 0
        for action in pending:
            if await self._expire_if_stale(action):
                expired += 1
        return expired

    async def _other_reviewers(self, org_id: int, owner_id: Optional[int]) -> int:
        q = select(func.count()).select_from(User).where(User.org_id == org_id, User.role.in_(REVIEWER_ROLES))
        if owner_id is not None:
            q = q.where(User.id != owner_id)
        return (await self.db.execute(q)).scalar_one()

    async def _recent_approvals(self, org_id: int, user_id: int) -> int:
        since = datetime.now(timezone.utc) - timedelta(minutes=FATIGUE_WINDOW_MINUTES)
        return (await self.db.execute(
            select(func.count()).select_from(AgentActionApproval).where(
                AgentActionApproval.org_id == org_id, AgentActionApproval.decided_by == user_id,
                AgentActionApproval.decision == "approved", AgentActionApproval.decided_at >= since)
        )).scalar_one()

    # ------------------------------------------------------------------ review packet
    async def review(self, org_id: int, action_id: int, user: User) -> dict:
        action = await self._action(org_id, action_id)
        await self._expire_if_stale(action)
        action = await self._action(org_id, action_id)
        agent = (await self.db.execute(select(Agent).where(Agent.id == action.agent_id))).scalar_one()
        input_sha = content_hash(action.input_data or {})

        # signature: does the agent's signature cover exactly these arguments?
        signature = {"present": bool(action.signature and action.signed_payload),
                     "valid": False, "covers_these_arguments": False}
        if signature["present"]:
            signature["valid"] = bool(agent.public_key) and verify_payload(
                action.signed_payload, action.signature, agent.public_key)
            signature["covers_these_arguments"] = (action.signed_payload or {}).get("input_sha256") == input_sha

        # chain context - facts from the server, plus text the agents wrote
        chain_info, statements = None, []
        if action.chain_id:
            chain = (await self.db.execute(
                select(DelegationChain).where(DelegationChain.id == action.chain_id, DelegationChain.org_id == org_id)
            )).scalar_one_or_none()
            hop = (await self.db.execute(
                select(DelegationHop)
                .where(DelegationHop.chain_id == action.chain_id, DelegationHop.to_agent_id == action.agent_id)
                .order_by(DelegationHop.depth.desc())
            )).scalars().first()
            if chain:
                chain_info = {"id": chain.id, "status": chain.status, "root_agent_id": chain.root_agent_id,
                              "depth": hop.depth if hop else 0,
                              "delegated_by_agent_id": hop.from_agent_id if hop else None,
                              "delegated_capabilities": list(hop.delegated_capabilities or []) if hop else None}
                if chain.root_task:
                    statements.append({"source": "chain root task", "text": chain.root_task})
            if hop and hop.task_description:
                statements.append({"source": f"delegation task from agent #{hop.from_agent_id}",
                                   "text": hop.task_description})

        policy_name = None
        if action.policy_id:
            policy_name = (await self.db.execute(
                select(AgentPolicy.name).where(AgentPolicy.id == action.policy_id)
            )).scalar_one_or_none()

        system = (await self.db.execute(
            select(AISystem).where(AISystem.org_id == org_id, AISystem.agent_id == action.agent_id)
        )).scalars().first()
        risk_tier = system.effective_risk_tier if system else None

        since = datetime.now(timezone.utc) - timedelta(days=7)
        rows = dict((await self.db.execute(
            select(AgentAction.policy_check_result, func.count())
            .where(AgentAction.org_id == org_id, AgentAction.agent_id == agent.id, AgentAction.created_at >= since)
            .group_by(AgentAction.policy_check_result)
        )).all())
        total = sum(rows.values())

        decision = (await self.db.execute(
            select(AgentActionApproval).where(AgentActionApproval.action_id == action.id)
        )).scalar_one_or_none()

        # can THIS user decide, and what will they be asked for?
        flags: List[str] = []
        if risk_tier in HIGH_RISK_TIERS:
            flags.append("high_risk_system")
        if "argument '" in (action.reason or ""):
            flags.append("argument_rule")
        if await self._recent_approvals(org_id, user.id) >= FATIGUE_THRESHOLD:
            flags.append("fatigue")
        blocked_reason, self_approval = None, False
        if agent.owner_user_id is not None and agent.owner_user_id == user.id:
            if await self._other_reviewers(org_id, user.id) > 0:
                blocked_reason = "You own this agent; another admin or approver must decide."
            else:
                self_approval = True

        return {
            "action": {
                "id": action.id, "agent_id": action.agent_id, "chain_id": action.chain_id,
                "action_type": action.action_type, "tool_name": action.tool_name,
                "input": action.input_data or {}, "status": action.policy_check_result,
                "reason": action.reason, "created_at": action.created_at,
            },
            "verified": {
                "input_sha256": input_sha,
                "signature": signature,
                "check_id": action.check_id,
                "policy": {"id": action.policy_id, "name": policy_name},
                "agent": {"id": agent.id, "name": agent.name, "status": agent.status,
                          "owner_user_id": agent.owner_user_id, "owner_team": agent.owner_team,
                          "allowed_tools": list(agent.allowed_tools or [])},
                "chain": chain_info,
                "inventory": {"system_id": system.id if system else None, "risk_tier": risk_tier,
                              "risk_confirmed": bool(system and system.confirmed_risk_tier)},
                "recent_7d": {"actions": total, "denied": rows.get("denied", 0),
                              "denial_rate": round(rows.get("denied", 0) / total, 3) if total else None},
            },
            "unverified_statements": statements,
            "decision": None if decision is None else {
                "decision": decision.decision, "decided_by": decision.decided_by,
                "decided_at": decision.decided_at, "reason": decision.reason,
                "self_approved": decision.self_approved,
            },
            "reviewer": {
                "can_decide": action.policy_check_result == "pending_approval" and blocked_reason is None,
                "blocked_reason": blocked_reason,
                "self_approval": self_approval,
                "requires_typed_confirmation": bool(flags),
                "confirmation_text": action.tool_name or "",
                "flags": flags,
                "expires_at": self.expires_at(action),
            },
        }

    # ------------------------------------------------------------------ decisions
    async def _guard(self, org_id: int, action_id: int, user: User, input_sha256: str) -> tuple:
        packet = await self.review(org_id, action_id, user)
        action = await self._action(org_id, action_id)
        if action.policy_check_result != "pending_approval":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Action is '{action.policy_check_result}', not pending approval")
        if packet["reviewer"]["blocked_reason"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=packet["reviewer"]["blocked_reason"])
        if input_sha256 != packet["verified"]["input_sha256"]:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="The arguments differ from what was reviewed; reload and review again")
        return packet, action

    async def approve(self, org_id: int, action_id: int, user: User,
                      input_sha256: str, confirmation: Optional[str]) -> dict:
        packet, action = await self._guard(org_id, action_id, user, input_sha256)
        rv = packet["reviewer"]
        typed = False
        if rv["requires_typed_confirmation"]:
            if (confirmation or "").strip() != rv["confirmation_text"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Type the tool name '{rv['confirmation_text']}' to confirm "
                           f"({', '.join(rv['flags'])})",
                )
            typed = True
        action.policy_check_result = "allowed"
        action.reason = (action.reason or "") + f" | approved by user #{user.id}"
        self.db.add(AgentActionApproval(
            org_id=org_id, action_id=action.id, decision="approved", decided_by=user.id,
            input_sha256=input_sha256, self_approved=rv["self_approval"],
            typed_confirmation=typed, flags=rv["flags"] or None,
        ))
        await self.db.commit()
        return {"flags": rv["flags"], "self_approved": rv["self_approval"]}

    async def deny(self, org_id: int, action_id: int, user: User,
                   input_sha256: Optional[str], reason: Optional[str]) -> None:
        action = await self._action(org_id, action_id)
        await self._expire_if_stale(action)
        action = await self._action(org_id, action_id)
        if action.policy_check_result != "pending_approval":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"Action is '{action.policy_check_result}', not pending approval")
        # denying is always allowed (also for the owner) - refusing can't be exploited
        action.policy_check_result = "denied"
        action.reason = (action.reason or "") + f" | denied by user #{user.id}: {reason or 'no reason given'}"
        self.db.add(AgentActionApproval(
            org_id=org_id, action_id=action.id, decision="denied", decided_by=user.id,
            input_sha256=content_hash(action.input_data or {}), reason=reason,
        ))
        self.db.add(AgentIncident(
            org_id=org_id, chain_id=action.chain_id, agent_id=action.agent_id,
            incident_type="policy_violation", severity="high",
            details={"tool": action.tool_name, "reason": "denied at human approval", "action_id": action.id},
        ))
        await self.db.commit()

    async def pending(self, org_id: int) -> list:
        await self.expire_stale(org_id)
        rows = (await self.db.execute(
            select(AgentAction, Agent.name)
            .join(Agent, Agent.id == AgentAction.agent_id)
            .where(AgentAction.org_id == org_id, AgentAction.policy_check_result == "pending_approval")
            .order_by(AgentAction.created_at)
        )).all()
        return [
            {"id": a.id, "agent_id": a.agent_id, "agent_name": name, "chain_id": a.chain_id,
             "tool_name": a.tool_name, "reason": a.reason, "created_at": a.created_at,
             "expires_at": self.expires_at(a)}
            for a, name in rows
        ]
