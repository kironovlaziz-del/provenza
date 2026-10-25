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
from app.models.delegation import DelegationChain
from app.models.agent_action import AgentAction, AgentIncident, ActionCheck
from app.core.agent_signing import content_hash
from app.services.agent_rights import Rights
from app.services.agent_policy_engine import (
    check_action,
    AgentView,
    ChainView,
    ActionContext,
    ALLOWED,
    DENIED,
    MODEL_ACTION,
    PENDING_APPROVAL,
    Decision,
)

# How long a /actions/check verdict stays usable for /actions/record.
CHECK_TTL_SECONDS = 300
RANK = {ALLOWED: 0, PENDING_APPROVAL: 1, DENIED: 2}


def stricter(live: Decision, signed: Decision, number: int) -> Decision:
    """The verdict of the working copy and of the signed policy together: a
    denial or an approval requirement of either applies. The signed side's
    reason says where it comes from."""
    if RANK.get(signed.result, 2) > RANK.get(live.result, 2):
        out = Decision(signed.result, f"signed policy (release #{number}): {signed.reason}", signed.incident_type,
                       matched_policy_id=signed.matched_policy_id)
    else:
        out = live
    out.required_capabilities = sorted(set(getattr(live, "required_capabilities", None) or [])
                                       | set(getattr(signed, "required_capabilities", None) or []))
    return out


async def signed_rows_refusal(db: AsyncSession, signed, org_id: int, action_type: Optional[str],
                              tool_name: Optional[str], input_data: dict) -> Optional[str]:
    """Why the configuration that would serve this action is not the signed
    one, or None. Every enabled row that could carry the call - the MCP
    server of its tool, its A2A peer, its HTTP tool, its egress route, the
    LLM gateway route of its model - must be in the signed policy exactly as
    it is configured now: the call goes where the row says, so a changed
    row serves nothing until it is signed."""
    from app.pvp import policy_bundle as pb

    tool = tool_name or ""
    checks = []                     # (section, row id, live view)
    if "." in tool:
        prefix, rest = tool.split(".", 1)
        from app.models.mcp import MCPServer

        for s in (await db.execute(select(MCPServer).where(MCPServer.org_id == org_id, MCPServer.slug == prefix,
                                                            MCPServer.enabled.is_(True)))).scalars():
            checks.append(("mcp_servers", s.id, pb.mcp_server_view(s), f"MCP server '{s.slug}'"))
        if prefix == "a2a":
            from app.models.a2a_gateway import A2APeer

            for p in (await db.execute(select(A2APeer).where(A2APeer.org_id == org_id, A2APeer.slug == rest,
                                                              A2APeer.enabled.is_(True)))).scalars():
                checks.append(("a2a_peers", p.id, pb.a2a_peer_view(p), f"A2A peer '{p.slug}'"))
        if prefix == "proxy" and action_type == "proxy":
            from app.models.egress_proxy import EgressRoute

            for r in (await db.execute(select(EgressRoute).where(EgressRoute.org_id == org_id,
                                                                  EgressRoute.slug == rest,
                                                                  EgressRoute.enabled.is_(True)))).scalars():
                checks.append(("egress_routes", r.id, pb.egress_route_view(r), f"egress route '{r.slug}'"))
        if action_type == MODEL_ACTION:
            from app.services.gateway_service import GatewayService

            found = await GatewayService(db)._route(org_id, str((input_data or {}).get("model") or rest))
            if found is not None:
                checks.append(("gateway.routes", found[0].id, pb.route_view(found[0]),
                               f"gateway route '{found[0].model}'"))
                checks.append(("ai_providers", found[1].id, pb.provider_view(found[1]),
                               f"AI connection '{found[1].name}'"))
    if tool:
        from app.models.http_tool import HttpTool

        for t in (await db.execute(select(HttpTool).where(HttpTool.org_id == org_id, HttpTool.name == tool,
                                                           HttpTool.enabled.is_(True)))).scalars():
            checks.append(("http_tools", t.id, pb.http_tool_view(t), f"HTTP tool '{t.name}'"))
    for section, row_id, view, what in checks:
        if section == "ai_providers" and section not in signed.bundle:
            continue    # a release signed before connections were in the bundle does not state them
        if signed.row(section, row_id) != view:
            return f"the {what} is not configured as in the signed policy (release #{signed.number})"
    return None


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

    async def _chain_view(self, chain_id: Optional[int], agent_id: int, agent) -> Tuple[ChainView, Rights]:
        """The chain as the engine sees it, and the agent's rights in it -
        computed by the server (services/agent_rights.py)."""
        from app.services.agent_rights import own_rights, rights_in_chain

        if chain_id is None:
            rights = own_rights(agent)
            return ChainView(max_depth_reached=0, granted_capabilities=rights.capabilities), rights
        result = await self.db.execute(
            select(DelegationChain).where(
                DelegationChain.id == chain_id, DelegationChain.org_id == agent.org_id
            )
        )
        chain = result.scalar_one_or_none()
        if not chain:
            # an unknown chain, or one belonging to another organization
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delegation chain not found")
        rights = await rights_in_chain(self.db, agent, chain)
        return ChainView(
            max_depth_reached=rights.depth,  # the agent's own depth, not the deepest branch
            root_agent_id=chain.root_agent_id,
            status=chain.status,
            granted_capabilities=rights.capabilities,
            delegation_expires_at=rights.expires_at,
            member=rights.member,
        ), rights

    async def _custom_policies(self, org_id: int, agent) -> List[dict]:
        """Enabled agent policies that apply: those scoped to this agent
        plus org-wide ones (agent_id IS NULL), highest priority first."""
        result = await self.db.execute(
            select(AgentPolicy).where(
                AgentPolicy.org_id == org_id,
                AgentPolicy.enabled == True,  # noqa: E712
                ((AgentPolicy.agent_id == agent.id) | (AgentPolicy.agent_id.is_(None))),
            ).order_by(AgentPolicy.priority.desc())
        )
        own = [
            {"id": p.id, "name": p.name, "rules": p.rules or {}}
            for p in result.scalars().all()
        ]
        # the policy hierarchy (organization -> team -> agent) first: its
        # refusals name the level that refused
        levels, _ = await self._hierarchy(agent)
        return levels + own

    async def _hierarchy(self, agent):
        """The policy hierarchy as engine policies + its depth limit, once per
        agent per service instance (a check reads it twice)."""
        cache = self.__dict__.setdefault("_hier_cache", {})
        if agent.id not in cache:
            from app.services import hier_policy

            cache[agent.id] = await hier_policy.engine_policies(self.db, agent)
        return cache[agent.id]

    async def check(
        self,
        org_id: int,
        agent_id: int,
        chain_id: Optional[int],
        action_type: Optional[str],
        tool_name: Optional[str],
        input_data: dict,
        tool_version: Optional[str] = None,
        tool_digest: Optional[str] = None,
    ):
        """Run the policy engine for a proposed action. Returns the
        Decision (does not persist - use record() for that).

        The tools and capabilities the agent holds are its rights in the
        chain, and what the action needs comes from the Tool Registry -
        nothing the caller declares is trusted.

        Once the organization has a signed policy in force
        (app/pvp/signed_policy.py), the action must be allowed by the
        working copy AND by the signed policy: the stricter verdict wins."""
        from app.pvp import signed_policy

        live = await self._evaluate(org_id, agent_id, chain_id, action_type, tool_name, input_data,
                                    tool_version, tool_digest)
        signed = await signed_policy.in_force(self.db, org_id)
        if signed is None or live.result == DENIED:
            return live
        held = await self._evaluate_signed(signed, org_id, agent_id, chain_id, action_type, tool_name,
                                           input_data, tool_version, tool_digest)
        return stricter(live, held, signed.number)

    async def _evaluate_signed(self, signed, org_id, agent_id, chain_id, action_type, tool_name, input_data,
                               tool_version, tool_digest) -> Decision:
        """The signed policy's verdict (app/pvp/bundle_eval.py), with what only
        the server knows looked up here: the live agent and its key, the rows
        that would carry the call, and the agent's rights in a delegation chain."""
        from app.core.agent_signing import key_fingerprint
        from app.pvp import bundle_eval

        live = await self._get_agent(agent_id, org_id)
        why = signed.refusal()
        view = None
        if why is None:
            view, why = signed.agent(live)
        if why is None:
            why = await signed_rows_refusal(self.db, signed, org_id, action_type, tool_name, input_data)
        if why is not None:
            return Decision(DENIED, why, None)
        chain = None
        if chain_id is not None:
            chain_view, rights = await self._chain_view(chain_id, agent_id, view)
            depth_limit = view.max_delegation_depth
            if rights.member and rights.depth > 0:
                root, why = signed.agent(await self._get_agent(chain_view.root_agent_id, org_id))
                if root is None:
                    return Decision(DENIED, why, None)
                depth_limit = root.max_delegation_depth
            chain = (chain_view, rights, depth_limit)
        return bundle_eval.evaluate(signed, agent_id=agent_id, action_type=action_type, tool_name=tool_name,
                                    input_data=input_data, key_fingerprint=key_fingerprint(live.public_key,
                                                                                           live.pq_public_key),
                                    tool_version=tool_version, tool_digest=tool_digest, chain=chain)

    async def _evaluate(self, org_id, agent_id, chain_id, action_type, tool_name, input_data, tool_version,
                        tool_digest):
        """The working copy's verdict."""
        from app.services.agent_rights import required_capabilities

        agent = await self._get_agent(agent_id, org_id)
        chain_view, rights = await self._chain_view(chain_id, agent_id, agent)
        # depth: the agent's own place in the chain, within the chain root's limit
        # (delegation already enforces each delegating agent's limit)
        depth_limit = agent.max_delegation_depth
        if chain_id is not None and rights.member and rights.depth > 0:
            root = await self._get_agent(chain_view.root_agent_id, org_id)
            depth_limit = root.max_delegation_depth
        _, policy_depth = await self._hierarchy(agent)
        if policy_depth is not None:
            depth_limit = min(depth_limit, policy_depth)
        agent_view = AgentView(
            allowed_tools=list(rights.tools),
            allowed_models=list(agent.allowed_models or []),
            max_delegation_depth=depth_limit,
            status=agent.status,
        )
        if action_type == "egress":
            # a direct call to an AI provider: the AI domain catalog is the right (app/pvp/egress.py)
            from app.pvp import egress

            _, refusal = await egress.classify(self.db, org_id, tool_name, input_data)
            if refusal is not None:
                return refusal
            agent_view.allowed_tools.append(tool_name)
        elif action_type == MODEL_ACTION:
            # a call through the LLM gateway: the right is the model (allowed_models and
            # models.allow, checked by the engine), not an entry in the tool list
            agent_view.allowed_tools.append(tool_name)
        elif action_type == "proxy":
            # a request through an egress proxy: the route's own rules first (app/pvp/egress_proxy.py);
            # the right to the route is "proxy.<route>" in the agent's tools, as for any tool
            from app.pvp import egress_proxy

            refusal = await egress_proxy.route_refusal(self.db, org_id, tool_name, input_data)
            if refusal is not None:
                return refusal
        required = await required_capabilities(self.db, org_id, tool_name)
        ctx = ActionContext(
            tool_name=tool_name,
            action_type=action_type,
            input_data=input_data or {},
            action_capabilities=required,
        )
        decision = await self._decide(org_id, agent, chain_id, tool_name, input_data, tool_version, tool_digest,
                                      agent_view, chain_view, ctx)
        decision.required_capabilities = list(required)  # one derivation, used for the verdict and stored
        return decision

    async def _decide(self, org_id, agent, chain_id, tool_name, input_data, tool_version, tool_digest,
                      agent_view, chain_view, ctx):
        policies = await self._custom_policies(org_id, agent)
        decision = check_action(agent_view, chain_view, ctx, policies)
        # ASI04: Tool Registry (also records usage when the policy already denied);
        # provider hosts of egress actions live in the AI domain catalog instead
        from app.services.supply_chain import SupplyChain
        # (egress-proxy routes in the route table, LLM gateway models in its routes)
        supply = None if ctx.action_type in ("egress", "proxy", MODEL_ACTION) else \
            await SupplyChain(self.db).verify(org_id, agent.id, tool_name, tool_version, tool_digest)
        if decision.result == DENIED:
            return decision
        if supply is not None:
            return supply
        return decision

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
        executed_by: Optional[str] = None,
        check_token: Optional[str] = None,
        witness: Optional[dict] = None,
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
            executed_by=executed_by,
            witness=witness,
            # set here, not by the database, so the evidence below can carry it
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(action)
        if decision is not None:
            # the PVP evidence of the action as recorded (app/pvp/evidence.py)
            from app.pvp.evidence import stamp

            await self.db.flush()
            stamp(action, check_token)

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
