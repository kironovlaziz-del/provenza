# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.delegation import DelegationChain, DelegationHop
from app.models.agent_action import AgentIncident
from app.services.capability_validator import validate_delegation


def _aware(dt):
    """Datetimes compared here are UTC; tolerate a naive one."""
    from datetime import timezone

    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=timezone.utc)


class DelegationService:
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

    async def _raise_incident(
        self, org_id: int, chain_id: Optional[int], agent_id: int, itype: str, severity: str, details: dict
    ) -> None:
        self.db.add(
            AgentIncident(
                org_id=org_id, chain_id=chain_id, agent_id=agent_id,
                incident_type=itype, severity=severity, details=details,
            )
        )

    async def delegate(
        self,
        org_id: int,
        from_agent_id: int,
        to_agent_id: int,
        task: str,
        delegated_capabilities: List[str],
        signature: Optional[str],
        chain_id: Optional[int],
        expires_at=None,
        signed_payload: Optional[dict] = None,
        signer_public_key: Optional[str] = None,
        pq_signature: Optional[str] = None,
        signer_pq_public_key: Optional[str] = None,
        delegated_tools: Optional[List[str]] = None,
        verified: bool = False,
    ) -> Tuple[DelegationChain, DelegationHop]:
        """
        Record one delegation hop, creating the chain if this is the root
        delegation (chain_id is None). All checks are made here, on the
        server, against rights the server computes (services/agent_rights.py):

          - both agents are active members of the organization; an agent
            cannot delegate to itself;
          - in an existing chain the delegating agent must be a member (the
            root, or reached by a hop) and its own grant must not have expired;
          - capabilities and tools: a subset of the delegating agent's rights
            in this chain -> otherwise capability_escalation incident + 403;
            tools not named are inherited from the parent, never widened;
          - depth: the parent's depth + 1, within both the delegating agent's
            and the chain root's max_delegation_depth -> depth_exceeded + 403;
          - TTL: never beyond the parent's own expiry -> ttl_escalation + 403.

        `verified` is the API layer's signature verdict, stored as is.
        """
        from datetime import datetime, timezone

        from app.services.agent_rights import own_rights, rights_in_chain

        from_agent = await self._get_agent(from_agent_id, org_id)
        to_agent = await self._get_agent(to_agent_id, org_id)
        if from_agent.id == to_agent.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="delegation.self")
        for agent in (from_agent, to_agent):
            if agent.status != "active":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                    detail=f"delegation.agent_not_active: agent {agent.id} is {agent.status}")
        now = datetime.now(timezone.utc)

        if chain_id is None:
            chain = DelegationChain(
                org_id=org_id,
                root_agent_id=from_agent_id,
                root_task=task,
                status="active",
                total_hops=0,
                max_depth_reached=0,
            )
            self.db.add(chain)
            await self.db.flush()
            parent = own_rights(from_agent)
            root = from_agent
        else:
            chain = await self._get_chain(chain_id, org_id)
            if chain.status != "active":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Chain is {chain.status}, cannot delegate further",
                )
            parent = await rights_in_chain(self.db, from_agent, chain)
            if not parent.member:
                # an outsider writing itself into someone else's chain
                await self._raise_incident(org_id, chain.id, from_agent_id, "not_in_chain", "high",
                                           {"to_agent_id": to_agent_id})
                await self.db.commit()
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail="delegation.not_in_chain: the delegating agent is not part of this chain")
            exp = _aware(parent.expires_at)
            if exp is not None and exp <= now:
                await self._raise_incident(org_id, chain.id, from_agent_id, "delegation_expired", "medium",
                                           {"to_agent_id": to_agent_id, "expired_at": exp.isoformat()})
                await self.db.commit()
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail="delegation.expired: the delegating agent's own grant has expired")
            root = await self._get_agent(chain.root_agent_id, org_id)

        new_depth = parent.depth + 1
        limit = min(from_agent.max_delegation_depth, root.max_delegation_depth)
        # and within the policy hierarchy's limit for the delegating agent
        from app.services import hier_policy

        # ... for the delegating agent and for the one receiving the work (its
        # actions are checked against its own limit - accepting a delegation
        # it could never act under would only fail later, on every action)
        for party in (from_agent, to_agent):
            _, policy_depth = await hier_policy.engine_policies(self.db, party)
            if policy_depth is not None:
                limit = min(limit, policy_depth)
        if new_depth > limit:
            await self._raise_incident(
                org_id, chain.id, from_agent_id, "depth_exceeded", "high",
                {"attempted_depth": new_depth, "max": limit},
            )
            chain.status = "violated"
            await self.db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Delegation depth {new_depth} exceeds the limit {limit}",
            )

        ok, escalated = validate_delegation(delegated_capabilities, parent.capabilities)
        if delegated_tools is not None:
            tools = sorted({str(t) for t in delegated_tools})
        elif parent.tools_narrowed:
            tools = list(parent.tools)       # a narrowed list is inherited, never widened
        else:
            tools = None                     # nobody named tools yet: each agent keeps its own
        ok_tools, escalated_tools = (True, []) if tools is None else validate_delegation(tools, parent.tools)
        if not ok or not ok_tools:
            await self._raise_incident(
                org_id, chain.id, from_agent_id, "capability_escalation", "critical",
                {"escalated": escalated, "parent_had": parent.capabilities,
                 "escalated_tools": escalated_tools, "parent_tools": parent.tools},
            )
            chain.status = "violated"
            await self.db.commit()
            what = ", ".join(escalated + [f"tool {t}" for t in escalated_tools])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Capability escalation: {what} not held by delegating agent",
            )

        # TTL monotonic: a delegation can never outlive the one that authorized it
        parent_expiry = _aware(parent.expires_at)
        expires_at = _aware(expires_at)
        if parent_expiry is not None:
            if expires_at is None:
                expires_at = parent_expiry
            elif expires_at > parent_expiry:
                await self._raise_incident(
                    org_id, chain.id, from_agent_id, "ttl_escalation", "critical",
                    {"requested_expiry": expires_at.isoformat(),
                     "parent_expiry": parent_expiry.isoformat()},
                )
                chain.status = "violated"
                await self.db.commit()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"TTL escalation: delegation cannot outlive its parent "
                           f"(requested {expires_at.isoformat()}, parent expires {parent_expiry.isoformat()})",
                )

        hop = DelegationHop(
            org_id=org_id,
            chain_id=chain.id,
            from_agent_id=from_agent_id,
            to_agent_id=to_agent_id,
            depth=new_depth,
            delegated_capabilities=sorted({str(c) for c in delegated_capabilities or []}),
            delegated_tools=tools,
            task_description=task,
            expires_at=expires_at,
            signature=signature,
            signed_payload=signed_payload,
            signer_public_key=signer_public_key if signature else None,
            pq_signature=pq_signature if signature else None,
            signer_pq_public_key=signer_pq_public_key if signature else None,
            verified=bool(verified and signature),
        )
        self.db.add(hop)
        chain.total_hops = (chain.total_hops or 0) + 1
        chain.max_depth_reached = max(chain.max_depth_reached or 0, new_depth)
        await self.db.commit()
        await self.db.refresh(hop)
        await self.db.refresh(chain)
        return chain, hop

    async def _get_chain(self, chain_id: int, org_id: int) -> DelegationChain:
        result = await self.db.execute(
            select(DelegationChain).where(
                DelegationChain.id == chain_id, DelegationChain.org_id == org_id
            )
        )
        chain = result.scalar_one_or_none()
        if not chain:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chain not found")
        return chain

    async def get_chain_detail(self, chain_id: int, org_id: int) -> dict:
        """Full chain view: chain + ordered hops (for the graph UI and
        the GET endpoint)."""
        chain = await self._get_chain(chain_id, org_id)
        hops_result = await self.db.execute(
            select(DelegationHop)
            .where(DelegationHop.chain_id == chain_id)
            .order_by(DelegationHop.depth, DelegationHop.id)
        )
        hops = list(hops_result.scalars().all())
        return {"chain": chain, "hops": hops}

    async def list_chains(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> Tuple[List[DelegationChain], int]:
        from sqlalchemy import func as sqlfunc
        base = select(DelegationChain).where(DelegationChain.org_id == org_id)
        total = await self.db.scalar(select(sqlfunc.count()).select_from(base.subquery()))
        result = await self.db.execute(
            base.order_by(DelegationChain.started_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)
