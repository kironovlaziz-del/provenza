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
    ) -> Tuple[DelegationChain, DelegationHop]:
        """
        Record one delegation hop, creating the chain if this is the root
        delegation (chain_id is None).

        Enforces the two governance invariants before accepting the hop:
          - capability subset: what's delegated must be within what the
            delegating agent legitimately holds in this chain (its own
            capabilities at the root, or what it was granted at deeper
            hops). A superset -> capability_escalation incident + 403.
          - depth: the new hop's depth must not exceed the delegating
            agent's max_delegation_depth -> depth_exceeded incident + 403.

        The parent's Ed25519 signature (verified at the API layer against
        the from_agent's public key) is stored on the hop for offline
        auditability.
        """
        from_agent = await self._get_agent(from_agent_id, org_id)
        await self._get_agent(to_agent_id, org_id)  # ensure target exists in org

        # Determine the chain and the parent's capability set within it.
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
            parent_capabilities = list(from_agent.capabilities or [])
            new_depth = 1
        else:
            chain = await self._get_chain(chain_id, org_id)
            if chain.status != "active":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Chain is {chain.status}, cannot delegate further",
                )
            # The parent's rights within THIS chain are whatever it was
            # granted on the hop that brought it in (or its own caps if it
            # is the root acting again).
            parent_capabilities = await self._capabilities_of_agent_in_chain(
                chain_id, from_agent_id, from_agent
            )
            new_depth = chain.max_depth_reached + 1

        # Depth check against the delegating agent's own limit.
        if new_depth > from_agent.max_delegation_depth:
            await self._raise_incident(
                org_id, chain.id, from_agent_id, "depth_exceeded", "high",
                {"attempted_depth": new_depth, "max": from_agent.max_delegation_depth},
            )
            chain.status = "violated"
            await self.db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Delegation depth {new_depth} exceeds agent limit {from_agent.max_delegation_depth}",
            )

        # Escalation check: delegated must be subset of parent's rights.
        ok, escalated = validate_delegation(delegated_capabilities, parent_capabilities)
        if not ok:
            await self._raise_incident(
                org_id, chain.id, from_agent_id, "capability_escalation", "critical",
                {"escalated": escalated, "parent_had": parent_capabilities},
            )
            chain.status = "violated"
            await self.db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Capability escalation: {', '.join(escalated)} not held by delegating agent",
            )

        # TTL monotonic check: a delegation can never outlive the one that
        # authorized it. If the delegating agent's own grant expires at T,
        # anything it delegates must expire at or before T.
        parent_expiry = await self._expiry_of_agent_in_chain(chain.id, from_agent_id)
        if parent_expiry is not None:
            if expires_at is None:
                # child left it open, but parent is time-bounded -> inherit
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
            delegated_capabilities=list(delegated_capabilities or []),
            task_description=task,
            expires_at=expires_at,
            signature=signature,
            signed_payload=signed_payload,
            signer_public_key=signer_public_key if signature else None,
            pq_signature=pq_signature if signature else None,
            signer_pq_public_key=signer_pq_public_key if signature else None,
            verified=bool(signature),  # API layer verifies before calling; stored result
        )
        self.db.add(hop)
        chain.total_hops = (chain.total_hops or 0) + 1
        chain.max_depth_reached = max(chain.max_depth_reached or 0, new_depth)
        await self.db.commit()
        await self.db.refresh(hop)
        await self.db.refresh(chain)
        return chain, hop

    async def _capabilities_of_agent_in_chain(
        self, chain_id: int, agent_id: int, agent: Agent
    ) -> List[str]:
        """The capability set an agent holds within a chain: the caps it
        was granted on the most recent hop TO it, or - if it's the root
        and has no incoming hop - its own registered capabilities."""
        result = await self.db.execute(
            select(DelegationHop)
            .where(DelegationHop.chain_id == chain_id, DelegationHop.to_agent_id == agent_id)
            .order_by(DelegationHop.depth.desc())
        )
        hop = result.scalars().first()
        if hop and hop.delegated_capabilities is not None:
            return list(hop.delegated_capabilities)
        return list(agent.capabilities or [])

    async def _expiry_of_agent_in_chain(self, chain_id: int, agent_id: int):
        """The expiry the agent holds within a chain: the expires_at of the
        most recent hop TO it, or None if it's the root / has no time bound.
        Used to enforce monotonic TTL shrinkage: a delegation can never
        outlive the delegation that authorized it."""
        result = await self.db.execute(
            select(DelegationHop)
            .where(DelegationHop.chain_id == chain_id, DelegationHop.to_agent_id == agent_id)
            .order_by(DelegationHop.depth.desc())
        )
        hop = result.scalars().first()
        return hop.expires_at if hop else None

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
