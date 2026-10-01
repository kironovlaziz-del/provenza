# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_key, hash_api_key
from app.core.agent_signing import generate_keypair
from app.models.agent import Agent
from app.models.delegation import DelegationChain
from app.schemas.agent import AgentCreate, AgentUpdate


class AgentRegistry:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def register(
        self, org_id: int, created_by: Optional[int], data: AgentCreate
    ) -> Tuple[Agent, str, str]:
        """
        Register a new agent. Returns (agent, raw_api_key,
        private_key_b64). Both secrets are shown to the caller ONCE and
        never stored in retrievable form: only the API key HASH and the
        PUBLIC key are persisted. This mirrors IngestionSource for the
        API key, and adds an Ed25519 keypair so the agent can sign its
        delegations and actions.
        """
        raw_key = generate_api_key()
        private_key_b64, public_key_b64 = generate_keypair()

        agent = Agent(
            org_id=org_id,
            name=data.name,
            description=data.description,
            agent_type=data.agent_type,
            version=data.version,
            owner_user_id=created_by,
            owner_team=data.owner_team,
            capabilities=data.capabilities or [],
            allowed_tools=data.allowed_tools or [],
            allowed_models=data.allowed_models or [],
            max_delegation_depth=data.max_delegation_depth,
            status="active",
            api_key_hash=hash_api_key(raw_key),
            public_key=public_key_b64,
        )
        self.db.add(agent)
        await self.db.commit()
        await self.db.refresh(agent)
        return agent, raw_key, private_key_b64

    async def list_agents(
        self, org_id: int, skip: int = 0, limit: int = 50
    ) -> Tuple[List[Agent], int]:
        base = select(Agent).where(Agent.org_id == org_id)
        total = await self.db.scalar(select(func.count()).select_from(base.subquery()))
        result = await self.db.execute(
            base.order_by(Agent.created_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def get_agent(self, agent_id: int, org_id: int) -> Agent:
        result = await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
        )
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        return agent

    async def update_agent(self, agent_id: int, org_id: int, data: AgentUpdate) -> Agent:
        agent = await self.get_agent(agent_id, org_id)
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(agent, field, value)
        await self.db.commit()
        await self.db.refresh(agent)
        return agent

    async def kill_agent(
        self, agent_id: int, org_id: int, reason: Optional[str], cascade: bool
    ) -> Tuple[List[int], int]:
        """
        Kill-switch: suspend an agent immediately. With cascade=True, also
        terminate every active delegation chain the agent roots and (via
        the chain) stop its descendants' work by marking those chains
        'terminated'. Returns (stopped_agent_ids, terminated_chain_count).

        Suspending the agent flips its status so the policy engine denies
        every subsequent action (see agent_policy_engine's status check) -
        that's the actual enforcement; terminating chains records the
        blast radius and stops new hops being accepted on them.
        """
        agent = await self.get_agent(agent_id, org_id)
        agent.status = "suspended"
        stopped = [agent.id]
        terminated = 0

        if cascade:
            result = await self.db.execute(
                select(DelegationChain).where(
                    DelegationChain.org_id == org_id,
                    DelegationChain.root_agent_id == agent_id,
                    DelegationChain.status.in_(("active", "tripped")),
                )
            )
            for chain in result.scalars().all():
                chain.status = "terminated"
                chain.completed_at = func.now()
                terminated += 1

        await self.db.commit()
        return stopped, terminated

    async def authenticate(self, org_id: int, raw_key: str) -> Optional[Agent]:
        """Resolve an agent from its raw API key (hash lookup). Used where
        an agent authenticates itself rather than a user."""
        result = await self.db.execute(
            select(Agent).where(
                Agent.org_id == org_id, Agent.api_key_hash == hash_api_key(raw_key)
            )
        )
        return result.scalar_one_or_none()
