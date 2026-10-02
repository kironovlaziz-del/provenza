# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from typing import List, Optional, Tuple

from fastapi import HTTPException, status

from app.core.errors import api_error
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import generate_api_key, hash_api_key
from app.core.agent_signing import generate_keypair, generate_pq_keypair, key_fingerprint
from app.models.agent import Agent, AgentSigningKey
from app.models.delegation import DelegationChain
from app.schemas.agent import AgentCreate, AgentUpdate


class AgentRegistry:
    def __init__(self, db: AsyncSession):
        self.db = db
        # ML-DSA-65 seed of the last server-generated hybrid key (shown once
        # by the register endpoint; never stored)
        self.generated_pq_private_key: Optional[str] = None

    async def register(
        self, org_id: int, created_by: Optional[int], data: AgentCreate
    ) -> Tuple[Agent, str, Optional[str]]:
        """
        Register a new agent. Returns (agent, raw_api_key, private_key_b64).
        The API key is shown ONCE and only its hash is stored.

        Signing key: with data.public_key (and, for a hybrid key,
        data.pq_public_key) the agent brought its own keys, the server never
        sees the private halves and private_key_b64 is None (key_origin
        "agent"). Without it the keys are generated here and returned once,
        not stored (key_origin "server"); key_scheme "hybrid" adds ML-DSA-65,
        whose seed is left in self.generated_pq_private_key.
        """
        raw_key = generate_api_key()
        self.generated_pq_private_key = None
        pq_public_key_b64 = None
        if data.public_key:
            await self._check_key_is_new(data.public_key, agent_id=None, pq_public_key=data.pq_public_key)
            private_key_b64, public_key_b64, origin = None, data.public_key, "agent"
            pq_public_key_b64 = data.pq_public_key
        else:
            private_key_b64, public_key_b64 = generate_keypair()
            origin = "server"
            if data.key_scheme == "hybrid":
                self.generated_pq_private_key, pq_public_key_b64 = generate_pq_keypair()
        await self._check_org_policy(org_id, pq_public_key_b64)

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
            pq_public_key=pq_public_key_b64,
            key_origin=origin,
        )
        self.db.add(agent)
        await self.db.flush()
        self.db.add(AgentSigningKey(
            org_id=org_id, agent_id=agent.id, public_key=public_key_b64, pq_public_key=pq_public_key_b64,
            fingerprint=key_fingerprint(public_key_b64, pq_public_key_b64), origin=origin, created_by=created_by,
        ))
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

    async def set_signing_key(self, agent_id: int, org_id: int, public_key: str,
                              user_id: Optional[int], pq_public_key: Optional[str] = None,
                              ) -> Tuple[Agent, Optional[str]]:
        """Make `public_key` (agent-held, already validated) the agent's
        signing key. The previous key is retired in the history, and records
        it signed keep verifying with it (they carry signer_public_key).
        Returns (agent, previous_fingerprint)."""
        # lock the agent row: two concurrent key changes must not both win
        agent = (await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id).with_for_update()
        )).scalar_one_or_none()
        if agent is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        previous = key_fingerprint(agent.public_key, agent.pq_public_key)
        if agent.public_key == public_key and agent.pq_public_key == pq_public_key:
            return agent, previous
        await self._check_org_policy(org_id, pq_public_key)
        await self._check_key_is_new(public_key, agent_id=agent.id, pq_public_key=pq_public_key)
        now = func.now()
        current = (await self.db.execute(
            select(AgentSigningKey).where(AgentSigningKey.agent_id == agent.id,
                                          AgentSigningKey.retired_at.is_(None))
        )).scalars().all()
        for row in current:
            row.retired_at = now
        await self.db.flush()  # retire before inserting: one current key per agent
        self.db.add(AgentSigningKey(
            org_id=org_id, agent_id=agent.id, public_key=public_key, pq_public_key=pq_public_key,
            fingerprint=key_fingerprint(public_key, pq_public_key), origin="agent", created_by=user_id,
        ))
        agent.public_key = public_key
        agent.pq_public_key = pq_public_key
        agent.key_origin = "agent"
        await self.db.commit()
        await self.db.refresh(agent)
        return agent, previous

    async def _check_org_policy(self, org_id: int, pq_public_key: Optional[str]) -> None:
        """With require_pq_signatures on, every new key must be hybrid."""
        from app.services.agent_identity import org_settings
        if not pq_public_key and (await org_settings(self.db, org_id)).get("require_pq_signatures"):
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "agent.pq_required")

    async def _check_key_is_new(self, public_key: str, agent_id: Optional[int],
                                pq_public_key: Optional[str] = None) -> None:
        """An agent-held key must be new: never another agent's key (in any
        organization), and never a key this server generated - otherwise a
        key whose private half passed through the server could be relabelled
        "agent-held". Re-activating the agent's own earlier agent-held key is
        allowed."""
        from sqlalchemy import or_
        cond = AgentSigningKey.public_key == public_key
        if pq_public_key:
            cond = or_(cond, AgentSigningKey.pq_public_key == pq_public_key)
        rows = (await self.db.execute(
            select(AgentSigningKey.agent_id, AgentSigningKey.origin).where(cond)
        )).all()
        for owner, origin in rows:
            if origin == "server":
                raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "agent.key_server_generated")
            if owner != agent_id:
                raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "agent.key_in_use")

    async def signing_keys(self, agent_id: int, org_id: int) -> List[AgentSigningKey]:
        await self.get_agent(agent_id, org_id)
        result = await self.db.execute(
            select(AgentSigningKey).where(AgentSigningKey.agent_id == agent_id, AgentSigningKey.org_id == org_id)
            .order_by(AgentSigningKey.created_at.desc(), AgentSigningKey.id.desc())
        )
        return list(result.scalars().all())

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
