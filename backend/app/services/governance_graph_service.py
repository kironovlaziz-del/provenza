"""
Builds the live governance graph in a single call: agents as nodes,
delegation hops as edges, annotated with violation state and recent
activity. Kept separate from the per-entity services so the graph
endpoint does one focused set of queries rather than composing several
list calls.
"""

from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.delegation import DelegationChain, DelegationHop
from app.models.agent_action import AgentAction, AgentIncident


class GovernanceGraphService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def build(self, org_id: int, activity_window_minutes: int = 60) -> dict:
        # --- agents (nodes) ---
        agents_res = await self.db.execute(
            select(Agent).where(Agent.org_id == org_id)
        )
        agents = list(agents_res.scalars().all())

        # unresolved incidents per agent -> violation flag
        inc_res = await self.db.execute(
            select(AgentIncident.agent_id)
            .where(AgentIncident.org_id == org_id, AgentIncident.resolved == False)  # noqa: E712
            .where(AgentIncident.agent_id.isnot(None))
        )
        violating_agents = {row[0] for row in inc_res.all()}

        # recent action counts per agent -> activity level (pulse)
        since = datetime.now(timezone.utc) - timedelta(minutes=activity_window_minutes)
        act_res = await self.db.execute(
            select(AgentAction.agent_id, func.count(AgentAction.id))
            .where(AgentAction.org_id == org_id, AgentAction.created_at >= since)
            .group_by(AgentAction.agent_id)
        )
        action_counts = {row[0]: row[1] for row in act_res.all()}

        nodes = [
            {
                "id": a.id,
                "name": a.name,
                "agent_type": a.agent_type,
                "status": a.status,
                "has_violation": a.id in violating_agents,
                "action_count": int(action_counts.get(a.id, 0)),
            }
            for a in agents
        ]

        # --- hops (edges) ---
        chains_res = await self.db.execute(
            select(DelegationChain).where(DelegationChain.org_id == org_id)
        )
        chain_status = {c.id: c.status for c in chains_res.scalars().all()}

        hops_res = await self.db.execute(
            select(DelegationHop)
            .where(DelegationHop.org_id == org_id)
            .order_by(DelegationHop.id)
        )
        edges = []
        for h in hops_res.scalars().all():
            cstatus = chain_status.get(h.chain_id, "active")
            edges.append(
                {
                    "id": h.id,
                    "chain_id": h.chain_id,
                    "from_agent_id": h.from_agent_id,
                    "to_agent_id": h.to_agent_id,
                    "delegated_capabilities": list(h.delegated_capabilities or []),
                    "verified": bool(h.verified),
                    "chain_status": cstatus,
                    "is_violation": cstatus == "violated",
                    "is_tripped": cstatus == "tripped",
                }
            )

        return {
            "nodes": nodes,
            "edges": edges,
            "generated_at": datetime.now(timezone.utc),
        }
