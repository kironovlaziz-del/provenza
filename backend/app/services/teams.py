# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Teams and role templates: org -> team (-> sub-team) -> agent.

- A team is an entity (teams.id); agents point to it by agents.team_id.
  The old free-text owner_team is kept only as the team's name for display.
- A role template is a named set of rights. An agent with a role has
  exactly the role's capabilities, tools, models and depth; changing the
  role changes them on every agent that has it, and the agent's own rights
  cannot be edited while it has a role.
- A team-owned role can only be given to agents of that team; an org-wide
  role (team_id NULL) to any agent.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import status
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import api_error
from app.models.agent import Agent
from app.models.enrollment import AgentEnrollment
from app.models.policy_layer import PolicyLayer
from app.models.team import RoleTemplate, Team

RIGHTS = ("capabilities", "allowed_tools", "allowed_models", "max_delegation_depth")


def team_out(t: Team, agents: int = 0, roles: int = 0) -> Dict[str, Any]:
    return {"id": t.id, "name": t.name, "description": t.description, "parent_id": t.parent_id,
            "agents": agents, "roles": roles}


def role_out(r: RoleTemplate, agents: int = 0) -> Dict[str, Any]:
    return {"id": r.id, "team_id": r.team_id, "name": r.name, "description": r.description,
            "capabilities": list(r.capabilities or []), "allowed_tools": list(r.allowed_tools or []),
            "allowed_models": list(r.allowed_models or []), "max_delegation_depth": r.max_delegation_depth,
            "require_hybrid": r.require_hybrid, "require_attestation": r.require_attestation,
            "attestation_policy_id": r.attestation_policy_id, "agents": agents}


async def get_team(db: AsyncSession, org_id: int, team_id: Optional[int]) -> Optional[Team]:
    if team_id is None:
        return None
    t = (await db.execute(select(Team).where(Team.id == team_id, Team.org_id == org_id))).scalar_one_or_none()
    if t is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "team.not_found")
    return t


async def get_role(db: AsyncSession, org_id: int, role_id: Optional[int],
                   lock: Optional[str] = None) -> Optional[RoleTemplate]:
    """lock: "update" - the role is being changed; "share" - it is being given
    to an agent, so a concurrent change (e.g. to require_hybrid) waits and the
    checks made here stay true until commit."""
    if role_id is None:
        return None
    q = select(RoleTemplate).where(RoleTemplate.id == role_id, RoleTemplate.org_id == org_id)
    if lock:
        q = q.with_for_update(read=lock == "share").execution_options(populate_existing=True)
    r = (await db.execute(q)).scalar_one_or_none()
    if r is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "role.not_found")
    return r


def check_role_fits_team(role: Optional[RoleTemplate], team_id: Optional[int]) -> None:
    """A team's role is only for that team's agents."""
    if role is not None and role.team_id is not None and role.team_id != team_id:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "role.other_team")


def _clean_name(v: Optional[str], code: str = "team.name_required") -> str:
    v = (v or "").strip()
    if not v:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, code)
    return v


async def _lock_hierarchy(db: AsyncSession, org_id: int) -> None:
    """Changes to an organization's team tree are serialized: two concurrent
    re-parentings could each pass the cycle check and together make a cycle."""
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('provenza.teams'), :org)"), {"org": int(org_id)})


async def role_requires_hybrid(db: AsyncSession, agent: Agent) -> bool:
    if not agent.role_id:
        return False
    r = await db.get(RoleTemplate, agent.role_id)
    return bool(r is not None and r.require_hybrid)


# --------------------------------------------------------------------------- teams

async def list_teams(db: AsyncSession, org_id: int) -> List[Dict[str, Any]]:
    teams = list((await db.execute(select(Team).where(Team.org_id == org_id).order_by(Team.name))).scalars())
    agents = dict((await db.execute(
        select(Agent.team_id, func.count()).where(Agent.org_id == org_id, Agent.team_id.is_not(None),
                                                  Agent.status != "retired")
        .group_by(Agent.team_id))).all())
    roles = dict((await db.execute(
        select(RoleTemplate.team_id, func.count()).where(RoleTemplate.org_id == org_id,
                                                         RoleTemplate.team_id.is_not(None))
        .group_by(RoleTemplate.team_id))).all())
    return [team_out(t, agents.get(t.id, 0), roles.get(t.id, 0)) for t in teams]


async def _check_parent(db: AsyncSession, org_id: int, team_id: Optional[int], parent_id: Optional[int]) -> None:
    """The parent exists in the organization and is not the team or one of its descendants."""
    seen = set()
    current = parent_id
    while current is not None:
        if current == team_id or current in seen:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "team.parent_cycle")
        seen.add(current)
        current = (await get_team(db, org_id, current)).parent_id


async def create_team(db: AsyncSession, org_id: int, user_id: int, values: Dict[str, Any]) -> Team:
    await _lock_hierarchy(db, org_id)
    await _check_parent(db, org_id, None, values.get("parent_id"))
    t = Team(org_id=org_id, name=values["name"], description=(values.get("description") or "").strip() or None,
             parent_id=values.get("parent_id"), created_by=user_id)
    # added INSIDE the savepoint: begin_nested() first flushes what is pending,
    # and a conflict raised by that flush would abort the whole transaction
    try:
        async with db.begin_nested():
            db.add(t)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "team.name_taken")
    return t


async def update_team(db: AsyncSession, org_id: int, team_id: int, values: Dict[str, Any]) -> Team:
    t = await get_team(db, org_id, team_id)
    if "name" in values:
        values["name"] = _clean_name(values["name"])
    if "parent_id" in values:
        await _lock_hierarchy(db, org_id)
        await _check_parent(db, org_id, t.id, values["parent_id"])
        t.parent_id = values["parent_id"]
        await db.flush()
        from app.services import kill_switch

        await kill_switch.hold_moved_team(db, org_id, t.id)  # moved under a stopped team: it stops too
    if "description" in values:
        t.description = (values["description"] or "").strip() or None
    if values.get("name") and values["name"] != t.name:
        try:
            async with db.begin_nested():
                t.name = values["name"]
                await db.flush()
        except IntegrityError:
            raise api_error(status.HTTP_409_CONFLICT, "team.name_taken")
        # the display name on the team's agents follows
        await db.execute(update(Agent).where(Agent.org_id == org_id, Agent.team_id == t.id).values(owner_team=t.name))
        await db.execute(update(AgentEnrollment).where(
            AgentEnrollment.org_id == org_id, AgentEnrollment.team_id == t.id).values(owner_team=t.name))
    return t


async def delete_team(db: AsyncSession, org_id: int, team_id: int) -> Dict[str, Any]:
    t = await get_team(db, org_id, team_id)
    # agents that can still run (active or suspended - a suspended one can be
    # switched back on) keep the team; retired agents do not
    live = (Agent.org_id == org_id) & (Agent.team_id == t.id) & (Agent.status != "retired")
    used = [
        what for what, q in (
            ("agents", select(func.count()).select_from(Agent).where(live)),
            ("roles", select(func.count()).select_from(RoleTemplate).where(
                RoleTemplate.org_id == org_id, RoleTemplate.team_id == t.id)),
            ("sub_teams", select(func.count()).select_from(Team).where(Team.org_id == org_id, Team.parent_id == t.id)),
            ("enrollments", select(func.count()).select_from(AgentEnrollment).where(
                AgentEnrollment.team_id == t.id, AgentEnrollment.used_at.is_(None),
                AgentEnrollment.revoked_at.is_(None))),
            # a policy level with rules: clear it first (the change is audited)
            ("policy", select(func.count()).select_from(PolicyLayer).where(
                PolicyLayer.org_id == org_id, PolicyLayer.team_id == t.id, PolicyLayer.document != text("'{}'::jsonb"))),
        ) if (await db.execute(q)).scalar_one()
    ]
    if used:
        # `parts` holds codes (agents, roles, sub_teams, enrollments) the client
        # translates; `agent_names` says which agents to move or retire
        names = [n for (n,) in (await db.execute(
            select(Agent.name).where(live).order_by(Agent.name).limit(5))).all()] if "agents" in used else []
        raise api_error(status.HTTP_409_CONFLICT, "team.not_empty", used=", ".join(used), parts=used,
                        agent_names=", ".join(names))
    snapshot = team_out(t)
    # retired agents leave the team; owner_team keeps its name as history
    await db.execute(update(Agent).where(
        Agent.org_id == org_id, Agent.team_id == t.id, Agent.status == "retired").values(team_id=None))
    # spent / revoked tokens keep their history, just not the link
    await db.execute(update(AgentEnrollment).where(
        AgentEnrollment.org_id == org_id, AgentEnrollment.team_id == t.id).values(team_id=None))
    # an emptied policy level goes with its team (what it held is in the audit log)
    await db.execute(delete(PolicyLayer).where(PolicyLayer.org_id == org_id, PolicyLayer.team_id == t.id))
    await db.delete(t)
    return snapshot


# --------------------------------------------------------------------------- roles

async def list_roles(db: AsyncSession, org_id: int, team_id: Optional[int] = None) -> List[Dict[str, Any]]:
    q = select(RoleTemplate).where(RoleTemplate.org_id == org_id)
    if team_id is not None:
        q = q.where((RoleTemplate.team_id == team_id) | RoleTemplate.team_id.is_(None))
    roles = list((await db.execute(q.order_by(RoleTemplate.name))).scalars())
    counts = dict((await db.execute(
        select(Agent.role_id, func.count()).where(Agent.org_id == org_id, Agent.role_id.is_not(None),
                                                  Agent.status != "retired")
        .group_by(Agent.role_id))).all())
    return [role_out(r, counts.get(r.id, 0)) for r in roles]


async def _check_attestation(db: AsyncSession, org_id: int, require: bool, policy_id: Optional[int]) -> None:
    """A role that requires attestation names the policy its agents attest
    under (services/attestation.py)."""
    from app.services.attestation import get_policy

    # 404 for another organization's policy; held so it cannot be deleted under us
    await get_policy(db, org_id, policy_id, lock="share")
    if require and policy_id is None:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "role.attestation_policy_required")


async def create_role(db: AsyncSession, org_id: int, user_id: int, values: Dict[str, Any]) -> RoleTemplate:
    await get_team(db, org_id, values.get("team_id"))
    await _check_attestation(db, org_id, bool(values.get("require_attestation")), values.get("attestation_policy_id"))
    r = RoleTemplate(org_id=org_id, created_by=user_id, **values)
    try:
        async with db.begin_nested():
            db.add(r)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "role.name_taken")
    return r


async def update_role(db: AsyncSession, org_id: int, role_id: int, values: Dict[str, Any]) -> tuple:
    """Returns (role, number of agents whose rights changed with it)."""
    r = await get_role(db, org_id, role_id, lock="update")
    # null only clears what may be empty; for the rest it means "unchanged"
    values = {k: v for k, v in values.items()
              if v is not None or k in ("team_id", "description", "attestation_policy_id")}
    if "name" in values:
        values["name"] = _clean_name(values["name"], "role.name_required")
    if "require_attestation" in values or "attestation_policy_id" in values:
        await _check_attestation(db, org_id, values.get("require_attestation", r.require_attestation),
                                 values.get("attestation_policy_id", r.attestation_policy_id))
    if "team_id" in values and values["team_id"] != r.team_id:
        # moving a role to a team must not strand agents (or open tokens) of other teams with it
        await get_team(db, org_id, values["team_id"])
        if values["team_id"] is not None:
            others = (await db.execute(select(func.count()).select_from(Agent).where(
                Agent.role_id == r.id, Agent.team_id.is_distinct_from(values["team_id"])))).scalar_one()
            others += (await db.execute(select(func.count()).select_from(AgentEnrollment).where(
                AgentEnrollment.role_id == r.id, AgentEnrollment.used_at.is_(None),
                AgentEnrollment.revoked_at.is_(None),
                AgentEnrollment.team_id.is_distinct_from(values["team_id"])))).scalar_one()
            if others:
                raise api_error(status.HTTP_409_CONFLICT, "role.agents_in_other_teams", count=others)
    if values.get("require_hybrid") and not r.require_hybrid:
        classic = (await db.execute(select(func.count()).select_from(Agent).where(
            Agent.org_id == org_id, Agent.role_id == r.id, Agent.pq_public_key.is_(None)))).scalar_one()
        if classic:
            # those agents re-key with a hybrid key first (or leave the role)
            raise api_error(status.HTTP_409_CONFLICT, "role.agents_not_hybrid", count=classic)
    try:
        async with db.begin_nested():
            for k, v in values.items():
                setattr(r, k, v)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "role.name_taken")
    changed = await sync_role(db, r)
    return r, changed


async def sync_role(db: AsyncSession, r: RoleTemplate) -> int:
    """Every agent with the role gets exactly its rights."""
    res = await db.execute(update(Agent).where(Agent.org_id == r.org_id, Agent.role_id == r.id).values(
        capabilities=list(r.capabilities or []), allowed_tools=list(r.allowed_tools or []),
        allowed_models=list(r.allowed_models or []), max_delegation_depth=r.max_delegation_depth))
    return res.rowcount or 0


async def delete_role(db: AsyncSession, org_id: int, role_id: int) -> Dict[str, Any]:
    r = await get_role(db, org_id, role_id)
    agents = (await db.execute(select(func.count()).select_from(Agent).where(
        Agent.org_id == org_id, Agent.role_id == r.id, Agent.status != "retired"))).scalar_one()
    open_tokens = (await db.execute(select(func.count()).select_from(AgentEnrollment).where(
        AgentEnrollment.role_id == r.id, AgentEnrollment.used_at.is_(None),
        AgentEnrollment.revoked_at.is_(None)))).scalar_one()
    if agents or open_tokens:
        raise api_error(status.HTTP_409_CONFLICT, "role.in_use", agents=agents, tokens=open_tokens)
    snapshot = role_out(r)
    # retired agents keep the rights they had, without the link
    await db.execute(update(Agent).where(
        Agent.org_id == org_id, Agent.role_id == r.id, Agent.status == "retired").values(role_id=None))
    await db.execute(update(AgentEnrollment).where(
        AgentEnrollment.org_id == org_id, AgentEnrollment.role_id == r.id).values(role_id=None))
    await db.delete(r)
    return snapshot


# --------------------------------------------------------------------------- agents

async def assign(db: AsyncSession, org_id: int, agent: Agent, team_id: Optional[int],
                 role_id: Optional[int]) -> Agent:
    """Put the agent in a team and/or give it a role (None clears)."""
    team = await get_team(db, org_id, team_id)
    role = await get_role(db, org_id, role_id, lock="share")
    check_role_fits_team(role, team_id)
    if role is not None and role.require_hybrid and not agent.pq_public_key:
        raise api_error(status.HTTP_409_CONFLICT, "role.requires_hybrid")
    agent.team_id = team.id if team else None
    agent.owner_team = team.name if team else None
    agent.role_id = role.id if role else None
    if role is not None:
        for k in RIGHTS:
            setattr(agent, k, list(getattr(role, k)) if isinstance(getattr(role, k), list) else getattr(role, k))
    return agent


async def template_for_enrollment(db: AsyncSession, org_id: int, values: Dict[str, Any]) -> Dict[str, Any]:
    """An enrollment with a role takes the role's rights (anything else given is
    ignored) and the role's team when none is named; the team name is recorded."""
    role = await get_role(db, org_id, values.get("role_id"))
    team_id = values.get("team_id")
    if role is not None and team_id is None:
        team_id = role.team_id
    team = await get_team(db, org_id, team_id)
    check_role_fits_team(role, team_id)
    out = dict(values)
    out["team_id"] = team.id if team else None
    out["owner_team"] = team.name if team else values.get("owner_team")
    if role is not None:
        for k in RIGHTS:
            out[k] = getattr(role, k)
        out["require_hybrid"] = bool(role.require_hybrid or values.get("require_hybrid"))
    return out
