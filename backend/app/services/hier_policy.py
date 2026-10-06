# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The policy hierarchy: organization -> team (-> its parent teams first) ->
agent, each level a document of core/policy_doc.py, combined so that lower
levels can only tighten.

Where it applies:
  * gateway (gateway_service): limits, models, providers, output scanning - for the calling agent, on top of the gateway settings
    (which take part as the topmost level, "gateway settings");
  * agent actions (agent_audit -> agent_policy_engine): tools allow / deny /
    require approval, models, delegation depth;
  * user requests (request_service): the organization level - providers,
    approval required - on top of the use case's policy.
Blocked terms have their own page and scopes (services/blocked_terms.py).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import policy_doc
from app.core.errors import api_error
from app.core.policy_doc import Effective, PolicyDocError
from app.models.agent import Agent
from app.models.policy_layer import PolicyLayer
from app.models.team import Team

SCOPES = ("org", "team", "agent")
GATEWAY_SOURCE = "gateway settings"
ORG_SOURCE = "organization"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def doc_error(e: PolicyDocError):
    return api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, e.code, path=e.path, detail=e.detail)


def _check_scope(doc: Dict[str, Any], scope: str) -> Dict[str, Any]:
    """User requests are governed by the organization level only: a
    `requests` section anywhere else would be shown but do nothing."""
    if scope != "org" and doc.get("requests"):
        raise PolicyDocError("policy.org_only", "requests", "only the organization level governs user requests")
    return doc


def parse(yaml_text: Optional[str], document: Optional[Dict[str, Any]],
          scope: str = "org") -> Tuple[Dict[str, Any], str]:
    """(validated document, YAML to keep). YAML wins when both are given:
    it is what the admin typed, comments included."""
    try:
        if yaml_text is not None:
            return _check_scope(policy_doc.from_yaml(yaml_text), scope), yaml_text
        doc = _check_scope(policy_doc.validate(document or {}), scope)
        return doc, policy_doc.to_yaml(doc)
    except PolicyDocError as e:
        raise doc_error(e)


def layer_out(layer: Optional[PolicyLayer], scope: str, target_id: Optional[int]) -> Dict[str, Any]:
    if layer is None:
        return {"scope": scope, "team_id": target_id if scope == "team" else None,
                "agent_id": target_id if scope == "agent" else None, "document": {}, "yaml": "", "revision": 0,
                "updated_at": None, "updated_by": None}
    return {"scope": layer.scope, "team_id": layer.team_id, "agent_id": layer.agent_id,
            "document": layer.document or {}, "yaml": layer.source_yaml or policy_doc.to_yaml(layer.document or {}),
            "revision": layer.revision,
            "updated_at": layer.updated_at.isoformat() if layer.updated_at else None, "updated_by": layer.updated_by}


async def _target(db: AsyncSession, org_id: int, scope: str, target_id: Optional[int]):
    """The team or agent a level belongs to, in this organization."""
    if scope not in SCOPES:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "policy.bad_scope")
    if scope == "org":
        if target_id is not None:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "policy.bad_scope")
        return None
    if target_id is None:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "policy.target_required")
    model = Team if scope == "team" else Agent
    row = (await db.execute(select(model).where(model.id == target_id, model.org_id == org_id))).scalar_one_or_none()
    if row is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "team.not_found" if scope == "team" else "agent.not_found")
    return row


def _where(org_id: int, scope: str, target_id: Optional[int]):
    q = select(PolicyLayer).where(PolicyLayer.org_id == org_id, PolicyLayer.scope == scope)
    if scope == "team":
        q = q.where(PolicyLayer.team_id == target_id)
    elif scope == "agent":
        q = q.where(PolicyLayer.agent_id == target_id)
    return q


async def get_layer(db: AsyncSession, org_id: int, scope: str, target_id: Optional[int],
                    lock: bool = False) -> Optional[PolicyLayer]:
    await _target(db, org_id, scope, target_id)
    q = _where(org_id, scope, target_id)
    if lock:
        q = q.with_for_update().execution_options(populate_existing=True)
    return (await db.execute(q)).scalar_one_or_none()


async def save_layer(db: AsyncSession, org_id: int, user_id: int, scope: str, target_id: Optional[int],
                     yaml_text: Optional[str], document: Optional[Dict[str, Any]],
                     expected_revision: Optional[int]) -> Tuple[PolicyLayer, Dict[str, Any]]:
    """Write a level. expected_revision: the revision the editor started from
    (0 for a level that did not exist) - a concurrent change is refused
    rather than silently overwritten. Returns (layer, document before)."""
    doc, source = parse(yaml_text, document, scope)
    layer = await get_layer(db, org_id, scope, target_id, lock=True)
    current = layer.revision if layer else 0
    if expected_revision is not None and expected_revision != current:
        raise api_error(status.HTTP_409_CONFLICT, "policy.stale", current=current)
    before = dict(layer.document or {}) if layer else {}
    now = _now()
    if layer is None:
        layer = PolicyLayer(org_id=org_id, scope=scope, team_id=target_id if scope == "team" else None,
                            agent_id=target_id if scope == "agent" else None, document=doc, source_yaml=source,
                            revision=1, updated_by=user_id, created_at=now, updated_at=now)
        try:
            async with db.begin_nested():  # added inside: begin_nested() flushes first
                db.add(layer)
                await db.flush()
        except IntegrityError:
            raise api_error(status.HTTP_409_CONFLICT, "policy.stale", current=1)
    else:
        layer.document, layer.source_yaml = doc, source
        layer.revision = current + 1
        layer.updated_by, layer.updated_at = user_id, now
        await db.flush()
    return layer, before


# --------------------------------------------------------------------------- the chain
def _gateway_level(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """The gateway settings, as the topmost level of the hierarchy."""
    doc: Dict[str, Any] = {"limits": {"requests_per_minute": int(cfg["rpm_per_agent"]),
                                      "max_tokens": int(cfg["max_tokens_cap"])},
                           "content": {"scan_output": bool(cfg["scan_output"])}}
    return doc


async def _team_chain(db: AsyncSession, org_id: int, team_id: Optional[int]) -> List[Team]:
    """The team and its parents, topmost first."""
    out: List[Team] = []
    seen = set()
    current = team_id
    while current is not None and current not in seen and len(out) < 20:
        seen.add(current)
        t = (await db.execute(select(Team).where(Team.id == current, Team.org_id == org_id))).scalar_one_or_none()
        if t is None:
            break
        out.append(t)
        current = t.parent_id
    return list(reversed(out))


async def chain(db: AsyncSession, org_id: int, *, team_id: Optional[int] = None, agent: Optional[Agent] = None,
                gateway: bool = True, draft: Optional[Tuple[str, Optional[int], Dict[str, Any]]] = None
                ) -> List[Dict[str, Any]]:
    """The levels that govern an agent (or a team's agents), topmost first:
    [{"source", "scope", "id", "document"}]. `draft` (scope, target id,
    document) replaces that level's stored document - for previews."""
    rows = {(r.scope, r.team_id if r.scope == "team" else r.agent_id): r for r in (await db.execute(
        select(PolicyLayer).where(PolicyLayer.org_id == org_id))).scalars()}

    def doc_of(scope: str, target: Optional[int]) -> Dict[str, Any]:
        if draft is not None and draft[0] == scope and draft[1] == target:
            return draft[2]
        r = rows.get((scope, target))
        return dict(r.document or {}) if r else {}

    levels: List[Dict[str, Any]] = []
    if gateway:
        from app.services.gateway_service import GatewayService

        levels.append({"source": GATEWAY_SOURCE, "scope": "gateway", "id": None,
                       "document": _gateway_level(await GatewayService(db).settings(org_id))})
    levels.append({"source": ORG_SOURCE, "scope": "org", "id": None, "document": doc_of("org", None)})
    if agent is not None:
        team_id = agent.team_id
    for t in await _team_chain(db, org_id, team_id):
        levels.append({"source": f"team {t.name}", "scope": "team", "id": t.id, "document": doc_of("team", t.id)})
    if agent is not None:
        levels.append({"source": f"agent {agent.name}", "scope": "agent", "id": agent.id,
                       "document": doc_of("agent", agent.id)})
    return levels


def combine(levels: List[Dict[str, Any]]) -> Dict[str, Any]:
    return policy_doc.resolve([(lv["source"], lv["document"]) for lv in levels])


async def for_agent(db: AsyncSession, agent: Agent) -> Effective:
    """Everything that governs this agent, combined."""
    return Effective(combine(await chain(db, agent.org_id, agent=agent)))


async def engine_policies(db: AsyncSession, agent: Agent) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    """The hierarchy as agent_policy_engine custom policies - one per level
    that has tool or model rules, so every level must pass on its own (and a
    refusal names the level) - and the delegation depth limit."""
    levels = await chain(db, agent.org_id, agent=agent, gateway=False)
    policies: List[Dict[str, Any]] = []
    for lv in levels:
        doc = lv["document"]
        tools, models = doc.get("tools") or {}, doc.get("models") or {}
        rules: Dict[str, Any] = {}
        if "allow" in tools:
            rules["allow_only_tool_patterns"] = tools["allow"]
        if tools.get("deny"):
            rules["deny_tool_patterns"] = tools["deny"]
        if tools.get("require_approval"):
            rules["require_approval_tool_patterns"] = tools["require_approval"]
        if "allow" in models:
            rules["allow_only_model_patterns"] = models["allow"]
        if rules:
            policies.append({"id": None, "name": f"{lv['source']} policy", "rules": rules})
    depth = Effective(combine(levels)).limit("limits.max_delegation_depth")
    return policies, depth


async def for_requests(db: AsyncSession, org_id: int) -> Effective:
    """What governs user requests (Policy Center): the organization level."""
    return Effective(combine(await chain(db, org_id, gateway=False)))


async def preview(db: AsyncSession, org_id: int, scope: str, target_id: Optional[int],
                  yaml_text: Optional[str], document: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """What the level would be and what it would make the effective policy,
    without saving. Errors come back in the answer, not as an HTTP error, so
    the editor can show them next to the text."""
    target = await _target(db, org_id, scope, target_id)
    try:
        doc = policy_doc.from_yaml(yaml_text) if yaml_text is not None else policy_doc.validate(document or {})
        _check_scope(doc, scope)
    except PolicyDocError as e:
        return {"ok": False, "error": {"code": e.code, "path": e.path, "detail": e.detail}}
    levels = await chain(db, org_id, team_id=target_id if scope == "team" else None,
                         agent=target if scope == "agent" else None, draft=(scope, target_id, doc))
    return {"ok": True, "document": doc, "yaml": policy_doc.to_yaml(doc), "levels": levels,
            "effective": combine(levels)}


async def overview(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    """Which levels have rules: for the page's tree."""
    rows = list((await db.execute(select(PolicyLayer).where(PolicyLayer.org_id == org_id))).scalars())
    teams = list((await db.execute(select(Team).where(Team.org_id == org_id).order_by(Team.name))).scalars())
    agent_ids = [r.agent_id for r in rows if r.scope == "agent"]
    names = dict((await db.execute(select(Agent.id, Agent.name).where(Agent.id.in_(agent_ids)))).all()) \
        if agent_ids else {}

    def count(doc: Dict[str, Any]) -> int:
        return sum(len(v) for k, v in (doc or {}).items() if isinstance(v, dict))

    return {
        "org": next(({"rules": count(r.document), "revision": r.revision} for r in rows if r.scope == "org"),
                    {"rules": 0, "revision": 0}),
        "teams": [{"id": t.id, "name": t.name, "parent_id": t.parent_id,
                   "rules": next((count(r.document) for r in rows if r.scope == "team" and r.team_id == t.id), 0)}
                  for t in teams],
        "agents": [{"id": r.agent_id, "name": names.get(r.agent_id), "rules": count(r.document)}
                   for r in rows if r.scope == "agent" and count(r.document)],
    }
