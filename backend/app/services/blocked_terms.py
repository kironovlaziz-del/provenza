# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Blocked terms: the one place they are kept (Policies -> Blocked terms).

A term has a scope (models/blocked_term.py): the whole organization, every
agent, a team (with its sub-teams), one agent, or one policy (the use cases
it governs). It is matched as a whole word or anywhere, with the usual
disguises seen through (core/term_match.py), and it either blocks the
prompt or only records that it was seen (monitor). Terms can be grouped in
categories and a category switched off as a whole.

Which terms apply:
  * gateway call of an agent: org + agents + its team and the teams above +
    the agent itself                                         -> for_agent()
  * user AI request: org + the policy of its use case        -> for_request()
  * provider playground: org + every active policy           -> for_playground()

Hits are counted per term (hits, last_hit_at) - never the text itself.
"""

import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import status
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import term_match as tm
from app.core.errors import api_error
from app.models.agent import Agent
from app.models.ai_policy import AIPolicy
from app.models.blocked_term import BlockedTerm, BlockedTermCategory
from app.models.team import Team

SCOPES = ("org", "agents", "team", "agent", "policy")
MAX_TERMS = 5000
MAX_CATEGORIES = 100
MAX_IMPORT_ROWS = 5000
CSV_COLUMNS = ["term", "match", "action", "scope", "target", "category", "enabled", "note"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- applying

def _live(org_id: int):
    """Live, switched-on terms whose category (if any) is switched on."""
    return (select(BlockedTerm.id, BlockedTerm.term, BlockedTerm.match, BlockedTerm.action, BlockedTerm.scope,
                   BlockedTermCategory.name)
            .outerjoin(BlockedTermCategory, BlockedTermCategory.id == BlockedTerm.category_id)
            .where(BlockedTerm.org_id == org_id, BlockedTerm.deleted_at.is_(None), BlockedTerm.enabled.is_(True),
                   or_(BlockedTerm.category_id.is_(None), BlockedTermCategory.enabled.is_(True))))


def _as_terms(rows) -> List[tm.Term]:
    # the match key is recomputed from the term (cached): a better reduction applies to old terms too
    return [tm.Term(i, term, match, action, "", scope, cat) for i, term, match, action, scope, cat in rows]


async def _team_ids_up(db: AsyncSession, org_id: int, team_id: Optional[int]) -> List[int]:
    """The team and every team above it."""
    if team_id is None:
        return []
    parents = dict((await db.execute(select(Team.id, Team.parent_id).where(Team.org_id == org_id))).all())
    out, t = [], team_id
    while t is not None and t not in out:
        out.append(t)
        t = parents.get(t)
    return out


async def for_agent(db: AsyncSession, agent: Agent) -> List[tm.Term]:
    teams = await _team_ids_up(db, agent.org_id, agent.team_id)
    cond = [BlockedTerm.scope.in_(("org", "agents")), and_(BlockedTerm.scope == "agent",
                                                          BlockedTerm.agent_id == agent.id)]
    if teams:
        cond.append(and_(BlockedTerm.scope == "team", BlockedTerm.team_id.in_(teams)))
    return _as_terms((await db.execute(_live(agent.org_id).where(or_(*cond)))).all())


async def for_request(db: AsyncSession, org_id: int, policy_id: Optional[int]) -> List[tm.Term]:
    cond = [BlockedTerm.scope == "org"]
    if policy_id is not None:
        cond.append(and_(BlockedTerm.scope == "policy", BlockedTerm.policy_id == policy_id))
    return _as_terms((await db.execute(_live(org_id).where(or_(*cond)))).all())


async def for_playground(db: AsyncSession, org_id: int) -> List[tm.Term]:
    active = select(AIPolicy.id).where(AIPolicy.org_id == org_id, AIPolicy.status == "active")
    cond = or_(BlockedTerm.scope == "org", and_(BlockedTerm.scope == "policy", BlockedTerm.policy_id.in_(active)))
    return _as_terms((await db.execute(_live(org_id).where(cond))).all())


async def record_hits(db: AsyncSession, org_id: int, hits: Iterable[Any]) -> None:
    """Count the terms found (term_match.Hit) - once per request; the caller
    commits soon after (the rows stay locked until then)."""
    ids = sorted({h.term.id for h in hits if getattr(h.term, "id", None)})
    now = _now()
    for i in ids:  # one row at a time, in id order: two requests never lock them crosswise
        await db.execute(update(BlockedTerm).where(BlockedTerm.org_id == org_id, BlockedTerm.id == i)
                         .values(hits=BlockedTerm.hits + 1, last_hit_at=now))


# --------------------------------------------------------------------------- reading

def term_out(t: BlockedTerm, names: Dict[Tuple[str, int], str], categories: Dict[int, str]) -> Dict[str, Any]:
    target = t.team_id or t.agent_id or t.policy_id
    return {"id": t.id, "term": t.term, "match": t.match, "action": t.action, "scope": t.scope,
            "target_id": target, "target_name": names.get((t.scope, target)) if target else None,
            "category_id": t.category_id, "category": categories.get(t.category_id) if t.category_id else None,
            "enabled": t.enabled, "note": t.note, "hits": t.hits, "last_hit_at": t.last_hit_at,
            "source": t.source, "created_at": t.created_at, "updated_at": t.updated_at}


async def _names(db: AsyncSession, org_id: int) -> Dict[Tuple[str, int], str]:
    out: Dict[Tuple[str, int], str] = {}
    for i, n in (await db.execute(select(Team.id, Team.name).where(Team.org_id == org_id))).all():
        out[("team", i)] = n
    for i, n in (await db.execute(select(Agent.id, Agent.name).where(Agent.org_id == org_id))).all():
        out[("agent", i)] = n
    for i, n in (await db.execute(select(AIPolicy.id, AIPolicy.name).where(AIPolicy.org_id == org_id))).all():
        out[("policy", i)] = n
    return out


async def _categories(db: AsyncSession, org_id: int) -> List[BlockedTermCategory]:
    return list((await db.execute(select(BlockedTermCategory).where(BlockedTermCategory.org_id == org_id)
                                  .order_by(BlockedTermCategory.name))).scalars())


async def overview(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    cats = await _categories(db, org_id)
    cat_names = {c.id: c.name for c in cats}
    names = await _names(db, org_id)
    terms = list((await db.execute(select(BlockedTerm).where(BlockedTerm.org_id == org_id,
                                                             BlockedTerm.deleted_at.is_(None))
                                   .order_by(func.lower(BlockedTerm.term)))).scalars())
    counts: Dict[Optional[int], int] = {}
    for t in terms:
        counts[t.category_id] = counts.get(t.category_id, 0) + 1
    return {
        "terms": [term_out(t, names, cat_names) for t in terms],
        "categories": [{"id": c.id, "name": c.name, "description": c.description, "enabled": c.enabled,
                        "terms": counts.get(c.id, 0)} for c in cats],
        "targets": {
            "teams": [{"id": i, "name": n} for (s, i), n in names.items() if s == "team"],
            "agents": [{"id": i, "name": n} for (s, i), n in names.items() if s == "agent"],
            "policies": [{"id": i, "name": n} for (s, i), n in names.items() if s == "policy"],
        },
        "limits": {"max_terms": MAX_TERMS, "max_term_length": tm.MAX_TERM_LENGTH},
    }


# --------------------------------------------------------------------------- writing

async def _check_target(db: AsyncSession, org_id: int, scope: str, target_id: Optional[int]) -> Dict[str, Any]:
    if scope not in SCOPES:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.bad_scope")
    out = {"team_id": None, "agent_id": None, "policy_id": None}
    if scope in ("org", "agents"):
        return out
    if target_id is None:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.target_required")
    model = {"team": Team, "agent": Agent, "policy": AIPolicy}[scope]
    found = (await db.execute(select(model.id).where(model.id == target_id, model.org_id == org_id))).first()
    if not found:
        raise api_error(status.HTTP_404_NOT_FOUND, "terms.target_not_found")
    out[f"{scope}_id"] = target_id
    return out


async def _check_category(db: AsyncSession, org_id: int, category_id: Optional[int]) -> None:
    if category_id is not None and not (await db.execute(select(BlockedTermCategory.id).where(
            BlockedTermCategory.id == category_id, BlockedTermCategory.org_id == org_id))).first():
        raise api_error(status.HTTP_404_NOT_FOUND, "terms.category_not_found")


def _clean_term(term: Any) -> Tuple[str, str]:
    t = " ".join(str(term or "").split())
    if "\x00" in t:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.bad_character")
    key = tm.term_key(t)
    if len(t) > tm.MAX_TERM_LENGTH or len(key) > tm.MAX_KEY_LENGTH:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.too_long", max=tm.MAX_TERM_LENGTH)
    if len(key) < 2:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.too_short")
    return t, key


async def _lock(db: AsyncSession, org_id: int) -> None:
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('provenza.blocked_terms'), :org)"),
                     {"org": int(org_id)})


async def _count(db: AsyncSession, org_id: int) -> int:
    return int((await db.execute(select(func.count()).select_from(BlockedTerm).where(
        BlockedTerm.org_id == org_id, BlockedTerm.deleted_at.is_(None)))).scalar_one())


async def create_term(db: AsyncSession, org_id: int, user_id: int, values: Dict[str, Any]) -> BlockedTerm:
    term, key = _clean_term(values["term"])
    target = await _check_target(db, org_id, values.get("scope", "org"), values.get("target_id"))
    await _check_category(db, org_id, values.get("category_id"))
    await _lock(db, org_id)
    if await _count(db, org_id) >= MAX_TERMS:
        raise api_error(status.HTTP_409_CONFLICT, "terms.too_many", max=MAX_TERMS)
    t = BlockedTerm(org_id=org_id, term=term, key=key, match=values.get("match", "word"),
                    action=values.get("action", "block"), scope=values.get("scope", "org"), **target,
                    category_id=values.get("category_id"), enabled=values.get("enabled", True),
                    note=(values.get("note") or "").replace("\x00", "").strip() or None, hits=0,
                    source=values.get("source"),
                    created_by=user_id, updated_by=user_id, created_at=_now(), updated_at=_now())
    try:
        async with db.begin_nested():
            db.add(t)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "terms.duplicate", term=term)
    return t


async def get_term(db: AsyncSession, org_id: int, term_id: int, lock: bool = False) -> BlockedTerm:
    q = select(BlockedTerm).where(BlockedTerm.id == term_id, BlockedTerm.org_id == org_id,
                                  BlockedTerm.deleted_at.is_(None))
    if lock:
        q = q.with_for_update()
    t = (await db.execute(q)).scalar_one_or_none()
    if t is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "terms.not_found")
    return t


def snapshot(t: BlockedTerm) -> Dict[str, Any]:
    return {"term": t.term, "match": t.match, "action": t.action, "scope": t.scope,
            "target_id": t.team_id or t.agent_id or t.policy_id, "category_id": t.category_id,
            "enabled": t.enabled, "note": t.note}


async def update_term(db: AsyncSession, org_id: int, user_id: int, term_id: int,
                      values: Dict[str, Any]) -> Tuple[Dict[str, Any], BlockedTerm]:
    t = await get_term(db, org_id, term_id, lock=True)
    before = snapshot(t)
    changes: Dict[str, Any] = {}
    if "term" in values:
        changes["term"], changes["key"] = _clean_term(values["term"])
    if "scope" in values or "target_id" in values:
        scope = values.get("scope", t.scope)
        target = values.get("target_id", before["target_id"] if scope == t.scope else None)
        changes.update({"scope": scope, **await _check_target(db, org_id, scope, target)})
    if "category_id" in values:
        await _check_category(db, org_id, values["category_id"])
        changes["category_id"] = values["category_id"]
    for k in ("match", "action", "enabled"):
        if k in values:
            changes[k] = values[k]
    if "note" in values:
        changes["note"] = (values["note"] or "").replace("\x00", "").strip() or None
    try:
        async with db.begin_nested():
            for k, v in changes.items():
                setattr(t, k, v)
            t.updated_by, t.updated_at = user_id, _now()
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "terms.duplicate", term=changes.get("term", t.term))
    return before, t


async def delete_term(db: AsyncSession, org_id: int, user_id: int, term_id: int) -> Dict[str, Any]:
    """Kept, marked deleted: flags on old requests still name it."""
    t = await get_term(db, org_id, term_id, lock=True)
    before = snapshot(t)
    t.deleted_at, t.enabled = _now(), False
    t.updated_by, t.updated_at = user_id, _now()
    return before


def _category_name(v: Any) -> str:
    name = " ".join(str(v or "").replace("\x00", "").split())
    if not name:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.category_name_required")
    if len(name) > 100:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.category_name_too_long")
    return name


async def create_category(db: AsyncSession, org_id: int, user_id: int, values: Dict[str, Any]) -> BlockedTermCategory:
    name = _category_name(values.get("name"))
    if len(await _categories(db, org_id)) >= MAX_CATEGORIES:
        raise api_error(status.HTTP_409_CONFLICT, "terms.too_many_categories", max=MAX_CATEGORIES)
    c = BlockedTermCategory(org_id=org_id, name=name, description=(values.get("description") or "").strip() or None,
                            enabled=values.get("enabled", True), created_by=user_id, created_at=_now())
    try:
        async with db.begin_nested():
            db.add(c)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "terms.category_taken", name=name)
    return c


async def update_category(db: AsyncSession, org_id: int, category_id: int,
                          values: Dict[str, Any]) -> Tuple[Dict[str, Any], BlockedTermCategory]:
    c = (await db.execute(select(BlockedTermCategory).where(
        BlockedTermCategory.id == category_id, BlockedTermCategory.org_id == org_id).with_for_update())
         ).scalar_one_or_none()
    if c is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "terms.category_not_found")
    before = {"name": c.name, "description": c.description, "enabled": c.enabled}
    try:
        async with db.begin_nested():
            if "name" in values:
                c.name = _category_name(values["name"])
            if "description" in values:
                c.description = (values["description"] or "").strip() or None
            if "enabled" in values:
                c.enabled = bool(values["enabled"])
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "terms.category_taken", name=values.get("name"))
    return before, c


async def delete_category(db: AsyncSession, org_id: int, category_id: int) -> Dict[str, Any]:
    """Its terms stay, without a category."""
    c = (await db.execute(select(BlockedTermCategory).where(
        BlockedTermCategory.id == category_id, BlockedTermCategory.org_id == org_id).with_for_update())
         ).scalar_one_or_none()
    if c is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "terms.category_not_found")
    moved = (await db.execute(update(BlockedTerm).where(BlockedTerm.org_id == org_id,
                                                        BlockedTerm.category_id == c.id)
                              .values(category_id=None))).rowcount
    snap = {"name": c.name, "terms_uncategorized": moved}
    await db.delete(c)
    return snap


# --------------------------------------------------------------------------- testing

async def test(db: AsyncSession, org_id: int, sample: str, draft: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Every live, switched-on term (any scope) and a draft term against a
    sample: what is found and where. Nothing is stored or counted."""
    import asyncio

    sample = (sample or "")[:20000]
    terms = _as_terms((await db.execute(_live(org_id))).all())
    if draft and (draft.get("term") or "").strip():
        key = tm.term_key(" ".join(str(draft["term"]).split()))
        if len(key) >= 2:
            terms.insert(0, tm.Term(0, draft["term"], draft.get("match", "word"), draft.get("action", "block"), key,
                                    "draft"))
    hits = await asyncio.to_thread(tm.find, sample, terms)
    names = await _names(db, org_id)
    targets = {}
    for t in (await db.execute(select(BlockedTerm).where(
            BlockedTerm.id.in_([h.term.id for h in hits if h.term.id])))).scalars():
        target = t.team_id or t.agent_id or t.policy_id
        targets[t.id] = names.get((t.scope, target)) if target else None
    return {"hits": [{"id": h.term.id or None, "term": h.term.term, "match": h.term.match, "action": h.term.action,
                      "scope": h.term.scope, "target_name": targets.get(h.term.id), "category": h.term.category,
                      "spans": [{"start": a, "end": b, "text": sample[a:b][:200]} for a, b in h.spans]}
                     for h in hits]}


# --------------------------------------------------------------------------- CSV

def _safe_cell(v: Any) -> str:
    """Spreadsheets run a cell starting with = + - @ as a formula: prefix it."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


async def export_csv(db: AsyncSession, org_id: int) -> str:
    data = await overview(db, org_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for t in data["terms"]:
        w.writerow([_safe_cell(x) for x in (t["term"], t["match"], t["action"], t["scope"], t["target_name"] or "",
                                            t["category"] or "", "yes" if t["enabled"] else "no", t["note"] or "")])
    return buf.getvalue()


def _unsafe_cell(s: str) -> str:
    s = (s or "").strip()
    return s[1:] if s[:1] == "'" and s[1:2] in ("=", "+", "-", "@") else s


async def import_csv(db: AsyncSession, org_id: int, user_id: int, content: str, dry_run: bool) -> Dict[str, Any]:
    """Add terms from CSV (columns as exported; only `term` is required).
    A term already there with the same scope is left as it is. Targets and
    categories are named; a category that does not exist is created. With
    dry_run nothing is stored - the result says what would happen."""
    content = content.lstrip("\ufeff").replace("\x00", "")
    first = content.split("\n", 1)[0]
    delimiter = max((",", ";", "\t"), key=first.count) if first else ","  # Excel writes ; in many locales
    try:
        rows = list(csv.DictReader(io.StringIO(content), delimiter=delimiter))
    except csv.Error as e:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.import_bad_csv", detail=str(e)[:200])
    if len(rows) > MAX_IMPORT_ROWS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.import_too_large", max=MAX_IMPORT_ROWS)
    if rows and "term" not in rows[0]:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "terms.import_no_term_column")
    names = await _names(db, org_id)
    by_name: Dict[Tuple[str, str], Optional[int]] = {}
    for (sc, i), n in names.items():  # a name used twice cannot pick a target
        k = (sc, " ".join(n.split()).lower())
        by_name[k] = None if k in by_name else i
    cats = {" ".join(c.name.split()).lower(): c.id for c in await _categories(db, org_id)}
    existing = {(t.scope, t.team_id or t.agent_id or t.policy_id or 0, t.key) for t in (await db.execute(
        select(BlockedTerm).where(BlockedTerm.org_id == org_id, BlockedTerm.deleted_at.is_(None)))).scalars()}
    added, skipped, errors = [], [], []
    room = MAX_TERMS - await _count(db, org_id)
    for n, row in enumerate(rows, start=2):
        row = {k: _unsafe_cell(v) for k, v in row.items() if k}
        try:
            term, key = _clean_term(row.get("term"))
            match = (row.get("match") or "word").lower()
            action = (row.get("action") or "block").lower()
            scope = (row.get("scope") or "org").lower()
            if match not in tm.MATCH_MODES or action not in tm.ACTIONS or scope not in SCOPES:
                raise ValueError("terms.import_bad_value")
            target = None
            if scope in ("team", "agent", "policy"):
                k = (scope, " ".join((row.get("target") or "").split()).lower())
                if k not in by_name:
                    raise ValueError("terms.target_not_found")
                target = by_name[k]
                if target is None:
                    raise ValueError("terms.target_ambiguous")
            if (scope, target or 0, key) in existing:
                skipped.append({"line": n, "term": term, "why": "terms.duplicate"})
                continue
            if len(added) >= room:
                raise ValueError("terms.too_many")
            enabled = (row.get("enabled") or "yes").lower() not in ("no", "false", "0", "off")
            category = row.get("category") or ""
            category = _category_name(category) if category.strip() else None
            added.append({"line": n, "term": term, "match": match, "action": action, "scope": scope,
                          "target_id": target, "category": category,
                          "enabled": enabled, "note": (row.get("note") or "")[:1000] or None})
            existing.add((scope, target or 0, key))
        except ValueError as e:
            errors.append({"line": n, "term": (row.get("term") or "")[:200], "why": str(e)})
        except Exception as e:  # api_error from _clean_term
            detail = getattr(e, "detail", None)
            errors.append({"line": n, "term": (row.get("term") or "")[:200],
                           "why": detail["code"] if isinstance(detail, dict) else str(detail or e)})
    if not dry_run:
        for a in added:
            cat_id = None
            if a["category"]:
                cat_id = cats.get(a["category"].lower())
                if cat_id is None:
                    cat_id = (await create_category(db, org_id, user_id, {"name": a["category"]})).id
                    cats[a["category"].lower()] = cat_id
            await create_term(db, org_id, user_id, {**a, "category_id": cat_id, "source": "import"})
    return {"dry_run": dry_run, "added": len(added), "skipped": skipped, "errors": errors,
            "preview": [{k: a[k] for k in ("line", "term", "scope", "action")} for a in added[:50]]}
