# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Rule packs: ready-made policy documents (the same YAML as a level of the
policy hierarchy, core/policy_doc.py) that an administrator applies to the
organization, a team or an agent - and undoes.

    profile   a whole policy for a level: applying it REPLACES the level's
              document; undoing it puts back the document it replaced
    guard     restrictions against one danger: applying it ADDS them -
              deny and approval entries, lower limits, an allow list of
              models or providers where the level has none. A guard never
              allows a tool, so it can only tighten. Undoing it takes out
              exactly what it added, and nothing that was there before.

Applying and undoing write the level through hier_policy.save_layer, as the
editor does: a new revision, the audit log with the document before and
after, and - when the organization signs its policy - the usual rule that a
tightening applies at once and a loosening (an undone guard) only once
administrators sign a release with it.

Built-in packs live in rule_packs_builtin.py (read-only: "builtin:<slug>");
an organization's own are in policy_packs ("own:<id>").
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import policy_doc
from app.core.errors import api_error
from app.core.policy_doc import FIELDS, PolicyDocError
from app.models.policy_pack import PolicyPack, PolicyPackApplication
from app.services import hier_policy
from app.services.audit_service import AuditService
from app.services.rule_packs_builtin import BUILTIN

MAX_OWN = 200
KINDS = ("profile", "guard")
LEVELS = ("org", "team", "agent", "any")
LIST_FIELDS = [f"{s}.{k}" for (s, k), (_, typ, _) in FIELDS.items() if typ == "patterns"]
LIMIT_FIELDS = [k for (s, k), (_, typ, _) in FIELDS.items() if s == "limits"]
UNION_FIELDS = [("tools", "deny"), ("tools", "require_approval"), ("tools", "arguments")]
ALLOW_FIELDS = [("models", "allow"), ("providers", "allow")]   # what a guard may restrict to


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- packs

def validate(kind: str, yaml_text: str) -> Dict[str, Any]:
    """The pack's document, checked like a level; a guard may not allow tools."""
    if kind not in KINDS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pack.bad_kind")
    try:
        doc = policy_doc.from_yaml(yaml_text)
    except PolicyDocError as e:
        raise hier_policy.doc_error(e)
    if not any(k in doc for k in policy_doc.SECTIONS):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pack.empty")
    if kind == "guard" and "allow" in doc.get("tools", {}):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pack.guard_allows_tools")
    return doc


_BUILTIN = {f"builtin:{p['slug']}": {**p, "document": policy_doc.from_yaml(p["yaml"])} for p in BUILTIN}


def _builtin_out(ref: str, p: Dict[str, Any]) -> Dict[str, Any]:
    return {"ref": ref, "builtin": True, "name": p["name"], "description": p["document"].get("description"),
            "kind": p["kind"], "level": p["level"], "yaml": p["yaml"], "document": p["document"]}


def _own_out(p: PolicyPack) -> Dict[str, Any]:
    return {"ref": f"own:{p.id}", "id": p.id, "builtin": False, "name": p.name, "description": p.description,
            "kind": p.kind, "level": p.level, "yaml": p.source_yaml, "document": p.document,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None}


async def list_packs(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    own = (await db.execute(select(PolicyPack).where(PolicyPack.org_id == org_id).order_by(PolicyPack.name))
           ).scalars().all()
    return {"builtin": [_builtin_out(r, p) for r, p in _BUILTIN.items()], "own": [_own_out(p) for p in own]}


async def resolve(db: AsyncSession, org_id: int, ref: str) -> Dict[str, Any]:
    if ref in _BUILTIN:
        return _builtin_out(ref, _BUILTIN[ref])
    if ref.startswith("own:") and ref[4:].isdigit():
        p = await _own(db, org_id, int(ref[4:]))
        return _own_out(p)
    raise api_error(status.HTTP_404_NOT_FOUND, "pack.not_found")


async def _own(db: AsyncSession, org_id: int, pack_id: int, lock: bool = False) -> PolicyPack:
    q = select(PolicyPack).where(PolicyPack.id == pack_id, PolicyPack.org_id == org_id)
    p = (await db.execute(q.with_for_update() if lock else q)).scalar_one_or_none()
    if p is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "pack.not_found")
    return p


def _check_meta(name: str, level: str) -> str:
    name = (name or "").strip()
    if not name or len(name) > 100:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pack.bad_name")
    if level not in LEVELS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pack.bad_level")
    return name


async def create(db: AsyncSession, org_id: int, user_id: int, name: str, description: Optional[str], kind: str,
                 level: str, yaml_text: str) -> Dict[str, Any]:
    name = _check_meta(name, level)
    doc = validate(kind, yaml_text)
    count = int(await db.scalar(select(func.count()).select_from(PolicyPack).where(PolicyPack.org_id == org_id)) or 0)
    if count >= MAX_OWN:
        raise api_error(status.HTTP_409_CONFLICT, "pack.too_many", max=MAX_OWN)
    p = PolicyPack(org_id=org_id, name=name, description=(description or doc.get("description") or None),
                   kind=kind, level=level, document=doc, source_yaml=yaml_text, created_by=user_id)
    try:
        async with db.begin_nested():
            db.add(p)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "pack.name_taken")
    await AuditService(db).log(org_id, user_id, "policy_pack", p.id, "created", {"name": name, "kind": kind})
    await db.commit()
    return _own_out(p)


async def update(db: AsyncSession, org_id: int, user_id: int, pack_id: int, name: str, description: Optional[str],
                 kind: str, level: str, yaml_text: str) -> Dict[str, Any]:
    name = _check_meta(name, level)
    doc = validate(kind, yaml_text)
    p = await _own(db, org_id, pack_id, lock=True)
    before = {"name": p.name, "kind": p.kind, "document": p.document}
    p.name, p.description, p.kind, p.level = name, (description or doc.get("description") or None), kind, level
    p.document, p.source_yaml, p.updated_at = doc, yaml_text, _now()
    try:
        async with db.begin_nested():
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "pack.name_taken")
    await AuditService(db).log(org_id, user_id, "policy_pack", p.id, "updated",
                               {"before": before, "after": {"name": name, "kind": kind, "document": doc}})
    await db.commit()
    return _own_out(p)


async def delete(db: AsyncSession, org_id: int, user_id: int, pack_id: int) -> None:
    """Deleting a pack does not change any level it was applied to; its
    applications stay, and can still be undone."""
    p = await _own(db, org_id, pack_id, lock=True)
    await AuditService(db).log(org_id, user_id, "policy_pack", p.id, "deleted", {"name": p.name})
    await db.delete(p)
    await db.commit()


# --------------------------------------------------------------------------- applying

def _get(doc: Dict[str, Any], sec: str, key: str):
    return (doc.get(sec) or {}).get(key)


def _set(doc: Dict[str, Any], sec: str, key: str, value) -> None:
    section = dict(doc.get(sec) or {})
    if value is None or (value == [] and (sec, key) != ("tools", "allow")):
        section.pop(key, None)
    else:
        section[key] = value
    if section:
        doc[sec] = section
    else:
        doc.pop(sec, None)


def merge_guard(current: Dict[str, Any], pack: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """(new document, what was added, what was left as it was and why)."""
    doc = {k: (dict(v) if isinstance(v, dict) else v) for k, v in (current or {}).items()}
    delta: Dict[str, Any] = {}
    skipped: List[str] = []
    for sec, key in UNION_FIELDS:
        have = list(_get(doc, sec, key) or [])
        added = [p for p in (_get(pack, sec, key) or []) if p not in have]
        if added:
            _set(doc, sec, key, have + added)
            delta[f"{sec}.{key}"] = added
    for key in LIMIT_FIELDS:
        want = _get(pack, "limits", key)
        if want is None:
            continue
        have = _get(doc, "limits", key)
        if have is None or want < have:
            _set(doc, "limits", key, want)
            delta[f"limits.{key}"] = {"before": have, "set": want}
        else:
            skipped.append(f"limits.{key}")                    # the level is already as strict
    for sec, key in ALLOW_FIELDS:
        want = _get(pack, sec, key)
        if want is None:
            continue
        if _get(doc, sec, key) is None:
            _set(doc, sec, key, list(want))
            delta[f"{sec}.{key}"] = {"set": list(want)}
        else:
            skipped.append(f"{sec}.{key}")                     # the level has its own list: compare them by hand
    return doc, delta, skipped


def undo_guard(current: Dict[str, Any], delta: Dict[str, Any]) -> Dict[str, Any]:
    """Take out what the guard added, if it is still there; what was there
    before it, or was changed by hand since, stays."""
    doc = {k: (dict(v) if isinstance(v, dict) else v) for k, v in (current or {}).items()}
    for sec, key in UNION_FIELDS:
        added = delta.get(f"{sec}.{key}")
        if added:
            _set(doc, sec, key, [p for p in (_get(doc, sec, key) or []) if p not in added] or None)
    for key in LIMIT_FIELDS:
        d = delta.get(f"limits.{key}")
        if d and _get(doc, "limits", key) == d["set"]:
            _set(doc, "limits", key, d["before"])
    for sec, key in ALLOW_FIELDS:
        d = delta.get(f"{sec}.{key}")
        if d and _get(doc, sec, key) == d["set"]:
            _set(doc, sec, key, None)
    return doc


def diff(before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What changes, field by field, for the confirmation."""
    out: List[Dict[str, Any]] = []
    for (sec, key), (_, typ, _) in FIELDS.items():
        b, a = _get(before, sec, key), _get(after, sec, key)
        if b == a:
            continue
        if typ in ("patterns", "argument_rules"):
            out.append({"field": f"{sec}.{key}", "before": b, "after": a,
                        "added": [p for p in (a or []) if p not in (b or [])],
                        "removed": [p for p in (b or []) if p not in (a or [])]})
        else:
            out.append({"field": f"{sec}.{key}", "before": b, "after": a})
    return out


async def _plan(db: AsyncSession, org_id: int, ref: str, scope: str, target_id: Optional[int]):
    pack = await resolve(db, org_id, ref)
    layer = await hier_policy.get_layer(db, org_id, scope, target_id)
    current = dict(layer.document or {}) if layer else {}
    if pack["kind"] == "profile":
        new, delta, skipped = dict(pack["document"]), None, []
    else:
        new, delta, skipped = merge_guard(current, pack["document"])
    return pack, layer, current, new, delta, skipped


async def preview(db: AsyncSession, org_id: int, ref: str, scope: str, target_id: Optional[int]) -> Dict[str, Any]:
    pack, layer, current, new, _, skipped = await _plan(db, org_id, ref, scope, target_id)
    return {"pack": {k: pack[k] for k in ("ref", "name", "kind", "level")}, "scope": scope, "target_id": target_id,
            "revision": layer.revision if layer else 0, "before": current, "after": new,
            "changes": diff(current, new), "skipped": skipped}


async def apply(db: AsyncSession, org_id: int, user_id: int, ref: str, scope: str, target_id: Optional[int],
                revision: Optional[int]) -> Dict[str, Any]:
    pack, _, _, _, _, _ = await _plan(db, org_id, ref, scope, target_id)
    # under the level's lock: what is merged is what is stored now
    layer = await hier_policy.get_layer(db, org_id, scope, target_id, lock=True)
    current = dict(layer.document or {}) if layer else {}
    if revision is not None and revision != (layer.revision if layer else 0):
        raise api_error(status.HTTP_409_CONFLICT, "policy.stale", current=layer.revision if layer else 0)
    if pack["kind"] == "profile":
        new, delta, skipped, yaml_text = dict(pack["document"]), None, [], pack["yaml"]
    else:
        new, delta, skipped = merge_guard(current, pack["document"])
        yaml_text = None
        if not delta:
            raise api_error(status.HTTP_409_CONFLICT, "pack.nothing_to_add")
    layer, before = await hier_policy.save_layer(db, org_id, user_id, scope, target_id, yaml_text,
                                                 None if yaml_text is not None else new, None)
    app = PolicyPackApplication(org_id=org_id, pack_ref=pack["ref"], pack_name=pack["name"], kind=pack["kind"],
                                scope=scope, team_id=target_id if scope == "team" else None,
                                agent_id=target_id if scope == "agent" else None, delta=delta,
                                previous=before if pack["kind"] == "profile" else None,
                                applied=layer.document, revision=layer.revision, applied_by=user_id)
    db.add(app)
    await db.flush()
    await AuditService(db).log(org_id, user_id, f"policy_layer_{scope}", target_id if scope != "org" else None,
                               "updated", {"revision": layer.revision, "before": before, "after": layer.document,
                                           "pack": pack["name"], "pack_ref": pack["ref"],
                                           "pack_application": app.id})
    await db.commit()
    return {"application": _app_out(app), "layer": hier_policy.layer_out(layer, scope, target_id),
            "skipped": skipped}


# --------------------------------------------------------------------------- undoing

def _app_out(a: PolicyPackApplication) -> Dict[str, Any]:
    return {"id": a.id, "pack_ref": a.pack_ref, "pack_name": a.pack_name, "kind": a.kind, "scope": a.scope,
            "target_id": a.team_id if a.scope == "team" else a.agent_id, "revision": a.revision,
            "delta": a.delta, "applied_by": a.applied_by,
            "applied_at": a.applied_at.isoformat() if a.applied_at else None, "undone_by": a.undone_by,
            "undone_at": a.undone_at.isoformat() if a.undone_at else None}


async def applications(db: AsyncSession, org_id: int) -> List[Dict[str, Any]]:
    rows = (await db.execute(select(PolicyPackApplication).where(PolicyPackApplication.org_id == org_id)
                             .order_by(PolicyPackApplication.id.desc()).limit(500))).scalars().all()
    return [_app_out(a) for a in rows]


async def _application(db: AsyncSession, org_id: int, app_id: int, lock: bool = False) -> PolicyPackApplication:
    q = select(PolicyPackApplication).where(PolicyPackApplication.id == app_id, PolicyPackApplication.org_id == org_id)
    a = (await db.execute(q.with_for_update() if lock else q)).scalar_one_or_none()
    if a is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "pack.application_not_found")
    if a.undone_at is not None:
        raise api_error(status.HTTP_409_CONFLICT, "pack.already_undone")
    return a


def _target_of(a: PolicyPackApplication) -> Optional[int]:
    return a.team_id if a.scope == "team" else a.agent_id


def _undone(a: PolicyPackApplication, current: Dict[str, Any]) -> Dict[str, Any]:
    return dict(a.previous or {}) if a.kind == "profile" else undo_guard(current, a.delta or {})


async def preview_undo(db: AsyncSession, org_id: int, app_id: int) -> Dict[str, Any]:
    a = await _application(db, org_id, app_id)
    layer = await hier_policy.get_layer(db, org_id, a.scope, _target_of(a))
    current = dict(layer.document or {}) if layer else {}
    new = _undone(a, current)
    return {"application": _app_out(a), "revision": layer.revision if layer else 0, "before": current,
            "after": new, "changes": diff(current, new), "edited_since": current != (a.applied or {})}


async def undo(db: AsyncSession, org_id: int, user_id: int, app_id: int, revision: Optional[int],
               confirm_edited: bool) -> Dict[str, Any]:
    a = await _application(db, org_id, app_id, lock=True)
    target_id = _target_of(a)
    layer = await hier_policy.get_layer(db, org_id, a.scope, target_id, lock=True)
    current = dict(layer.document or {}) if layer else {}
    if revision is not None and revision != (layer.revision if layer else 0):
        raise api_error(status.HTTP_409_CONFLICT, "policy.stale", current=layer.revision if layer else 0)
    # a profile's undo puts the old level back over anything changed since: say so first
    if a.kind == "profile" and current != (a.applied or {}) and not confirm_edited:
        raise api_error(status.HTTP_409_CONFLICT, "pack.edited_since")
    new = _undone(a, current)
    layer, before = await hier_policy.save_layer(db, org_id, user_id, a.scope, target_id, None, new, None)
    a.undone_by, a.undone_at = user_id, _now()
    await AuditService(db).log(org_id, user_id, f"policy_layer_{a.scope}", target_id if a.scope != "org" else None,
                               "updated", {"revision": layer.revision, "before": before, "after": layer.document,
                                           "pack": a.pack_name, "pack_ref": a.pack_ref,
                                           "pack_application_undone": a.id})
    await db.commit()
    return {"application": _app_out(a), "layer": hier_policy.layer_out(layer, a.scope, target_id)}
