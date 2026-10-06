# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PII rules: which built-in detectors of the prompt firewall run and whether
they mask or block, and the organization's own patterns
(core/pii_patterns.py checks those before they are saved).

The firewall (services/prompt_firewall.py) gets them through config(),
which every caller loads once per request: the gateway, user AI requests,
the provider playground, and the masked views of stored text
(observability), where block rules only mask.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import status
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import pii_patterns as pp
from app.core.errors import api_error
from app.models.pii import PiiRule, PiiSettings
from app.services.prompt_firewall import CustomRule, PiiConfig, scan

logger = logging.getLogger("pii_rules")

MAX_RULES = 50
# pattern checks and tests run in threads; a few at a time, so editors
# cannot fill the thread pool the request scans use too
_CHECKS: Dict[Any, asyncio.Semaphore] = {}


def _checks() -> asyncio.Semaphore:
    """One semaphore per event loop (tests run several loops)."""
    loop = asyncio.get_running_loop()
    if loop not in _CHECKS:
        _CHECKS.clear()
        _CHECKS[loop] = asyncio.Semaphore(2)
    return _CHECKS[loop]


async def _validate(pattern: str, ignore_case: bool) -> None:
    async with _checks():
        await asyncio.to_thread(pp.validate, pattern, ignore_case)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _pattern_error(e: pp.PiiPatternError):
    return api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, e.code, detail=e.detail or "")


async def _settings(db: AsyncSession, org_id: int, lock: bool = False) -> Optional[PiiSettings]:
    q = select(PiiSettings).where(PiiSettings.org_id == org_id)
    if lock:
        q = q.with_for_update()
    return (await db.execute(q)).scalar_one_or_none()


def builtin_state(row: Optional[PiiSettings]) -> Dict[str, Dict[str, Any]]:
    stored = (row.builtin if row is not None else None) or {}
    out = {}
    for b in pp.BUILTIN:
        s = stored.get(b["type"]) or {}
        action = s.get("action") if s.get("action") in pp.ACTIONS else "mask"
        out[b["type"]] = {"enabled": bool(s.get("enabled", True)), "action": action}
    return out


async def _rules(db: AsyncSession, org_id: int, only_enabled: bool = False) -> List[PiiRule]:
    q = select(PiiRule).where(PiiRule.org_id == org_id, PiiRule.deleted_at.is_(None))
    if only_enabled:
        q = q.where(PiiRule.enabled.is_(True))
    return list((await db.execute(q.order_by(PiiRule.id))).scalars())


async def config(db: AsyncSession, org_id: int, request_budget: Optional[float] = None) -> PiiConfig:
    """The firewall's settings for this organization. `request_budget`:
    seconds all scans of this request may spend on custom rules together
    (the gateway scans every message)."""
    state = builtin_state(await _settings(db, org_id))
    custom = []
    for r in await _rules(db, org_id, only_enabled=True):
        try:
            compiled = pp.compile_rule(r.pattern, r.ignore_case)
        except Exception:  # noqa: BLE001 - checked when saved; if it still fails, it fails closed
            logger.warning("PII rule %s does not compile; prompts it should check are refused", r.id)
            compiled = None
        custom.append(CustomRule(r.id, r.label, compiled, r.action))
    return PiiConfig(actions={t: s["action"] for t, s in state.items() if s["enabled"]}, custom=custom,
                     budget=request_budget)


async def note_timeouts(db: AsyncSession, org_id: int, rule_ids: List[int]) -> None:
    """Count rules that ran out of time; the caller commits."""
    if rule_ids:
        await db.execute(update(PiiRule).where(PiiRule.org_id == org_id, PiiRule.id.in_(rule_ids))
                         .values(timeouts=PiiRule.timeouts + 1, last_timeout_at=_now()))


def rule_out(r: PiiRule) -> Dict[str, Any]:
    return {"id": r.id, "name": r.name, "label": r.label, "description": r.description, "pattern": r.pattern,
            "ignore_case": r.ignore_case, "action": r.action, "enabled": r.enabled, "revision": r.revision,
            "timeouts": r.timeouts, "last_timeout_at": r.last_timeout_at,
            "created_at": r.created_at, "updated_at": r.updated_at}


async def overview(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    from app.core.config import settings

    row = await _settings(db, org_id)
    state = builtin_state(row)
    ner_models = settings.PROMPT_FIREWALL_NER_MODELS or {}
    return {
        "builtin": [{**b, **state[b["type"]]} for b in pp.BUILTIN],
        "revision": row.revision if row is not None else 0,
        "rules": [rule_out(r) for r in await _rules(db, org_id)],
        "names": {"ner_enabled": bool(settings.PROMPT_FIREWALL_NER_ENABLED),
                  "ner_languages": sorted(ner_models.keys()), "gazetteer_languages": ["uz"]},
        "limits": {"max_rules": MAX_RULES, "max_pattern_length": pp.MAX_PATTERN_LENGTH,
                   "rule_timeout_ms": int(pp.RULE_TIMEOUT * 1000)},
    }


async def save_builtin(db: AsyncSession, org_id: int, user_id: int, types: Dict[str, Dict[str, Any]],
                       revision: Optional[int]) -> Dict[str, Any]:
    """Change built-in types; returns {"before", "after"} for the audit record."""
    for t, v in types.items():
        if t not in pp.BUILTIN_TYPES:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pii.unknown_type", type=t)
        if "action" in v and v["action"] not in pp.ACTIONS:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pii.bad_action")
    row = await _settings(db, org_id, lock=True)
    current = row.revision if row is not None else 0
    if revision is not None and revision != current:
        raise api_error(status.HTTP_409_CONFLICT, "pii.stale")
    before = builtin_state(row)
    after = {t: dict(s) for t, s in before.items()}
    for t, v in types.items():
        if "enabled" in v:
            after[t]["enabled"] = bool(v["enabled"])
        if "action" in v:
            after[t]["action"] = v["action"]
    if row is None:
        row = PiiSettings(org_id=org_id, builtin=after, revision=1, updated_by=user_id, updated_at=_now())
        try:
            async with db.begin_nested():  # added inside: begin_nested flushes what is pending first
                db.add(row)
                await db.flush()
        except IntegrityError:  # created by someone else meanwhile
            raise api_error(status.HTTP_409_CONFLICT, "pii.stale")
    else:
        row.builtin = after
        row.revision = current + 1
        row.updated_by, row.updated_at = user_id, _now()
    return {"before": before, "after": after, "revision": row.revision}


def _clean(values: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(values)
    if "name" in out:
        out["name"] = (out["name"] or "").strip()
        if not out["name"]:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pii.name_required")
    if "label" in out:
        try:
            out["label"] = pp.validate_label(out["label"])
        except pp.PiiPatternError as e:
            raise _pattern_error(e)
    if "description" in out:
        out["description"] = (out["description"] or "").strip() or None
    if "action" in out and out["action"] not in pp.ACTIONS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "pii.bad_action")
    return out


async def get_rule(db: AsyncSession, org_id: int, rule_id: int, lock: bool = False) -> PiiRule:
    q = select(PiiRule).where(PiiRule.id == rule_id, PiiRule.org_id == org_id, PiiRule.deleted_at.is_(None))
    if lock:
        q = q.with_for_update()
    r = (await db.execute(q)).scalar_one_or_none()
    if r is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "pii.rule_not_found")
    return r


async def create_rule(db: AsyncSession, org_id: int, user_id: int, values: Dict[str, Any]) -> PiiRule:
    values = _clean(values)
    try:  # the timing test takes up to a few seconds: off the event loop
        await _validate(values["pattern"], bool(values.get("ignore_case")))
    except pp.PiiPatternError as e:
        raise _pattern_error(e)
    # one create at a time per organization, so the limit holds
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('provenza.pii_rules'), :org)"), {"org": int(org_id)})
    if len(await _rules(db, org_id)) >= MAX_RULES:
        raise api_error(status.HTTP_409_CONFLICT, "pii.too_many_rules", max=MAX_RULES)
    r = PiiRule(org_id=org_id, created_by=user_id, updated_by=user_id, created_at=_now(), updated_at=_now(),
                revision=1, timeouts=0, **values)
    try:
        async with db.begin_nested():
            db.add(r)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "pii.label_taken", label=values["label"])
    return r


async def update_rule(db: AsyncSession, org_id: int, user_id: int, rule_id: int, values: Dict[str, Any],
                      revision: Optional[int]) -> Dict[str, Any]:
    values = _clean(values)
    r = await get_rule(db, org_id, rule_id)
    pattern = values.get("pattern", r.pattern)
    ignore_case = bool(values.get("ignore_case", r.ignore_case))
    if pattern != r.pattern or ignore_case != r.ignore_case:
        try:  # before taking the row lock: the timing test can take seconds
            await _validate(pattern, ignore_case)
        except pp.PiiPatternError as e:
            raise _pattern_error(e)
    r = await get_rule(db, org_id, rule_id, lock=True)
    await db.refresh(r)  # the locked, current row
    if revision is not None and revision != r.revision:
        raise api_error(status.HTTP_409_CONFLICT, "pii.stale")
    if (values.get("pattern", r.pattern), bool(values.get("ignore_case", r.ignore_case))) != (pattern, ignore_case):
        raise api_error(status.HTTP_409_CONFLICT, "pii.stale")  # changed while we checked it
    before = rule_out(r)
    try:
        async with db.begin_nested():
            for k, v in values.items():
                setattr(r, k, v)
            r.revision = before["revision"] + 1
            r.updated_by, r.updated_at = user_id, _now()
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "pii.label_taken", label=values.get("label"))
    return {"before": before, "rule": r}


async def delete_rule(db: AsyncSession, org_id: int, user_id: int, rule_id: int) -> Dict[str, Any]:
    """Kept, marked deleted: the audit log and old flags still name it."""
    r = await get_rule(db, org_id, rule_id, lock=True)
    snapshot = rule_out(r)
    r.deleted_at = _now()
    r.enabled = False
    r.updated_by, r.updated_at = user_id, _now()
    return snapshot


async def test(db: AsyncSession, org_id: int, sample: str, draft: Optional[Dict[str, Any]] = None,
               exclude_id: Optional[int] = None) -> Dict[str, Any]:
    """A sample through the firewall with the organization's settings and,
    when given, a draft rule (as if saved, replacing `exclude_id`)."""
    sample = (sample or "")[:pp.MAX_SAMPLE_LENGTH]
    out: Dict[str, Any] = {"rule": None}
    cfg = await config(db, org_id)
    if exclude_id is not None:
        cfg.custom = [c for c in cfg.custom if c.id != exclude_id]
    if draft and (draft.get("pattern") or "").strip():
        try:
            label = pp.validate_label(draft.get("label") or "")
        except pp.PiiPatternError:
            label = "DRAFT"
        async with _checks():
            out["rule"], compiled = await asyncio.to_thread(pp.test, draft["pattern"],
                                                            bool(draft.get("ignore_case")), sample)
        if compiled is not None:  # not cached: drafts change on every keystroke
            action = draft.get("action") if draft.get("action") in pp.ACTIONS else "mask"
            cfg.custom = [CustomRule(0, label, compiled, action)] + [c for c in cfg.custom if c.label != label]
    async with _checks():
        r = await asyncio.to_thread(scan, sample, None, "en", cfg)
    out["firewall"] = {"blocked": r.blocked, "reason": r.blocked_reason, "flags": r.flags,
                       "masked_text": r.masked_text, "timed_out": r.timed_out}
    return out
