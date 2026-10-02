# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Content of agent events for the live terminal.

attach()  adds what an agent sent and got back to a batch of events, with
          personal data masked by the Prompt Firewall (the same masking the
          gateway applies). The live bus never carries this: content is read
          from the database for the reader that asked, per batch.
reveal()  the same content of ONE event without masking. Only for admins, on
          an explicit request; the API writes an audit entry for every call.

If masking fails the text is withheld, never shown unmasked.
"""

import asyncio
import json
from collections import defaultdict
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.a2a import A2AMessage
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.ai_request import AIRequest
from app.models.ai_response import AIResponse
from app.models.delegation import DelegationHop
from app.models.gateway import GatewayCall

MASK_LIMIT = 4000     # characters masked and shown per section in the terminal
RAW_LIMIT = 20000     # characters returned by reveal()
WITHHELD = "[content withheld: masking failed]"
# text Provenza writes itself from labels (verdict reasons, flag and
# capability names) - never user input, so it is shown as is
SYSTEM_LABELS = {"reason", "reasons", "flags", "capabilities", "findings"}


def _dump(value) -> Optional[str]:
    if value is None or value == {} or value == []:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]} … (+{len(text) - limit} chars)"


def _mask_many(texts: List[str]) -> List[str]:
    from app.services import prompt_firewall

    out = []
    for t in texts:
        try:
            out.append(prompt_firewall.scan(t).masked_text if t else t)
        except Exception:  # noqa: BLE001
            out.append(WITHHELD)
    return out


def _messages(raw_json: str) -> str:
    try:
        msgs = json.loads(raw_json)
    except (TypeError, ValueError):
        return raw_json
    lines = []
    for m in msgs if isinstance(msgs, list) else []:
        content = m.get("content") if isinstance(m, dict) else m
        if isinstance(content, list):
            content = " ".join(str(p.get("text", "")) if isinstance(p, dict) else str(p) for p in content)
        lines.append(f"[{m.get('role', '?') if isinstance(m, dict) else '?'}] {content}")
    return "\n".join(lines)


async def _sections(db: AsyncSession, org_id: int, kind: str, ids: List[int], raw: bool) -> Dict[int, List[dict]]:
    """{event id: [{"label", "text", "masked"}]} with UNMASKED text, except
    the gateway prompt, which is stored masked and decrypted only for raw."""
    out: Dict[int, List[dict]] = defaultdict(list)

    def add(i, label, value, pre_masked=False):
        text = _dump(value)
        if text:
            out[i].append({"label": label, "text": text,
                           "pre_masked": pre_masked or label in SYSTEM_LABELS})

    if kind == "action.recorded":
        rows = (await db.execute(select(AgentAction.id, AgentAction.input_data, AgentAction.output_data,
                                        AgentAction.reason)
                                 .where(AgentAction.org_id == org_id, AgentAction.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "input", r.input_data)
            add(r.id, "output", r.output_data)
            add(r.id, "reason", r.reason)
    elif kind == "action.checked":
        rows = (await db.execute(select(ActionCheck.id, ActionCheck.reason, ActionCheck.action_capabilities)
                                 .where(ActionCheck.org_id == org_id, ActionCheck.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "reason", r.reason)
            add(r.id, "capabilities", r.action_capabilities)
    elif kind == "incident.created":
        rows = (await db.execute(select(AgentIncident.id, AgentIncident.details)
                                 .where(AgentIncident.org_id == org_id, AgentIncident.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "details", r.details)
    elif kind == "llm.call":
        calls = (await db.execute(select(GatewayCall.id, GatewayCall.reason, GatewayCall.flags, GatewayCall.ai_request_id)
                                  .where(GatewayCall.org_id == org_id, GatewayCall.id.in_(ids)))).all()
        req_ids = [c.ai_request_id for c in calls if c.ai_request_id]
        reqs, resps = {}, {}
        if req_ids:
            reqs = {r.id: r for r in (await db.execute(
                select(AIRequest.id, AIRequest.masked_input_text, AIRequest.input_text_encrypted)
                .where(AIRequest.org_id == org_id, AIRequest.id.in_(req_ids)))).all()}
            resps = {r.request_id: r.response_text for r in (await db.execute(
                select(AIResponse.request_id, AIResponse.response_text).where(AIResponse.request_id.in_(req_ids)))).all()}
        for c in calls:
            req = reqs.get(c.ai_request_id)
            if req is not None:
                if raw and req.input_text_encrypted:
                    from app.core.crypto import decrypt_secret
                    try:
                        add(c.id, "prompt", _messages(decrypt_secret(req.input_text_encrypted)))
                    except Exception:  # noqa: BLE001 - key rotated away, BYOK key revoked...
                        add(c.id, "prompt", "[original prompt cannot be decrypted]")
                else:
                    add(c.id, "prompt", req.masked_input_text, pre_masked=True)
            add(c.id, "response", resps.get(c.ai_request_id))
            add(c.id, "reason", c.reason)
            add(c.id, "flags", c.flags)
    elif kind == "a2a.message":
        rows = (await db.execute(select(A2AMessage.id, A2AMessage.reasons, A2AMessage.findings, A2AMessage.payload_sha256)
                                 .where(A2AMessage.org_id == org_id, A2AMessage.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "reasons", r.reasons)
            add(r.id, "findings", r.findings)
            add(r.id, "payload", f"not stored; sha256 {r.payload_sha256}" if r.payload_sha256 else None, pre_masked=True)
    elif kind == "delegation.hop":
        rows = (await db.execute(select(DelegationHop.id, DelegationHop.task_description,
                                        DelegationHop.delegated_capabilities, DelegationHop.depth)
                                 .where(DelegationHop.org_id == org_id, DelegationHop.id.in_(ids)))).all()
        for r in rows:
            add(r.id, "task", r.task_description)
            add(r.id, "capabilities", r.delegated_capabilities)
    return out


async def attach(db: AsyncSession, org_id: int, events: List[dict]) -> None:
    """Add masked "content" to each event in place."""
    by_kind: Dict[str, List[int]] = defaultdict(list)
    for ev in events:
        if isinstance(ev.get("id"), int):
            by_kind[ev.get("type")].append(ev["id"])
    found: Dict[tuple, List[dict]] = {}
    for kind, ids in by_kind.items():
        for i, secs in (await _sections(db, org_id, kind, ids, raw=False)).items():
            found[(kind, i)] = secs

    pending = [s for secs in found.values() for s in secs if not s["pre_masked"]]
    masked = await asyncio.to_thread(_mask_many, [_cut(s["text"], MASK_LIMIT) for s in pending]) if pending else []
    for s, m in zip(pending, masked):
        s["text"] = m
    for ev in events:
        secs = found.get((ev.get("type"), ev.get("id")))
        if secs:
            ev["content"] = [{"label": s["label"], "text": _cut(s["text"], MASK_LIMIT)} for s in secs]
            ev["masked"] = True


async def reveal(db: AsyncSession, org_id: int, kind: str, event_id: int) -> Optional[List[dict]]:
    """Unmasked content of one event, or None when it does not exist."""
    secs = (await _sections(db, org_id, kind, [event_id], raw=True)).get(event_id)
    if secs is None:
        return None
    return [{"label": s["label"], "text": _cut(s["text"], RAW_LIMIT)} for s in secs]
