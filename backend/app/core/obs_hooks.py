# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent events for the live view, taken from the database itself.

One SQLAlchemy session hook instead of a publish() call in every guard: an
AgentAction, ActionCheck or AgentIncident that is flushed is noted, and
published only after the transaction commits (a rolled back verdict never
reaches the screen). Every guard that writes an incident - injection,
breaker, supply chain, behaviour, A2A, memory, identity, approvals - is
covered without touching it, including future ones.

What goes out (to_event) is metadata only: ids, tool or model name,
verdict or status, the OWASP codes found in the reason, flag labels,
tokens, duration. Never arguments, prompts, outputs, the free-text reason
or incident details - those can carry personal data. Content is attached
later, per reader, masked (app.services.obs_content); raw text only on an
admin's explicit, audited request.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core import obs_bus

log = logging.getLogger(__name__)

EVENT_TYPES = ("action.checked", "action.recorded", "llm.call", "a2a.message", "delegation.hop", "incident.created")
KINDS = {"ActionCheck": "action.checked", "AgentAction": "action.recorded", "AgentIncident": "incident.created",
         "GatewayCall": "llm.call", "A2AMessage": "a2a.message", "DelegationHop": "delegation.hop"}
GUARD_RE = re.compile(r"\bASI(?:0[1-9]|10)\b")
_KEY = "obs_pending"


def guards_in(*texts) -> List[str]:
    found = set()
    for t in texts:
        if t:
            found.update(GUARD_RE.findall(str(t).upper()))
    return sorted(found)


def _labels(value, n=20) -> List[str]:
    """Short string labels from a JSON list (flags, reasons) - never free text."""
    if not isinstance(value, list):
        return []
    return [str(v)[:60] for v in value[:n] if isinstance(v, (str, int))]


def _short(value, n=100):
    return value[:n] if isinstance(value, str) else value


def to_event(obj) -> Optional[Tuple[int, dict]]:
    """(org_id, event) for a tracked row, else None. Reads only attributes
    already loaded on the instance - no lazy loads inside a flush."""
    kind = KINDS.get(type(obj).__name__)
    if kind is None:
        return None
    d = obj.__dict__
    org_id, ev_id = d.get("org_id"), d.get("id")
    if org_id is None or ev_id is None:
        return None
    ts = d.get("created_at")
    ev = {
        "v": 1,
        "type": kind,
        "id": ev_id,
        "ts": (ts if isinstance(ts, datetime) else datetime.now(timezone.utc)).isoformat(),
        "agent_id": d.get("agent_id"),
        "chain_id": d.get("chain_id"),
    }
    if kind == "incident.created":
        ev.update(incident_type=d.get("incident_type"), severity=d.get("severity"))
    elif kind == "llm.call":
        flags = _labels(d.get("flags"))
        ev.update(model=_short(d.get("model")), status=d.get("status"), duration_ms=d.get("latency_ms"),
                  prompt_tokens=d.get("prompt_tokens"), completion_tokens=d.get("completion_tokens"),
                  provider_id=d.get("provider_id"), flags=flags, guards=guards_in(d.get("reason"), " ".join(flags)))
    elif kind == "a2a.message":
        ev.update(agent_id=d.get("from_agent_id"), to_agent_id=d.get("to_agent_id"),
                  message_type=_short(d.get("message_type"), 50), status=d.get("status"),
                  signature_valid=d.get("signature_valid"), guards=["ASI07"] if d.get("status") != "accepted" else [])
    elif kind == "delegation.hop":
        ev.update(agent_id=d.get("from_agent_id"), to_agent_id=d.get("to_agent_id"), depth=d.get("depth"),
                  capabilities=_labels(d.get("delegated_capabilities")), verified=d.get("verified"))
    else:
        ev.update(
            action_type=_short(d.get("action_type"), 50),
            tool=_short(d.get("tool_name")),
            policy_id=d.get("policy_id"),
        )
        if kind == "action.checked":
            ev.update(decision=d.get("decision"), guards=guards_in(d.get("reason")), incident_type=d.get("incident_type"))
        else:
            ev.update(
                decision=d.get("policy_check_result"),
                guards=guards_in(d.get("reason")),
                duration_ms=d.get("duration_ms"),
                has_check=d.get("check_id") is not None,
            )
    return org_id, {k: v for k, v in ev.items() if v is not None and v != []}


def matches(ev: dict, agent_ids: Optional[set], types: Optional[set]) -> bool:
    if types and ev.get("type") not in types:
        return False
    if agent_ids and ev.get("agent_id") not in agent_ids and ev.get("to_agent_id") not in agent_ids:
        return False
    return True


def _after_flush(session, flush_context):
    try:
        found = []
        for obj in session.new:
            if type(obj).__name__ in KINDS:
                item = to_event(obj)
                if item:
                    found.append(item)
        if found:
            session.info.setdefault(_KEY, []).extend(found)
    except Exception:  # noqa: BLE001 - the live view must never break a write
        log.debug("observability: after_flush failed", exc_info=True)


def _after_commit(session):
    pending = session.info.pop(_KEY, None)
    if not pending:
        return
    try:
        by_org: Dict[int, List[dict]] = {}
        for org_id, ev in pending:
            by_org.setdefault(org_id, []).append(ev)
        for org_id, events in by_org.items():
            obs_bus.publish(org_id, events)
    except Exception:  # noqa: BLE001
        log.debug("observability: publish failed", exc_info=True)


def _after_soft_rollback(session, previous_transaction):
    session.info.pop(_KEY, None)


def install() -> None:
    for name, fn in (("after_flush", _after_flush), ("after_commit", _after_commit),
                     ("after_soft_rollback", _after_soft_rollback)):
        if not event.contains(Session, name, fn):
            event.listen(Session, name, fn)


install()
