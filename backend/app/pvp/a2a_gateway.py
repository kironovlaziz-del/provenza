# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
A2A gateway - an organization's agents talk to remote A2A agents only
through Provenza (docs/pvp/spec.md, section 5.2).

    agent ──A2A 1.0 / 0.3──► /api/v1/a2a-gateway/<peer> ──► Input Guard ──► PVP check
                                                                 │
                    record (executed_by="a2a_gateway") ◄── remote A2A agent (its own version)

Each operation is a PVP action of the calling agent on the tool
"a2a.<peer>", so agent rights, policies (who may talk to whom), the Tool
Registry, ASI01/ASI05 on what is sent, the behaviour baseline and the
breaker all apply, and every exchange is recorded:

  a2a.send          SendMessage / message/send
  a2a.get_task      GetTask / tasks/get
  a2a.cancel_task   CancelTask / tasks/cancel

Guarantees beyond the MCP gateway's (credentials stay here, the approved
card is what is served, the live card is re-checked before each call, the
answer is scanned and withheld in enforce mode when it carries injected
instructions):

  tasks are owned  a task belongs to the agent that created it. GetTask,
                   CancelTask, a follow-up message (taskId) or a reference
                   (referenceTaskIds) to someone else's task is
                   TaskNotFound - checked before anything else, so it
                   reveals nothing (A2A 1.0, 13.1)
  no side channels push-notification configs are refused: the peer would
                   deliver to a URL outside scanning and audit. Streaming
                   and resubscription are not offered.
"""

import itertools
import time
from typing import Any, Dict, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_secret
from app.core.outbound import validate_url
from app.models.a2a_gateway import A2APeer, A2ATask
from app.models.agent import Agent
from app.models.agent_action import AgentIncident
from app.models.tool_registry import ToolRegistryEntry
from app.pvp import a2a_wire as w
from app.pvp.guard import structure_findings
from app.pvp.model import ALLOWED, PENDING_APPROVAL, PVPActionRequest
from app.pvp.orchestrator import PVPOrchestrator
from app.pvp.upstream_http import UpstreamError, get_json, jsonrpc
from app.services.agent_rights import own_rights
from app.services.supply_chain import DRIFT_INCIDENT, manifest_digest

EXECUTOR = "a2a_gateway"
CHAIN_META = "provenza/chain_id"
LIVE_TTL_SECONDS = 60
MAX_CARD_BYTES = 1024 * 1024
REFUSED = -32000   # implementation-defined server error: refused by Provenza
ACTION_TYPES = {"SendMessage": "a2a.send", "GetTask": "a2a.get_task", "CancelTask": "a2a.cancel_task"}

# peer id -> (expires at, card digest)
_live: Dict[int, Tuple[float, str]] = {}
_ids = itertools.count(1)


def tool_name(slug: str) -> str:
    return f"a2a.{slug}"


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _auth(peer: A2APeer) -> Dict[str, str]:
    if not peer.auth_secret_encrypted:
        return {}
    return {peer.auth_header: decrypt_secret(peer.auth_secret_encrypted)}


async def fetch_card(peer: A2APeer) -> dict:
    card = await get_json(peer.card_url, headers=_auth(peer), timeout=float(peer.timeout_seconds),
                          max_bytes=MAX_CARD_BYTES)
    if not isinstance(card, dict):
        raise UpstreamError("upstream.bad_card", "the agent card is not an object")
    return w.pinned_card(card)


class A2AGateway:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ admin

    async def sync(self, org_id: int, peer: A2APeer) -> dict:
        """Fetch and pin-check the peer's card. A new peer gets a pending Tool
        Registry entry pinned to this card; a card that changed after approval
        drifts (incident) until an admin approves it again."""
        try:
            card = await fetch_card(peer)
            try:
                endpoint, version = w.card_endpoint(card)
            except w.A2AError as exc:
                raise UpstreamError("upstream.bad_card", exc.message) from exc
            try:
                validate_url(endpoint)
            except ValueError as exc:
                raise UpstreamError("upstream.endpoint_blocked", str(exc)) from exc
        except UpstreamError as exc:
            peer.last_error = f"{exc.code}: {str(exc)[:300]}"
            await self.db.commit()
            raise
        digest = manifest_digest(card)
        changed = peer.card_digest is not None and peer.card_digest != digest
        peer.card, peer.card_digest, peer.endpoint_url, peer.protocol_version = card, digest, endpoint, version
        entry = await self._entry(org_id, peer, digest)
        peer.registry_entry_id = entry.id
        if entry.status == "approved" and entry.pinned_digest != digest:
            entry.status = "drifted"
            entry.drift_details = {"detected_at": _now().isoformat(), "tool": entry.pattern,
                                   "problems": ["A2A agent card changed"], "reported_digest": digest,
                                   "pinned_digest": entry.pinned_digest, "detected_by": "a2a_sync"}
            self.db.add(AgentIncident(org_id=org_id, incident_type=DRIFT_INCIDENT, severity="critical",
                                      details={"registry_entry_id": entry.id, "pattern": entry.pattern,
                                               **entry.drift_details}))
        peer.last_synced_at, peer.last_error = _now(), None
        _live.pop(peer.id, None)
        status = entry.status
        await self.db.commit()
        return {"version": version, "endpoint": endpoint, "card_digest": digest, "changed": changed,
                "status": status, "skills": len(card.get("skills") or [])}

    async def _entry(self, org_id: int, peer: A2APeer, digest: str) -> ToolRegistryEntry:
        name = tool_name(peer.slug)
        entry = (await self.db.execute(select(ToolRegistryEntry).where(
            ToolRegistryEntry.org_id == org_id, ToolRegistryEntry.pattern == name))).scalar_one_or_none()
        if entry is None:
            entry = ToolRegistryEntry(
                org_id=org_id, pattern=name, kind="tool", status="pending", discovered=True, seen_count=0,
                display_name=peer.name[:255], source=f"a2a:{peer.slug}", pinned_digest=digest, first_seen_at=_now(),
                notes=f"A2A agent '{peer.name}', added by a sync; approve its card to let agents reach it")
            self.db.add(entry)
            await self.db.flush()
        elif entry.pinned_digest is None:
            entry.pinned_digest = digest
        return entry

    async def approve(self, org_id: int, peer: A2APeer, user_id: int) -> ToolRegistryEntry:
        entry = await self._entry(org_id, peer, peer.card_digest)
        peer.registry_entry_id = entry.id
        entry.pinned_digest, entry.status = peer.card_digest, "approved"
        entry.approved_by, entry.approved_at, entry.drift_details = user_id, _now(), None
        await self.db.commit()
        return entry

    # ------------------------------------------------------------------ agents

    async def reachable(self, agent: Agent, slug: str) -> Optional[A2APeer]:
        """The peer, if this agent may see it: enabled, its synced card is the
        approved one, and "a2a.<slug>" is in the agent's rights. Otherwise
        None - an agent cannot tell an unknown peer from a forbidden one."""
        row = (await self.db.execute(
            select(A2APeer, ToolRegistryEntry)
            .join(ToolRegistryEntry, ToolRegistryEntry.id == A2APeer.registry_entry_id)
            .where(A2APeer.org_id == agent.org_id, A2APeer.slug == slug, A2APeer.enabled.is_(True),
                   ToolRegistryEntry.status == "approved", ToolRegistryEntry.pinned_digest == A2APeer.card_digest)
        )).first()
        if row is None or tool_name(slug) not in set(own_rights(agent).tools):
            return None
        return row[0]

    async def _live_digest(self, peer: A2APeer) -> str:
        cached = _live.get(peer.id)
        if cached is None or cached[0] < time.monotonic():
            cached = (time.monotonic() + LIVE_TTL_SECONDS, manifest_digest(await fetch_card(peer)))
            _live[peer.id] = cached
        return cached[1]

    async def _owner(self, peer: A2APeer, task_id: str) -> Optional[int]:
        row = (await self.db.execute(select(A2ATask.agent_id).where(
            A2ATask.peer_id == peer.id, A2ATask.task_id == task_id))).first()
        return row[0] if row else None

    async def _own(self, agent_id: int, peer: A2APeer, task_ids) -> None:
        for task_id in task_ids:
            if task_id and await self._owner(peer, task_id) != agent_id:
                raise w.A2AError(w.TASK_NOT_FOUND, "Task not found")

    async def _claim(self, org_id: int, peer_id: int, agent_id: int, task: dict) -> bool:
        """Make the task this agent's - atomically, by the unique (peer, task)
        key - or report that it already belongs to someone else."""
        try:
            async with self.db.begin_nested():
                self.db.add(A2ATask(org_id=org_id, peer_id=peer_id, agent_id=agent_id, task_id=task["id"],
                                    context_id=task.get("contextId") if isinstance(task.get("contextId"), str)
                                    and len(task["contextId"]) <= w.MAX_ID else None))
        except IntegrityError:
            pass
        owner = (await self.db.execute(select(A2ATask.agent_id).where(
            A2ATask.peer_id == peer_id, A2ATask.task_id == task["id"]))).scalar_one()
        return owner == agent_id

    async def handle(self, agent: Agent, peer: A2APeer, canonical: str, params: dict,
                     chain_id: Optional[int]) -> Tuple[str, dict]:
        """One governed operation. Returns ("task" | "message", canonical
        object) or raises A2AError."""
        org_id, agent_id, slug = agent.org_id, agent.id, peer.slug
        peer_id, endpoint, version, pinned = peer.id, peer.endpoint_url, peer.protocol_version, peer.card_digest
        auth, timeout = _auth(peer), float(peer.timeout_seconds)

        # ownership first: nothing below may tell whether someone else's task exists
        if canonical == "SendMessage":
            msg = params["message"]
            if msg.get("role") != "ROLE_USER":
                raise w.A2AError(w.INVALID_PARAMS, "message.role must be ROLE_USER: the agent is the client")
            await self._own(agent_id, peer, [msg.get("taskId"), *(msg.get("referenceTaskIds") or [])])
        else:
            await self._own(agent_id, peer, [params["id"]])

        try:
            live, live_error = await self._live_digest(peer), None
        except UpstreamError as exc:
            live, live_error = None, exc.code

        orc = PVPOrchestrator(self.db)
        check = await orc.check(org_id, PVPActionRequest(
            agent_id=agent_id, chain_id=chain_id, action_type=ACTION_TYPES[canonical], tool_name=tool_name(slug),
            input=params, tool_digest=live))

        refusal = None
        if live_error:
            refusal = f"A2A gateway: the remote agent's card could not be confirmed ({live_error})"
        elif live != pinned:
            refusal = "A2A gateway: the remote agent's card changed since it was approved (ASI04)"
        if check.decision != ALLOWED or refusal:
            action = await orc.record_executed(org_id, check, input_data=params, output=None, duration_ms=None,
                                                  executed_by=EXECUTOR, refusal=refusal)
            if check.decision == PENDING_APPROVAL and not refusal:
                raise w.A2AError(REFUSED, "This call needs a human approval and was not sent",
                                 {"action_id": action.id, "reason": check.reason})
            raise w.A2AError(REFUSED, "Refused by Provenza", {"action_id": action.id, "reason": refusal or check.reason})

        wire_params = w.send_params_to_wire(params, version) if canonical == "SendMessage" else params
        body = {"jsonrpc": "2.0", "id": next(_ids), "method": w.wire_method(canonical, version), "params": wire_params}
        headers = {**auth, **({"A2A-Version": "1.0"} if version == w.V1 else {})}
        started = time.monotonic()
        kind, obj, output, peer_error = "task", None, None, None
        try:
            status, _, msg = await jsonrpc(endpoint, body, headers=headers, timeout=timeout)
            if msg is None:
                raise UpstreamError("upstream.bad_response", f"HTTP {status}, no JSON-RPC response")
            if "error" in msg:
                err = msg.get("error") or {}
                code = err.get("code") if isinstance(err.get("code"), int) else REFUSED
                peer_error = w.A2AError(code, str(err.get("message") or "The remote agent refused")[:300])
                output = {"peer_error": code}
            else:
                kind, obj = w.result_from_peer(canonical, msg.get("result"), version)
                output = {kind: obj}
        except UpstreamError as exc:
            output, peer_error = {"upstream_error": exc.code}, w.A2AError(REFUSED, "The remote agent could not "
                                                                                  "be reached", {"reason": exc.code})
        except w.A2AError as exc:
            output, peer_error = {"invalid_agent_response": exc.message[:200]}, exc
        duration = int((time.monotonic() - started) * 1000)

        bad = structure_findings(output, "$.output")
        if bad:
            output, obj = {"withheld": sorted({f.code for f in bad})}, None
            peer_error = w.A2AError(REFUSED, "The remote agent's answer was refused by Provenza",
                                    {"reason": output["withheld"]})
        if obj is not None and kind == "task" and canonical == "SendMessage" \
                and not await self._claim(org_id, peer_id, agent_id, obj):
            # the peer answered with another caller's task: never hand it over
            output, obj = {"withheld": ["a2a.foreign_task"]}, None
            peer_error = w.A2AError(w.INVALID_AGENT_RESPONSE, "The remote agent returned a task of another caller")
        action = await orc.record_executed(org_id, check, input_data=params, output=output,
                                                   duration_ms=duration, executed_by=EXECUTOR)
        if peer_error is not None:
            data = dict(peer_error.data or {})
            data["action_id"] = action.id
            raise w.A2AError(peer_error.code, peer_error.message, data)
        return kind, obj
