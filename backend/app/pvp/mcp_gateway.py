# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
MCP gateway - Provenza as the only MCP server an agent talks to
(docs/pvp/spec.md, section 5).

    agent ──MCP──► /api/v1/mcp ──► Input Guard ──► PVP check ──► upstream MCP server
                                                       │               (HTTP only,
                                    record (executed_by="mcp_gateway") ◄┘ SSRF-guarded)

What it guarantees, and how:

  credentials      the agent knows the gateway and its own key. Upstream
                   URLs stay here; credentials do not: a server that takes
                   one is sealed to the egress proxies (app/pvp/sealed.py)
                   and reached through them only.
  what the model   tools/list serves only tools an admin approved, with the
  reads            definition that was approved: a tool is shown while its
                   synced definition hashes to the Tool Registry pin. A
                   description changed upstream ("tool poisoning") is never
                   shown - the tool disappears until it is re-approved.
  what is called   before every call the live definition is fetched (cached
                   LIVE_TTL_SECONDS) and hashed by the gateway itself - not
                   reported by the agent - so a tool that changed after
                   approval is refused, and the Tool Registry raises its drift
                   incident.
  the decision     every call is a PVP action.request through the
                   orchestrator: rights in the chain, policies, the Tool
                   Registry, the behaviour baseline, the circuit breaker.
                   Denied and refused calls are recorded too.
  the output       NUL characters / oversized structures are refused (they
                   could not even be stored).

Pending approval (ASI09): the call is recorded as pending and NOT executed;
the agent is told so. Approvals are given on the recorded action; the same
call made again after the approval runs once (app/pvp/approvals.py).

Errors follow MCP: an unknown tool is a JSON-RPC error; a refusal is a tool
result with isError, so the model sees why - never the refused content.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.pvp import enforcement
from app.models.agent import Agent
from app.models.agent_action import AgentIncident
from app.models.mcp import MCPServer, MCPTool
from app.models.tool_registry import ToolRegistryEntry
from app.pvp import mcp_client
from app.pvp.guard import structure_findings
from app.pvp.model import ALLOWED, PENDING_APPROVAL, PVPActionRequest
from app.pvp.orchestrator import PVPOrchestrator
from app.services.agent_rights import own_rights
from app.services.supply_chain import DRIFT_INCIDENT, manifest_digest

DEFINITION_KEYS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
LIVE_TTL_SECONDS = 60
EXECUTOR = "mcp_gateway"
CHAIN_META = "provenza/chain_id"

# server id -> (expires at, {tool name: definition})
_live: Dict[int, Tuple[float, Dict[str, dict]]] = {}


def definition_of(tool: dict) -> dict:
    """What an agent's model reads about a tool - all of it is pinned."""
    return {k: tool[k] for k in DEFINITION_KEYS if k in tool}


def digest_of(definition: dict) -> str:
    return manifest_digest(definition)


def exposed(slug: str, name: str) -> str:
    return f"{slug}.{name}"


def _text_result(text: str, *, is_error: bool = True) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MCPGatewayError(Exception):
    """A JSON-RPC protocol error (unknown tool, bad params)."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def upstream_for(server: MCPServer) -> mcp_client.MCPUpstream:
    """This server holds no upstream credential (app/pvp/sealed.py): an MCP
    server that takes one is reached through an egress proxy only."""
    if (server.credential_source or "none") != "none":
        raise mcp_client.UpstreamError("upstream.credential_at_proxy",
                                       "its credential is sealed to the egress proxies: reach it through one")
    protocol = server.detected_version or server.protocol
    return mcp_client.MCPUpstream(server.id, server.url, protocol=protocol, auth_header=server.auth_header,
                                  auth_value=None, timeout=float(server.timeout_seconds))


class MCPGateway:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ sync

    async def sync(self, org_id: int, server: MCPServer) -> dict:
        """Fetch the server's tools. New tools get a pending Tool Registry
        entry pinned to the definition seen now; a tool whose definition
        changed keeps its approved pin and becomes drifted (incident) until
        an admin approves the new definition. Nothing is approved here."""
        up = upstream_for(server)
        try:
            server.detected_version = await up.detect()
            tools = await up.list_tools()
        except mcp_client.UpstreamError as exc:
            server.last_error = f"{exc.code}: {str(exc)[:300]}"
            await self.db.commit()
            raise
        return await self.apply_sync(org_id, server, tools, up.server_info)

    async def apply_sync(self, org_id: int, server: MCPServer, tools: List[dict],
                         server_info: Optional[dict]) -> dict:
        """The tools a sync found - by this gateway, or by an egress proxy for a
        server whose credential is sealed to it (POST /egress-proxy/mcp/sync)."""
        server.server_info = server_info
        now = _now()
        rows = {t.name: t for t in (await self.db.execute(
            select(MCPTool).where(MCPTool.server_id == server.id))).scalars()}
        report: Dict[str, List[Any]] = {"added": [], "changed": [], "unchanged": [], "removed": [], "skipped": []}
        seen = set()
        for tool in tools:
            name = tool.get("name")
            if not isinstance(name, str) or not mcp_client.TOOL_NAME.match(name):
                report["skipped"].append({"name": str(name)[:128], "reason": "name"})
                continue
            full = exposed(server.slug, name)
            if len(full) > 100:
                report["skipped"].append({"name": name, "reason": "name_too_long"})
                continue
            if name in seen:
                report["skipped"].append({"name": name, "reason": "duplicate"})
                continue
            seen.add(name)
            definition = definition_of(tool)
            digest = digest_of(definition)
            entry = await self._entry(org_id, full, server, definition, digest)
            row = rows.get(name)
            if row is None:
                row = MCPTool(org_id=org_id, server_id=server.id, name=name, exposed_name=full,
                              definition=definition, digest=digest, first_seen_at=now)
                self.db.add(row)
                report["added"].append(full)
            elif row.digest != digest or row.removed_at is not None:
                report["changed"].append(full)
            else:
                report["unchanged"].append(full)
            row.definition, row.digest, row.last_seen_at, row.removed_at = definition, digest, now, None
            row.registry_entry_id = entry.id
            self._drift_check(org_id, entry, digest)
        for name, row in rows.items():
            if name not in seen and row.removed_at is None:
                row.removed_at = now
                report["removed"].append(row.exposed_name)
        server.last_synced_at, server.last_error = now, None
        _live.pop(server.id, None)
        await self.db.commit()
        return report

    async def _entry(self, org_id: int, full: str, server: MCPServer, definition: dict,
                     digest: str) -> ToolRegistryEntry:
        entry = (await self.db.execute(select(ToolRegistryEntry).where(
            ToolRegistryEntry.org_id == org_id, ToolRegistryEntry.pattern == full))).scalar_one_or_none()
        if entry is None:
            entry = ToolRegistryEntry(
                org_id=org_id, pattern=full, kind="tool", status="pending", discovered=True, seen_count=0,
                display_name=(definition.get("title") or definition.get("name"))[:255],
                source=f"mcp:{server.slug}", pinned_digest=digest, first_seen_at=_now(),
                notes=f"MCP tool of server '{server.name}', added by a sync; approve to expose it to agents",
            )
            self.db.add(entry)
            await self.db.flush()
        elif entry.pinned_digest is None:
            entry.pinned_digest = digest
        return entry

    def _drift_check(self, org_id: int, entry: ToolRegistryEntry, digest: str) -> None:
        if entry.status == "approved" and entry.pinned_digest and entry.pinned_digest != digest:
            entry.status = "drifted"
            entry.drift_details = {"detected_at": _now().isoformat(), "tool": entry.pattern,
                                   "problems": ["MCP tool definition changed upstream"],
                                   "reported_digest": digest, "pinned_digest": entry.pinned_digest,
                                   "detected_by": "mcp_sync"}
            self.db.add(AgentIncident(org_id=org_id, incident_type=DRIFT_INCIDENT, severity="critical",
                                      details={"registry_entry_id": entry.id, "pattern": entry.pattern,
                                               **entry.drift_details}))

    async def approve(self, org_id: int, tool: MCPTool, user_id: int) -> ToolRegistryEntry:
        """Approve the definition seen at the last sync: re-pin and approve."""
        entry = await self._entry(org_id, tool.exposed_name, await self._server(org_id, tool.server_id),
                                  tool.definition, tool.digest)
        tool.registry_entry_id = entry.id
        entry.pinned_digest, entry.status = tool.digest, "approved"
        entry.approved_by, entry.approved_at, entry.drift_details = user_id, _now(), None
        await self.db.commit()
        return entry

    async def _server(self, org_id: int, server_id: int) -> MCPServer:
        return (await self.db.execute(select(MCPServer).where(
            MCPServer.id == server_id, MCPServer.org_id == org_id))).scalar_one()

    # ------------------------------------------------------- agent: list

    async def _approved(self, org_id: int, name: Optional[str] = None):
        """(tool, server) pairs whose synced definition is the approved one."""
        q = (select(MCPTool, MCPServer, ToolRegistryEntry)
             .join(MCPServer, MCPServer.id == MCPTool.server_id)
             .join(ToolRegistryEntry, ToolRegistryEntry.id == MCPTool.registry_entry_id)
             .where(MCPTool.org_id == org_id, MCPServer.enabled.is_(True), MCPTool.removed_at.is_(None),
                    ToolRegistryEntry.status == "approved",
                    ToolRegistryEntry.pinned_digest == MCPTool.digest))
        if name is not None:
            q = q.where(MCPTool.exposed_name == name)
        return [(t, s) for t, s, _ in (await self.db.execute(q.order_by(MCPTool.exposed_name))).all()]

    async def list_tools(self, agent: Agent) -> List[dict]:
        allowed = set(own_rights(agent).tools)
        out = []
        for tool, _ in await self._approved(agent.org_id):
            if tool.exposed_name in allowed:
                out.append({**tool.definition, "name": tool.exposed_name})
        return out

    # ------------------------------------------------------- agent: call

    async def _live_definition(self, server: MCPServer, name: str) -> Optional[dict]:
        cached = _live.get(server.id)
        if cached is None or cached[0] < time.monotonic():
            tools = await upstream_for(server).list_tools()
            cached = (time.monotonic() + LIVE_TTL_SECONDS,
                      {t["name"]: definition_of(t) for t in tools if isinstance(t.get("name"), str)})
            _live[server.id] = cached
        return cached[1].get(name)

    async def plan(self, agent: Agent, name: str, arguments: Dict[str, Any], chain_id: Optional[int],
                   live_digest: Optional[str], live_error: Optional[str], proxy) -> dict:
        """A tool call an egress proxy makes to a server whose credential is
        sealed to it: decided here as call() decides, with the live
        definition's digest the proxy computed itself from the upstream."""
        from app.pvp import proxy_actions

        org_id, agent_id = agent.org_id, agent.id
        found = await self._approved(org_id, name)
        if not found:
            raise MCPGatewayError(-32602, f"Unknown tool: {name}")
        tool, server = found[0]
        orc = PVPOrchestrator(self.db)
        check = await orc.check(org_id, PVPActionRequest(
            agent_id=agent_id, chain_id=chain_id, action_type="tool_call", tool_name=name, input=arguments,
            tool_digest=live_digest))
        refusal = None
        if live_error:
            refusal = f"MCP gateway: the upstream server could not confirm the tool ({live_error[:100]})"
        elif live_digest != tool.digest:
            refusal = "MCP gateway: the tool's definition changed upstream since it was approved (ASI04)"
        if check.decision != ALLOWED or refusal:
            action = await orc.record_executed(org_id, check, input_data=arguments, output=None,
                                                  duration_ms=None, executed_by=proxy_actions.EXECUTOR,
                                                  refusal=refusal)
            if check.decision == PENDING_APPROVAL and not refusal:
                return {"decision": "refused", "result": _text_result(
                    f"This call needs a human approval and was not executed (action #{action.id}): {check.reason}")}
            return {"decision": "refused",
                    "result": _text_result(f"Refused by Provenza (action #{action.id}): {refusal or check.reason}")}
        await proxy_actions.reserve(self.db, proxy, check.check_id, arguments)
        out = await proxy_actions.allowed(self.db, proxy, check, arguments)
        return {**out, "arguments": arguments, "upstream_name": tool.name,
                "input_schema": (tool.definition or {}).get("inputSchema"), "pinned_digest": tool.digest,
                "server": {"id": server.id, "slug": server.slug, "url": server.url,
                           "protocol": server.detected_version or server.protocol,
                           "timeout_seconds": server.timeout_seconds},
                "credential": {"object": "mcp_server", "id": server.id,
                               "source": server.credential_source or "none", "header": server.auth_header}}

    async def call(self, agent: Agent, name: str, arguments: Dict[str, Any], chain_id: Optional[int]) -> dict:
        org_id, agent_id = agent.org_id, agent.id
        found = await self._approved(org_id, name)
        if not found:
            raise MCPGatewayError(-32602, f"Unknown tool: {name}")
        tool, server = found[0]
        upstream_name, schema, pinned = tool.name, (tool.definition or {}).get("inputSchema"), tool.digest

        try:
            live = await self._live_definition(server, upstream_name)
        except mcp_client.UpstreamError as exc:
            live, live_error = None, exc.code
        else:
            live_error = None if live is not None else "upstream.tool_missing"
        live_digest = digest_of(live) if live is not None else None

        orc = PVPOrchestrator(self.db)
        check = await orc.check(org_id, PVPActionRequest(
            agent_id=agent_id, chain_id=chain_id, action_type="tool_call", tool_name=name, input=arguments,
            tool_digest=live_digest))

        refusal = None
        if await enforcement.enforced(self.db, org_id):
            refusal = "MCP gateway: " + enforcement.REFUSAL
        elif live_error:
            refusal = f"MCP gateway: the upstream server could not confirm the tool ({live_error})"
        elif live_digest != pinned:
            refusal = "MCP gateway: the tool's definition changed upstream since it was approved (ASI04)"
        if check.decision != ALLOWED or refusal:
            action = await orc.record_executed(org_id, check, input_data=arguments, output=None,
                                                  duration_ms=None, executed_by=EXECUTOR, refusal=refusal)
            if check.decision == PENDING_APPROVAL and not refusal:
                return _text_result(f"This call needs a human approval and was not executed "
                                    f"(action #{action.id}): {check.reason}")
            return _text_result(f"Refused by Provenza (action #{action.id}): {refusal or check.reason}")

        started = time.monotonic()
        try:
            result = await upstream_for(server).call_tool(upstream_name, arguments, schema)
            output = {k: result[k] for k in ("content", "structuredContent", "isError") if k in result}
        except mcp_client.UpstreamError as exc:
            output = {"upstream_error": exc.code}
        duration = int((time.monotonic() - started) * 1000)

        bad = structure_findings(output, "$.output")
        if bad:
            output = {"withheld": sorted({f.code for f in bad})}
        action = await orc.record_executed(org_id, check, input_data=arguments, output=output,
                                                   duration_ms=duration, executed_by=EXECUTOR)
        if "upstream_error" in output:
            return _text_result(f"The tool could not be reached (action #{action.id}): {output['upstream_error']}")
        if "withheld" in output:
            return _text_result(f"The tool's output was refused by Provenza (action #{action.id}): "
                                f"{', '.join(output['withheld'])}")
        return {"content": output.get("content") or [], **{k: output[k] for k in ("structuredContent", "isError")
                                                           if k in output}}
