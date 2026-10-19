# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
HTTP tool gateway - an HTTP API as a tool the agent can only reach through
Provenza.

    agent ──signed request──► POST /http-tools/call ──► PVP check ──► the API
                                                           │      (address and key
                         record (executed_by="http_gateway") ◄┘     held here)

  credentials   the address and the credential are registered by an admin and
                stored here (the secret encrypted); the agent sends the tool
                name and arguments, never sees either
  one operation check -> call -> record happen together, here: there is no
                window in which an agent holds an allowed check and decides
                not to report what it did. Denied, pending and refused calls
                are recorded too
  identity      the agent signs the request like /agents/actions/check
                (nonce, issued_at, signature): a stolen API key alone calls
                nothing
  definition    method, URL, input schema and description are pinned in the
                Tool Registry when the admin saves them; the check reports
                the digest computed here
  arguments     checked against the tool's input schema (top level: required,
                types, additionalProperties: false) before anything is sent;
                path placeholders ({id}) take one URL-encoded segment
  the call      SSRF-guarded client (core/outbound.py): no redirects, no
                private addresses unless the operator allows them; the
                response is read up to max_response_bytes
  the tool too  for body methods the signed permit of the check goes along
                (Provenza-Permit), so an API behind provenza.permit accepts
                calls made through Provenza only
  the output    recorded; oversized or malformed structures are withheld;
                instructions aimed at the agent (ASI01) are withheld in
                enforce mode
"""

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_secret
from app.core.errors import api_error
from app.core.outbound import error_detail, guarded_async_client
from app.models.agent import Agent
from app.models.http_tool import HttpTool
from app.models.tool_registry import ToolRegistryEntry
from app.pvp import permits
from app.pvp.guard import structure_findings
from app.pvp.model import ALLOWED, PENDING_APPROVAL, PVPActionRequest
from app.pvp.orchestrator import PVPOrchestrator
from app.services.supply_chain import manifest_digest

EXECUTOR = "http_gateway"
BODY_METHODS = ("POST", "PUT", "PATCH")
METHODS = ("GET", "DELETE", *BODY_METHODS)
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}")
_JSON_TYPES = {"string": (str,), "integer": (int,), "number": (int, float), "boolean": (bool,),
               "object": (dict,), "array": (list,), "null": (type(None),)}


def definition(tool: HttpTool) -> Dict[str, Any]:
    """What is pinned: everything that decides what a call does."""
    return {"name": tool.name, "method": tool.method, "url": tool.url, "input_schema": tool.input_schema,
            "description": tool.description}


def placeholders(url: str) -> List[str]:
    return PLACEHOLDER.findall(url.split("?", 1)[0])


def _type_ok(value: Any, expected: Any) -> bool:
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        kinds = _JSON_TYPES.get(name)
        if kinds is None:
            return True   # a type this check does not know: not refused here
        if isinstance(value, bool) and name in ("integer", "number"):
            continue
        if isinstance(value, kinds):
            return True
    return False


def argument_problems(schema: Optional[dict], arguments: Dict[str, Any], url: str) -> List[str]:
    """The top level of the input schema, and the path placeholders."""
    problems = []
    if isinstance(schema, dict):
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for name in schema.get("required") or []:
            if name not in arguments:
                problems.append(f"missing argument '{name}'")
        if schema.get("additionalProperties") is False:
            problems += [f"unexpected argument '{k}'" for k in arguments if k not in props]
        for name, sub in props.items():
            if name in arguments and isinstance(sub, dict) and "type" in sub and not _type_ok(arguments[name], sub["type"]):
                problems.append(f"argument '{name}' is not of type {sub['type']}")
            if name in arguments and isinstance(sub, dict) and isinstance(sub.get("enum"), list) \
                    and arguments[name] not in sub["enum"]:
                problems.append(f"argument '{name}' is not one of the allowed values")
    for name in placeholders(url):
        value = arguments.get(name)
        if isinstance(value, bool) or not isinstance(value, (str, int)) or str(value) in ("", ".", ".."):
            problems.append(f"path argument '{name}' must be a non-empty string or an integer")
    return problems


def build_request(tool: HttpTool, arguments: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]], Optional[bytes]]:
    """(url, query params, JSON body). Path placeholders take one encoded
    segment each; a body method sends all the arguments as the JSON body (the
    input the permit is bound to); GET / DELETE send the others as the query."""
    used = set(placeholders(tool.url))
    url = PLACEHOLDER.sub(lambda m: quote(str(arguments[m.group(1)]), safe="") if m.group(1) in used else m.group(0),
                          tool.url)
    if tool.method in BODY_METHODS:
        return url, None, json.dumps(arguments, ensure_ascii=False, allow_nan=False).encode("utf-8")
    query = {}
    for k, v in arguments.items():
        if k in used:
            continue
        if isinstance(v, bool):
            query[k] = "true" if v else "false"
        elif isinstance(v, (str, int, float)):
            query[k] = v
        elif isinstance(v, list) and all(isinstance(i, (str, int, float)) and not isinstance(i, bool) for i in v):
            query[k] = v
        else:
            raise ValueError(f"argument '{k}' cannot go in a query string")
    return url, query, None


async def _send(tool: HttpTool, url: str, query: Optional[dict], body: Optional[bytes],
                permit: Optional[str]) -> Dict[str, Any]:
    headers = {"Accept": "application/json", "User-Agent": "provenza-http-gateway/1"}
    if body is not None:
        headers["Content-Type"] = "application/json"
        if permit and tool.send_permit:
            headers[permits.HEADER] = permit
    if tool.auth_secret_encrypted:
        headers[tool.auth_header] = decrypt_secret(tool.auth_secret_encrypted)
    limit = tool.max_response_bytes
    try:
        async with guarded_async_client(timeout=float(tool.timeout_seconds)) as client:
            async with client.stream(tool.method, url, params=query, content=body, headers=headers) as resp:
                chunks, size = [], 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > limit:
                        return {"status": resp.status_code, "withheld": ["response_too_large"]}
                    chunks.append(chunk)
                raw = b"".join(chunks)
                status_code, ctype = resp.status_code, resp.headers.get("content-type", "")
                if 300 <= status_code < 400:
                    return {"status": status_code, "upstream_error": "redirects are not followed"}
                if status_code >= 400:   # the JSON error message only, never the raw page
                    return {"status": status_code,
                            "upstream_error": error_detail(httpx.Response(status_code, content=raw))}
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        return {"upstream_error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    if not raw:
        return {"status": status_code, "body": None}
    if "json" in ctype:
        try:
            return {"status": status_code, "body": json.loads(raw)}
        except ValueError:
            return {"status": status_code, "withheld": ["invalid_json"]}
    try:
        return {"status": status_code, "body": {"text": raw.decode("utf-8")}}
    except UnicodeDecodeError:
        return {"status": status_code, "withheld": ["binary_response"]}


class HttpToolGateway:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def tool(self, org_id: int, name: str) -> HttpTool:
        t = (await self.db.execute(select(HttpTool).where(HttpTool.org_id == org_id, HttpTool.name == name,
                                                          HttpTool.enabled.is_(True)))).scalar_one_or_none()
        if t is None:
            raise api_error(status.HTTP_404_NOT_FOUND, "http_tool.not_found", name=name[:100])
        return t

    async def pin(self, tool: HttpTool, user_id: int) -> None:
        """The admin's definition is the approved one: pin its digest in the
        Tool Registry (creating or re-approving the entry). The caller commits."""
        from datetime import datetime, timezone

        tool.digest = manifest_digest(definition(tool))
        now = datetime.now(timezone.utc)
        entry = (await self.db.execute(select(ToolRegistryEntry).where(
            ToolRegistryEntry.org_id == tool.org_id, ToolRegistryEntry.pattern == tool.name))).scalar_one_or_none()
        if entry is None:
            entry = ToolRegistryEntry(org_id=tool.org_id, pattern=tool.name, kind="tool", discovered=False,
                                      seen_count=0, first_seen_at=now)
            self.db.add(entry)
        entry.display_name = tool.name
        entry.source = f"http:{tool.method} {tool.url}"[:500]
        entry.pinned_digest, entry.status = tool.digest, "approved"
        entry.approved_by, entry.approved_at, entry.drift_details = user_id, now, None
        entry.notes = "HTTP tool called through Provenza; its definition is pinned when an admin saves it"
        await self.db.flush()
        tool.registry_entry_id = entry.id

    async def available(self, agent: Agent) -> List[Dict[str, Any]]:
        """The HTTP tools this agent holds the right to, as an agent framework
        describes tools: name, description, input schema."""
        from app.services.agent_rights import own_rights

        allowed = set(own_rights(agent).tools)
        rows = (await self.db.execute(select(HttpTool).where(HttpTool.org_id == agent.org_id,
                                                             HttpTool.enabled.is_(True))
                                      .order_by(HttpTool.name))).scalars()
        return [{"name": t.name, "description": t.description or "", "method": t.method,
                 "input_schema": t.input_schema or {"type": "object"}} for t in rows if t.name in allowed]

    async def call(self, agent: Agent, req: PVPActionRequest) -> Dict[str, Any]:
        org_id = agent.org_id
        orc = PVPOrchestrator(self.db)
        tool = await self.tool(org_id, req.tool_name)
        await orc.verify_signed_request(org_id, agent, req)
        arguments = req.input
        check = await orc.check(org_id, req.model_copy(update={
            "action_type": "tool_call", "tool_digest": tool.digest, "signature": None, "pq_signature": None,
            "nonce": None, "issued_at": None}))

        refusal = None
        if manifest_digest(definition(tool)) != tool.digest:
            refusal = "HTTP tool gateway: the tool's definition differs from the one pinned (ASI04)"
        problems = argument_problems(tool.input_schema, arguments, tool.url)
        if problems and not refusal:
            refusal = "HTTP tool gateway: arguments refused: " + "; ".join(problems[:5])
        built = None
        if not refusal:
            try:
                built = build_request(tool, arguments)
            except ValueError as exc:
                refusal = f"HTTP tool gateway: arguments refused: {exc}"
        if check.decision != ALLOWED or refusal:
            action = await orc.record_executed(org_id, check, input_data=arguments, output=None,
                                                  duration_ms=None, executed_by=EXECUTOR, refusal=refusal)
            decision = "pending_approval" if check.decision == PENDING_APPROVAL and not refusal else "denied"
            return {"decision": decision, "reason": refusal or check.reason, "action_id": action.id,
                    "incident_type": None if refusal else check.incident_type}

        started = time.monotonic()
        output = await _send(tool, *built, check.permit)
        duration = int((time.monotonic() - started) * 1000)
        if structure_findings(output, "$.output"):
            output = {"status": output.get("status"),
                      "withheld": sorted({f.code for f in structure_findings(output, "$.output")})}
        action = await orc.record_executed(org_id, check, input_data=arguments, output=output,
                                                   duration_ms=duration, executed_by=EXECUTOR)
        out: Dict[str, Any] = {"decision": "allowed", "reason": check.reason, "action_id": action.id,
                               "status": output.get("status")}
        if "upstream_error" in output:
            out["error"] = output["upstream_error"]
        elif "withheld" in output:
            out["withheld"] = output["withheld"]
        else:
            out["body"] = output.get("body")
        return out

