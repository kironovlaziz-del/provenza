# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
MCP: the agent endpoint and its administration (app/pvp/mcp_gateway.py).

POST /api/v1/mcp is a Streamable HTTP MCP server for agents, authenticated
with the agent's own key (X-Agent-Key, or "Authorization: Bearer <agent key>"
for stock MCP clients). It speaks both eras of the protocol:

  modern  2026-07-28: stateless, _meta protocol version on every request,
          mirrored headers validated (HeaderMismatch -32020), server/discover
  legacy  2025-03-26 .. 2025-11-25: initialize -> requests; no session is
          minted (the server is stateless, which those revisions allow)

Responses are application/json. GET and DELETE answer 405 (no standalone
stream, no sessions). An Origin header that is not one of CORS_ORIGINS is
refused with 403 (DNS rebinding).

/api/v1/mcp-servers is the admin side: upstream servers, sync, approval.
"""

import base64
import re
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.config import settings
from app.core.crypto import encrypt_secret
from app.core.database import get_db
from app.core.errors import api_error
from app.core.outbound import validate_url
from app.models.mcp import MCPServer, MCPTool
from app.models.tool_registry import ToolRegistryEntry
from app.models.user import User, UserRole
from app.pvp import guard as pvp_guard
from app.pvp import mcp_client
from app.pvp.mcp_gateway import CHAIN_META, MCPGateway, MCPGatewayError
from app.services.agent_identity import authenticate_agent_request
from app.services.audit_service import AuditService

agent_router = APIRouter()
admin_router = APIRouter()

META_VERSION = "io.modelcontextprotocol/protocolVersion"
SERVER_INFO = {"name": "provenza-mcp-gateway", "title": "Provenza MCP gateway", "version": "1"}
INSTRUCTIONS = ("Tools are served by Provenza. Every call is checked against your organization's policies "
                "and recorded; a refused call returns isError with the reason.")
HEADER_MISMATCH = -32020
UNSUPPORTED_VERSION = -32022


# =============================================================== agent endpoint

async def mcp_agent(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    db: AsyncSession = Depends(get_db),
) -> User:
    key = x_agent_key
    if not key and authorization and authorization.lower().startswith("bearer "):
        key = authorization[7:].strip()
    if not key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="mcp.agent_key_required",
                            headers={"WWW-Authenticate": "Bearer"})
    return await authenticate_agent_request(request, db, key)


def _error(rid: Any, code: int, message: str, data: Any = None, http: int = 200) -> JSONResponse:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    body: Dict[str, Any] = {"jsonrpc": "2.0", "error": err}
    if rid is not None:
        body["id"] = rid
    return JSONResponse(status_code=http, content=body)


def _result(rid: Any, result: dict, modern: bool) -> JSONResponse:
    if modern:
        result = {"resultType": "complete", **result}
    return JSONResponse(content={"jsonrpc": "2.0", "id": rid, "result": result})


def _decode(value: Optional[str]) -> Optional[str]:
    if value and value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return value


def _origin_ok(origin: Optional[str]) -> bool:
    if origin is None:
        return True  # not a browser
    allowed = {o.strip().rstrip("/") for o in settings.CORS_ORIGINS.split(",") if o.strip()}
    return origin.rstrip("/") in allowed


@agent_router.get("")
@agent_router.delete("")
async def mcp_no_stream():
    """No standalone SSE stream and no sessions (2026-07-28)."""
    return Response(status_code=status.HTTP_405_METHOD_NOT_ALLOWED, headers={"Allow": "POST"})


@agent_router.post("")
async def mcp_endpoint(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(mcp_agent)):
    if not _origin_ok(request.headers.get("origin")):
        return _error(None, -32600, "Origin not allowed", http=status.HTTP_403_FORBIDDEN)
    try:
        body = await request.json()
    except ValueError:
        return _error(None, -32700, "Parse error", http=status.HTTP_400_BAD_REQUEST)
    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0" or not isinstance(body.get("method"), str):
        return _error(None, -32600, "Invalid Request: one JSON-RPC 2.0 request or notification per POST",
                      http=status.HTTP_400_BAD_REQUEST)
    method = body["method"]
    if "id" not in body:
        return Response(status_code=status.HTTP_202_ACCEPTED)  # notifications (initialized, cancelled, ...)
    rid = body["id"]
    if isinstance(rid, bool) or not isinstance(rid, (str, int)):
        return _error(None, -32600, "Invalid Request: id must be a string or an integer",
                      http=status.HTTP_400_BAD_REQUEST)
    params = body.get("params", {})
    if not isinstance(params, dict):
        return _error(rid, -32602, "Invalid params")
    meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
    modern = META_VERSION in meta
    header_version = request.headers.get("mcp-protocol-version")
    supported = [mcp_client.MODERN, *mcp_client.LEGACY]

    if modern:
        version = meta[META_VERSION]
        if header_version != version:
            return _error(rid, HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version", http=400)
        if version != mcp_client.MODERN:
            return _error(rid, UNSUPPORTED_VERSION, "Unsupported protocol version",
                          {"supported": supported, "requested": version}, http=400)
        if request.headers.get("mcp-method") != method:
            return _error(rid, HEADER_MISMATCH, "Header mismatch: Mcp-Method", http=400)
        if method == "tools/call" and _decode(request.headers.get("mcp-name")) != params.get("name"):
            return _error(rid, HEADER_MISMATCH, "Header mismatch: Mcp-Name", http=400)
    elif header_version is not None and header_version not in mcp_client.LEGACY:
        return _error(rid, UNSUPPORTED_VERSION, "Unsupported protocol version",
                      {"supported": supported, "requested": header_version}, http=400)

    agent = request.state.agent
    if method == "initialize" and not modern:
        asked = params.get("protocolVersion")
        return _result(rid, {"protocolVersion": asked if asked in mcp_client.LEGACY else mcp_client.LEGACY[0],
                             "capabilities": {"tools": {"listChanged": False}},
                             "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS}, False)
    if method == "ping":
        return _result(rid, {}, modern)
    if method == "server/discover" and modern:
        return _result(rid, {"supportedVersions": supported, "capabilities": {"tools": {}},
                             "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
                             "instructions": INSTRUCTIONS}, True)
    if method not in ("tools/list", "tools/call"):
        return _error(rid, -32601, f"Method not found: {method[:100]}", http=404 if modern else 200)

    name = params.get("name") if method == "tools/call" else None
    arguments = params.get("arguments", {}) if method == "tools/call" else {}
    if method == "tools/call" and (not isinstance(name, str) or not isinstance(arguments, dict)):
        return _error(rid, -32602, "Invalid params: name must be a string and arguments an object")
    try:
        await pvp_guard.admit(request, db, user, protocol="mcp", route=method,
                              identifiers={"tool_name": name} if name else {},
                              values={"arguments": arguments} if name else {})
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": str(exc.detail)}
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            return JSONResponse(status_code=429, headers=exc.headers,
                                content={"jsonrpc": "2.0", "id": rid,
                                         "error": {"code": -32000, "message": "Rate limited",
                                                   "data": detail}})
        return _error(rid, -32602, "Invalid params: refused by the input guard", detail.get("context") or detail)

    gw = MCPGateway(db)
    if method == "tools/list":
        return _result(rid, {"tools": await gw.list_tools(agent)}, modern)

    chain_id = meta.get(CHAIN_META)
    if chain_id is not None and (isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id < 1):
        return _error(rid, -32602, f"Invalid params: _meta['{CHAIN_META}'] must be a positive integer")
    try:
        return _result(rid, await gw.call(agent, name, arguments, chain_id), modern)
    except MCPGatewayError as exc:
        return _error(rid, exc.code, exc.message)
    except HTTPException as exc:
        # refused by the orchestrator before any check existed (attestation, unknown chain, ...)
        return _error(rid, -32000, "Refused by Provenza",
                      exc.detail if isinstance(exc.detail, (str, dict)) else None)


# ==================================================================== admin

_admin = require_role(UserRole.admin)
_RESERVED_HEADERS = {"host", "content-length", "content-type", "transfer-encoding", "connection", "accept",
                     "mcp-protocol-version", "mcp-method", "mcp-name", "mcp-session-id", "x-agent-key"}
_HEADER = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")
Protocol = Literal["auto", "2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]


def _check_header(v: Optional[str]) -> Optional[str]:
    if v is None:
        return v
    if not _HEADER.match(v) or v.lower() in _RESERVED_HEADERS or v.lower().startswith("mcp-param-"):
        raise ValueError("auth_header must be a plain HTTP header name that MCP and HTTP do not reserve")
    return v


def _check_url(v: Optional[str]) -> Optional[str]:
    return None if v is None else validate_url(v)


class MCPServerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,39}$")
    name: str = Field(min_length=1, max_length=255)
    url: str = Field(max_length=500)
    protocol: Protocol = "auto"
    auth_header: str = "Authorization"
    auth_secret: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, v):
        return _check_url(v)

    @field_validator("auth_header")
    @classmethod
    def _header(cls, v):
        return _check_header(v)


class MCPServerUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    url: Optional[str] = Field(default=None, max_length=500)
    protocol: Optional[Protocol] = None
    auth_header: Optional[str] = None
    auth_secret: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    clear_secret: bool = False
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=120)
    enabled: Optional[bool] = None

    @field_validator("url")
    @classmethod
    def _url(cls, v):
        return _check_url(v)

    @field_validator("auth_header")
    @classmethod
    def _header(cls, v):
        return _check_header(v)


class MCPServerOut(BaseModel):
    id: int
    slug: str
    name: str
    url: str
    protocol: str
    detected_version: Optional[str]
    auth_header: str
    has_secret: bool          # the secret itself is never returned
    enabled: bool
    timeout_seconds: int
    server_info: Optional[Dict[str, Any]]
    last_synced_at: Optional[datetime]
    last_error: Optional[str]
    created_at: datetime


class MCPToolOut(BaseModel):
    id: int
    name: str
    exposed_name: str
    title: Optional[str]
    description: Optional[str]
    digest: str
    registry_entry_id: Optional[int]
    status: str               # the Tool Registry entry's status
    pinned_digest: Optional[str]
    served: bool              # shown to agents: approved and the synced definition is the pinned one
    removed_at: Optional[datetime]


def _server_out(s: MCPServer) -> MCPServerOut:
    return MCPServerOut(
        id=s.id, slug=s.slug, name=s.name, url=s.url, protocol=s.protocol, detected_version=s.detected_version,
        auth_header=s.auth_header, has_secret=bool(s.auth_secret_encrypted), enabled=s.enabled,
        timeout_seconds=s.timeout_seconds, server_info=s.server_info, last_synced_at=s.last_synced_at,
        last_error=s.last_error, created_at=s.created_at)


async def _get_server(db: AsyncSession, org_id: int, server_id: int) -> MCPServer:
    s = (await db.execute(select(MCPServer).where(MCPServer.id == server_id, MCPServer.org_id == org_id)
                          .execution_options(populate_existing=True))).scalar_one_or_none()
    if s is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "mcp.server_not_found")
    return s


async def _get_tool(db: AsyncSession, server: MCPServer, tool_id: int) -> MCPTool:
    t = (await db.execute(select(MCPTool).where(MCPTool.id == tool_id, MCPTool.server_id == server.id))
         ).scalar_one_or_none()
    if t is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "mcp.tool_not_found")
    return t


def _forget(server_id: int) -> None:
    """Drop cached sessions / live definitions after a server changed."""
    from app.pvp import mcp_gateway

    mcp_client._sessions.pop(server_id, None)
    mcp_gateway._live.pop(server_id, None)


@admin_router.get("", response_model=List[MCPServerOut])
async def list_servers(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    rows = (await db.execute(select(MCPServer).where(MCPServer.org_id == user.org_id)
                             .order_by(MCPServer.slug))).scalars()
    return [_server_out(s) for s in rows]


@admin_router.post("", response_model=MCPServerOut)
async def create_server(data: MCPServerIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    server = MCPServer(org_id=org_id, slug=data.slug, name=data.name, url=data.url, protocol=data.protocol,
                       auth_header=data.auth_header, timeout_seconds=data.timeout_seconds, enabled=data.enabled,
                       auth_secret_encrypted=encrypt_secret(data.auth_secret, org_id) if data.auth_secret else None,
                       created_by=user_id)
    db.add(server)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise api_error(status.HTTP_409_CONFLICT, "mcp.slug_taken", slug=data.slug)
    await AuditService(db).log(org_id, user_id, "mcp_server", server.id, "created",
                               {"slug": data.slug, "url": data.url, "has_secret": bool(data.auth_secret)})
    return _server_out(await _get_server(db, org_id, server.id))


@admin_router.patch("/{server_id}", response_model=MCPServerOut)
async def update_server(server_id: int, data: MCPServerUpdate, db: AsyncSession = Depends(get_db),
                        user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    server = await _get_server(db, org_id, server_id)
    changes = data.model_dump(exclude_unset=True, exclude={"auth_secret", "clear_secret"})
    for key, value in changes.items():
        if value is not None:
            setattr(server, key, value)
    if data.auth_secret:
        server.auth_secret_encrypted = encrypt_secret(data.auth_secret, org_id)
    elif data.clear_secret:
        server.auth_secret_encrypted = None
    if "url" in changes or "protocol" in changes:
        server.detected_version = None  # detect again: it may be another server now
    await db.commit()
    _forget(server_id)
    await AuditService(db).log(org_id, user_id, "mcp_server", server_id, "updated",
                               {"fields": sorted(changes), "secret": "set" if data.auth_secret
                                else "cleared" if data.clear_secret else "unchanged"})
    return _server_out(await _get_server(db, org_id, server_id))


@admin_router.delete("/{server_id}")
async def delete_server(server_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    server = await _get_server(db, org_id, server_id)
    slug = server.slug
    await db.delete(server)
    await db.commit()
    _forget(server_id)
    await AuditService(db).log(org_id, user_id, "mcp_server", server_id, "deleted", {"slug": slug})
    return {"deleted": True}


@admin_router.post("/{server_id}/sync")
async def sync_server(server_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    server = await _get_server(db, org_id, server_id)
    _forget(server_id)
    try:
        report = await MCPGateway(db).sync(org_id, server)
    except mcp_client.UpstreamError as exc:
        raise api_error(status.HTTP_502_BAD_GATEWAY, "mcp.upstream_failed", reason=exc.code)
    await AuditService(db).log(org_id, user_id, "mcp_server", server_id, "synced",
                               {k: len(v) for k, v in report.items()})
    return report


@admin_router.get("/{server_id}/tools", response_model=List[MCPToolOut])
async def list_server_tools(server_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    server = await _get_server(db, user.org_id, server_id)
    rows = (await db.execute(
        select(MCPTool, ToolRegistryEntry).outerjoin(ToolRegistryEntry, ToolRegistryEntry.id == MCPTool.registry_entry_id)
        .where(MCPTool.server_id == server.id).order_by(MCPTool.name))).all()
    return [MCPToolOut(
        id=t.id, name=t.name, exposed_name=t.exposed_name, title=(t.definition or {}).get("title"),
        description=(t.definition or {}).get("description"), digest=t.digest, registry_entry_id=t.registry_entry_id,
        status=e.status if e else "unregistered", pinned_digest=e.pinned_digest if e else None,
        served=bool(e and e.status == "approved" and e.pinned_digest == t.digest and t.removed_at is None
                    and server.enabled),
        removed_at=t.removed_at) for t, e in rows]


@admin_router.post("/{server_id}/tools/{tool_id}/approve")
async def approve_tool(server_id: int, tool_id: int, db: AsyncSession = Depends(get_db),
                       user: User = Depends(_admin)):
    """Approve exactly the definition seen at the last sync (its digest
    becomes the pin). What an approver reads is what agents will be shown."""
    org_id, user_id = user.org_id, user.id
    server = await _get_server(db, org_id, server_id)
    tool = await _get_tool(db, server, tool_id)
    if tool.removed_at is not None:
        raise api_error(status.HTTP_409_CONFLICT, "mcp.tool_removed")
    exposed_name, digest = tool.exposed_name, tool.digest
    entry = await MCPGateway(db).approve(org_id, tool, user_id)
    await AuditService(db).log(org_id, user_id, "tool_registry", entry.id, "approved",
                               {"pattern": exposed_name, "pinned_digest": digest, "via": "mcp_gateway"})
    return {"approved": exposed_name, "pinned_digest": digest}


@admin_router.post("/{server_id}/tools/{tool_id}/block")
async def block_tool(server_id: int, tool_id: int, db: AsyncSession = Depends(get_db),
                     user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    server = await _get_server(db, org_id, server_id)
    tool = await _get_tool(db, server, tool_id)
    entry = (await db.execute(select(ToolRegistryEntry).where(ToolRegistryEntry.id == tool.registry_entry_id))
             ).scalar_one_or_none() if tool.registry_entry_id else None
    if entry is None:
        raise api_error(status.HTTP_409_CONFLICT, "mcp.tool_not_registered")
    entry.status = "blocked"
    exposed_name, entry_id = tool.exposed_name, entry.id
    await db.commit()
    await AuditService(db).log(org_id, user_id, "tool_registry", entry_id, "blocked",
                               {"pattern": exposed_name, "via": "mcp_gateway"})
    return {"blocked": exposed_name}
