# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
HTTP tools (app/pvp/http_tools.py).

  agents (X-Agent-Key, and a signed request for calls)
    GET  /http-tools/available     the tools this agent may call, with input schemas
    POST /http-tools/call          check -> call -> record, in one operation
  admins
    GET/POST /http-tools, PATCH/DELETE /http-tools/{id}
                                   the address, method, schema and credential (write-only)
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.crypto import encrypt_secret
from app.core.database import get_db
from app.core.errors import api_error
from app.core.outbound import validate_url
from app.models.http_tool import HttpTool
from app.models.mcp import MCPTool
from app.models.user import User, UserRole
from app.pvp import guard as pvp_guard
from app.pvp.http_tools import METHODS, HttpToolGateway, placeholders
from app.pvp.model import PVPActionRequest
from app.services.agent_identity import authenticate_agent_request
from app.services.audit_service import AuditService

router = APIRouter()
_admin = require_role(UserRole.admin)
_RESERVED = {"host", "content-length", "content-type", "transfer-encoding", "connection", "accept",
             "user-agent", "x-agent-key", "provenza-permit"}
NAME = r"^[a-z0-9][a-z0-9_.-]{0,99}$"
Method = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


# =============================================================== agents

async def http_tool_agent(request: Request, x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
                          db: AsyncSession = Depends(get_db)) -> User:
    if not x_agent_key:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "http_tool.agent_key_required")
    return await authenticate_agent_request(request, db, x_agent_key)


class CallIn(BaseModel):
    """The agent's signed action.request for the tool (as /agents/actions/check)."""
    model_config = ConfigDict(extra="forbid")
    agent_id: int
    action_type: Literal["tool_call"] = "tool_call"
    tool_name: str = Field(max_length=100)
    input: Dict[str, Any] = Field(default_factory=dict)
    chain_id: Optional[int] = None
    nonce: str = Field(min_length=16, max_length=128)
    issued_at: int
    signature: str = Field(max_length=200)
    pq_signature: Optional[str] = Field(default=None, max_length=8000)


@router.get("/available")
async def available(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(http_tool_agent)):
    return {"tools": await HttpToolGateway(db).available(request.state.agent)}


@router.post("/call")
async def call(data: CallIn, request: Request, db: AsyncSession = Depends(get_db),
               user: User = Depends(http_tool_agent)):
    agent = request.state.agent
    if data.agent_id != agent.id:
        raise api_error(status.HTTP_403_FORBIDDEN, "http_tool.not_this_agent")
    await pvp_guard.admit(request, db, user, protocol="rest", route="http_tool.call",
                          identifiers={"tool_name": data.tool_name}, values={"input": data.input})
    try:
        req = PVPActionRequest(agent_id=data.agent_id, chain_id=data.chain_id, action_type="tool_call",
                               tool_name=data.tool_name, input=data.input, nonce=data.nonce,
                               issued_at=data.issued_at, signature=data.signature, pq_signature=data.pq_signature)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)[:500])
    return await HttpToolGateway(db).call(agent, req)


# =============================================================== admins

def _header(v: Optional[str]) -> Optional[str]:
    if v is not None and (not v or len(v) > 100 or v.lower() in _RESERVED
                          or not all(c.isalnum() or c in "!#$%&'*+.^_`|~-" for c in v)):
        raise ValueError("auth_header must be a plain HTTP header name that HTTP and Provenza do not reserve")
    return v


def _url(v: Optional[str]) -> Optional[str]:
    if v is None:
        return v
    url = validate_url(v)
    if "#" in url:
        raise ValueError("the URL must not have a fragment")
    return url


def _schema(v: Optional[dict]) -> Optional[dict]:
    if v is not None and v.get("type", "object") != "object":
        raise ValueError("input_schema must describe an object (the arguments)")
    return v


class HttpToolIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=NAME)
    description: Optional[str] = Field(default=None, max_length=4000)
    method: Method
    url: str = Field(max_length=500)
    input_schema: Optional[Dict[str, Any]] = None
    auth_header: str = "Authorization"
    auth_secret: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    timeout_seconds: int = Field(default=30, ge=1, le=120)
    max_response_bytes: int = Field(default=1024 * 1024, ge=1024, le=8 * 1024 * 1024)
    send_permit: bool = True
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _check_url(cls, v):
        return _url(v)

    @field_validator("auth_header")
    @classmethod
    def _check_header(cls, v):
        return _header(v)

    @field_validator("input_schema")
    @classmethod
    def _check_schema(cls, v):
        return _schema(v)


class HttpToolUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: Optional[str] = Field(default=None, max_length=4000)
    method: Optional[Method] = None
    url: Optional[str] = Field(default=None, max_length=500)
    input_schema: Optional[Dict[str, Any]] = None
    auth_header: Optional[str] = None
    auth_secret: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    clear_secret: bool = False
    timeout_seconds: Optional[int] = Field(default=None, ge=1, le=120)
    max_response_bytes: Optional[int] = Field(default=None, ge=1024, le=8 * 1024 * 1024)
    send_permit: Optional[bool] = None
    enabled: Optional[bool] = None

    @field_validator("url")
    @classmethod
    def _check_url(cls, v):
        return _url(v)

    @field_validator("auth_header")
    @classmethod
    def _check_header(cls, v):
        return _header(v)

    @field_validator("input_schema")
    @classmethod
    def _check_schema(cls, v):
        return _schema(v)


class HttpToolOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    method: str
    url: str
    input_schema: Optional[Dict[str, Any]]
    auth_header: str
    has_secret: bool          # the secret itself is never returned
    timeout_seconds: int
    max_response_bytes: int
    send_permit: bool
    enabled: bool
    digest: str
    registry_entry_id: Optional[int]
    created_at: datetime
    updated_at: Optional[datetime]


def _out(t: HttpTool) -> HttpToolOut:
    return HttpToolOut(id=t.id, name=t.name, description=t.description, method=t.method, url=t.url,
                       input_schema=t.input_schema, auth_header=t.auth_header, has_secret=bool(t.auth_secret_encrypted),
                       timeout_seconds=t.timeout_seconds, max_response_bytes=t.max_response_bytes,
                       send_permit=t.send_permit, enabled=t.enabled, digest=t.digest,
                       registry_entry_id=t.registry_entry_id, created_at=t.created_at, updated_at=t.updated_at)


def _placeholders_declared(url: str, schema: Optional[dict]) -> None:
    props = (schema or {}).get("properties") or {}
    missing = [p for p in placeholders(url) if schema is not None and p not in props]
    if missing:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "http_tool.placeholder_undeclared",
                        names=", ".join(missing))


async def _get(db: AsyncSession, org_id: int, tool_id: int) -> HttpTool:
    t = (await db.execute(select(HttpTool).where(HttpTool.id == tool_id, HttpTool.org_id == org_id)
                          .execution_options(populate_existing=True))).scalar_one_or_none()
    if t is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "http_tool.not_found")
    return t


@router.get("", response_model=List[HttpToolOut])
async def list_tools(db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    rows = (await db.execute(select(HttpTool).where(HttpTool.org_id == user.org_id).order_by(HttpTool.name))).scalars()
    return [_out(t) for t in rows]


@router.post("", response_model=HttpToolOut)
async def create_tool(data: HttpToolIn, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    _placeholders_declared(data.url, data.input_schema)
    clash = (await db.execute(select(MCPTool.id).where(MCPTool.org_id == org_id, MCPTool.exposed_name == data.name,
                                                       MCPTool.removed_at.is_(None)))).first()
    if clash:
        raise api_error(status.HTTP_409_CONFLICT, "http_tool.name_taken", name=data.name)
    tool = HttpTool(org_id=org_id, name=data.name, description=data.description, method=data.method, url=data.url,
                    input_schema=data.input_schema, auth_header=data.auth_header,
                    auth_secret_encrypted=encrypt_secret(data.auth_secret, org_id) if data.auth_secret else None,
                    timeout_seconds=data.timeout_seconds, max_response_bytes=data.max_response_bytes,
                    send_permit=data.send_permit, enabled=data.enabled, digest="", created_by=user_id)
    try:
        async with db.begin_nested():   # a taken name undoes only this insert
            db.add(tool)
            await db.flush()
    except IntegrityError:
        raise api_error(status.HTTP_409_CONFLICT, "http_tool.name_taken", name=data.name)
    await HttpToolGateway(db).pin(tool, user_id)
    tool_id = tool.id
    await db.commit()
    await AuditService(db).log(org_id, user_id, "http_tool", tool_id, "created",
                               {"name": data.name, "method": data.method, "url": data.url,
                                "has_secret": bool(data.auth_secret)})
    return _out(await _get(db, org_id, tool_id))


@router.patch("/{tool_id}", response_model=HttpToolOut)
async def update_tool(tool_id: int, data: HttpToolUpdate, db: AsyncSession = Depends(get_db),
                      user: User = Depends(_admin)):
    org_id, user_id = user.org_id, user.id
    tool = await _get(db, org_id, tool_id)
    changes = data.model_dump(exclude_unset=True, exclude={"auth_secret", "clear_secret"})
    for key, value in changes.items():
        if value is not None or key == "input_schema":
            setattr(tool, key, value)
    _placeholders_declared(tool.url, tool.input_schema)
    if data.auth_secret:
        tool.auth_secret_encrypted = encrypt_secret(data.auth_secret, org_id)
    elif data.clear_secret:
        tool.auth_secret_encrypted = None
    before = tool.digest
    await HttpToolGateway(db).pin(tool, user_id)
    after = tool.digest
    await db.commit()
    await AuditService(db).log(org_id, user_id, "http_tool", tool_id, "updated",
                               {"fields": sorted(changes), "secret": "set" if data.auth_secret
                                else "cleared" if data.clear_secret else "unchanged",
                                "definition_changed": before != after})
    return _out(await _get(db, org_id, tool_id))


@router.delete("/{tool_id}")
async def disable_tool(tool_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(_admin)):
    """Disabled, not deleted: recorded actions keep referring to it."""
    org_id, user_id = user.org_id, user.id
    tool = await _get(db, org_id, tool_id)
    tool.enabled = False
    name = tool.name
    await db.commit()
    await AuditService(db).log(org_id, user_id, "http_tool", tool_id, "disabled", {"name": name})
    return {"disabled": True}
