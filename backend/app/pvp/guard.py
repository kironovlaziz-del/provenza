# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP Input Guard - what a request must pass before it becomes a PVP message
(docs/pvp/spec.md, section 4).

Cheap checks first, and nothing that costs the server work or another
agent's quota before the caller is known:

  1. body size      BodyLimitMiddleware, on the raw bytes, before anything
                    parses them (Caddy lets 200 MB through to /api/*)
  2. authentication app/api/deps.py (X-Agent-Key or a session)
  3. rate limit     per authenticated principal - the agent's key or the
                    user - never per an id read from the body
  4. structure      depth, node count, string and key sizes, NUL characters
                    (PostgreSQL cannot store U+0000 in JSONB; deep nesting
                    turns hashing into a RecursionError)
  5. identifiers    tool, action type, capability and model names: no
                    control / invisible characters, NFKC-stable, one script
                    ("stripe.chаrge" with a Cyrillic "a" is not the
                    tool a policy names)
  6. PVP schema     app/pvp/model.py (the adapter's _pvp)
  7. signature, policy, injection (ASI01), code shapes (ASI05), behaviour
                    (ASI10): the orchestrator and the services it calls -
                    the guard does not duplicate them

The guard refuses; it never rewrites. A rewritten input no longer matches
the hash the agent signed, so "sanitizing" would only move the problem.
Suspicious-but-valid content is not the guard's call either: the injection
and code-execution guards already hold such actions for a human (ASI09)
in enforce mode.

A refusal of an authenticated request is written to pvp_guard_log: the
body's hash and size and, per finding, a code and a JSON path - never the
content. Rate-limit refusals are not logged row by row: a flood would turn
into a write flood.
"""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import rate_limit
from app.core.config import settings
from app.core.errors import api_error
from app.models.pvp_guard import PVPGuardLog

# --- limits -------------------------------------------------------------------

KiB = 1024
MiB = 1024 * KiB

_P = re.escape(settings.API_V1_STR.rstrip("/"))
# raw body limit per PVP route (POST); tool outputs make record the largest
BODY_LIMITS = [
    (re.compile(_P + r"/agents/actions/check/?$"), 1 * MiB),
    (re.compile(_P + r"/agents/actions/record/?$"), 8 * MiB),
    (re.compile(_P + r"/agents/\d+/delegate/?$"), 64 * KiB),
    (re.compile(_P + r"/mcp/?$"), 1 * MiB),
    (re.compile(_P + r"/a2a-gateway/[a-z0-9-]+/?$"), 8 * MiB),   # messages may carry files
]

MAX_DEPTH = 64
MAX_NODES = 50_000
MAX_STRING = 2_000_000      # characters, one string
MAX_KEY = 1_000             # characters, one object key
MAX_FINDINGS = 20
MAX_PATH = 200
RATE_WINDOW_SECONDS = 60


def body_limit(path: str) -> Optional[int]:
    for rx, limit in BODY_LIMITS:
        if rx.match(path):
            return limit
    return None


# --- 1. body size (ASGI middleware) ---------------------------------------------

def _too_large(limit: int) -> bytes:
    return json.dumps({"detail": {"code": "pvp.body_too_large", "context": {"max_bytes": limit}}}).encode()


class BodyLimitMiddleware:
    """Refuses a PVP request whose body is over its route's limit with 413,
    before any part of the application reads it. A declared Content-Length
    is judged at once; a chunked body is counted while it streams and
    buffered (at most the limit) so the application reads it as usual."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        limit = body_limit(scope["path"])
        if limit is None:
            return await self.app(scope, receive, send)

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > limit:
                    return await self._refuse(send, limit)
            except ValueError:
                return await self._refuse(send, limit, status.HTTP_400_BAD_REQUEST)

        chunks: List[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            size += len(body)
            if size > limit:
                return await self._refuse(send, limit)
            chunks.append(body)
            if not message.get("more_body", False):
                break

        data = b"".join(chunks)
        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": data, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _refuse(send, limit: int, code: int = 413):  # Content Too Large
        body = _too_large(limit)
        await send({"type": "http.response.start", "status": code,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})


# --- 4-5. structure and identifiers (pure) ----------------------------------------

@dataclass(frozen=True)
class Finding:
    code: str
    path: str

    def out(self) -> Dict[str, str]:
        return {"code": self.code, "path": self.path}


_PLAIN_KEY = re.compile(r"^[A-Za-z0-9_-]{1,50}$")


def _at(path: str, key: Any) -> str:
    # a key that is not a plain name could itself be content: shown as "*"
    if isinstance(key, int):
        step = f"[{key}]"
    else:
        step = f".{key}" if _PLAIN_KEY.match(key) else ".*"
    return (path + step)[:MAX_PATH]


def structure_findings(value: Any, path: str = "$") -> List[Finding]:
    """Limits on one JSON value. Iterative and bounded: it stops descending
    below MAX_DEPTH and stops counting after MAX_NODES, so the check itself
    costs at most O(MAX_NODES)."""
    out: List[Finding] = []
    stack = [(value, path, 0)]
    nodes = 0
    while stack and len(out) < MAX_FINDINGS:
        node, where, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            out.append(Finding("input.too_many_nodes", path))
            break
        if isinstance(node, str):
            if len(node) > MAX_STRING:
                out.append(Finding("input.string_too_long", where))
            elif "\x00" in node:
                out.append(Finding("input.nul_character", where))
        elif isinstance(node, (dict, list)):
            if depth >= MAX_DEPTH:
                out.append(Finding("input.too_deep", where))
                continue
            if isinstance(node, dict):
                for k, v in node.items():
                    if len(k) > MAX_KEY:
                        out.append(Finding("input.key_too_long", where))
                    elif "\x00" in k:
                        out.append(Finding("input.nul_character", where))
                    stack.append((v, _at(where, k), depth + 1))
            else:
                stack.extend((v, _at(where, i), depth + 1) for i, v in enumerate(node))
    return out


_INVISIBLE = {"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"}


def _script(ch: str) -> str:
    # the first word of the character's name: LATIN, CYRILLIC, GREEK, CJK, ...
    return unicodedata.name(ch, "UNKNOWN").split(" ", 1)[0]


def identifier_findings(name: Optional[str], path: str) -> List[Finding]:
    """A name a policy will compare against: tool, action type, capability,
    model. It must read as what it is."""
    if not isinstance(name, str) or not name:
        return []
    if any(unicodedata.category(c) in _INVISIBLE for c in name):
        return [Finding("identifier.invisible_character", path)]
    if name != name.strip():
        return [Finding("identifier.surrounding_space", path)]
    if unicodedata.normalize("NFKC", name) != name:
        return [Finding("identifier.not_normalized", path)]
    if len({_script(c) for c in name if c.isalpha()}) > 1:
        return [Finding("identifier.mixed_script", path)]
    return []


def inspect(identifiers: Dict[str, Any], values: Dict[str, Any]) -> List[Finding]:
    """All findings for one request: identifiers (a name or a list of
    names, by field) and free-form values (by field)."""
    out: List[Finding] = []
    for field, ident in identifiers.items():
        names: Iterable = ident if isinstance(ident, list) else [ident]
        for i, name in enumerate(names):
            out += identifier_findings(name, f"$.{field}" if not isinstance(ident, list) else f"$.{field}[{i}]")
    for field, value in values.items():
        out += structure_findings(value, f"$.{field}")
    return out[:MAX_FINDINGS]


# --- the guard --------------------------------------------------------------------

def _principal(request: Request, user) -> str:
    agent = getattr(request.state, "agent", None)
    return f"agent:{agent.id}" if agent is not None else f"user:{user.id}"


async def admit(request: Request, db: AsyncSession, user, *, protocol: str, route: str,
                identifiers: Dict[str, Any], values: Dict[str, Any]) -> None:
    """Steps 3-5 for one authenticated request. Returns when the request may
    become a PVP message; raises 429 (rate) or 422 pvp.input_rejected."""
    try:
        rate_limit.enforce(request, scope="pvp", limit=settings.PVP_RATE_LIMIT_PER_MINUTE,
                           window_seconds=RATE_WINDOW_SECONDS, extra_key=_principal(request, user))
    except HTTPException as exc:
        if exc.status_code != status.HTTP_429_TOO_MANY_REQUESTS:
            raise
        err = api_error(status.HTTP_429_TOO_MANY_REQUESTS, "pvp.rate_limited", retry_after=RATE_WINDOW_SECONDS)
        err.headers = {"Retry-After": str(RATE_WINDOW_SECONDS)}
        raise err

    findings = inspect(identifiers, values)
    if not findings:
        return
    raw = await request.body()
    agent = getattr(request.state, "agent", None)
    db.add(PVPGuardLog(
        org_id=user.org_id, agent_id=agent.id if agent is not None else None, user_id=user.id,
        protocol=protocol, route=route, reason=findings[0].code,
        findings=[f.out() for f in findings],
        body_sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw),
        client_ip=rate_limit._client_ip(request)[:64],
    ))
    await db.commit()
    # the code and where - never the content
    raise api_error(422, "pvp.input_rejected",
                    reason=findings[0].code, findings=[f.out() for f in findings])
