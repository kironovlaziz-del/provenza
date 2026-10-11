# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
MCP client for upstream servers - the executor side of the MCP gateway.

Streamable HTTP only: a stdio server would mean running someone's process on
the Provenza host. Both protocol eras are spoken, because upstream servers in
the field are mostly still on the initialize-based revisions:

  modern  (2026-07-28)           stateless; every request carries
                                 _meta["io.modelcontextprotocol/protocolVersion"]
                                 and the mirrored headers MCP-Protocol-Version,
                                 Mcp-Method, Mcp-Name, Mcp-Param-*
  legacy  (2025-03-26..2025-11-25) initialize -> notifications/initialized ->
                                 requests, with Mcp-Session-Id when the server
                                 assigns one (cached, re-initialized on 404)

"auto" detects the era the way the specification describes: a modern
server/discover first; a 400 without a recognized modern error, a 404 or a
405 means a legacy server.

Every connection goes through core/outbound.guarded_async_client: the
resolved address is checked when connecting (no private ranges, no DNS
rebinding), redirects are not followed. Responses are read up to
MAX_RESPONSE_BYTES - a hostile server cannot exhaust memory - and either
JSON or an SSE stream, from which the response to our id is taken.
"""

import base64
import itertools
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from app.pvp.upstream_http import UpstreamError, jsonrpc, parse_body  # noqa: F401 (re-exported)

MODERN = "2026-07-28"
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26")
SUPPORTED = (MODERN,) + LEGACY
CLIENT_INFO = {"name": "provenza-mcp-gateway", "version": "1"}

MAX_TOOLS = 1000
MAX_PAGES = 20
SESSION_TTL_SECONDS = 300
# JSON-RPC errors only a modern server returns (UnsupportedProtocolVersion, HeaderMismatch)
MODERN_ERRORS = {-32022, -32020}

_ids = itertools.count(1)
# server id -> (session id or None, negotiated version, expires at)
_sessions: Dict[int, Tuple[Optional[str], str, float]] = {}


# --- header encoding (2026-07-28, Value Encoding) ---------------------------------

_SAFE = re.compile(r"^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$")


def header_value(value: Any) -> str:
    if isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    if _SAFE.match(text) and not (text.startswith("=?base64?") and text.endswith("?=")):
        return text
    return "=?base64?" + base64.b64encode(text.encode()).decode() + "?="


_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
# what the specification says tool names SHOULD be; the gateway exposes only such names
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def param_headers(input_schema: Any, arguments: Dict[str, Any]) -> Dict[str, str]:
    """Mcp-Param-* for properties marked x-mcp-header, reached only through
    "properties" keys from the schema root (the specification's rule)."""
    out: Dict[str, str] = {}

    def walk(schema: Any, value: Any) -> None:
        if not isinstance(schema, dict) or not isinstance(value, dict):
            return
        for key, sub in (schema.get("properties") or {}).items():
            if not isinstance(sub, dict) or key not in value:
                continue
            name = sub.get("x-mcp-header")
            if isinstance(name, str) and _TOKEN.match(name) and value[key] is not None \
                    and isinstance(value[key], (str, int, bool)):
                out[f"Mcp-Param-{name}"] = header_value(value[key])
            walk(sub, value[key])

    walk(input_schema, arguments)
    return out


class MCPUpstream:
    def __init__(self, server_id: int, url: str, *, protocol: str = "auto", auth_header: Optional[str] = None,
                 auth_value: Optional[str] = None, timeout: float = 30.0):
        self.server_id, self.url, self.protocol = server_id, url, protocol
        self.auth = {auth_header: auth_value} if auth_header and auth_value else {}
        self.timeout = timeout
        self.version: Optional[str] = protocol if protocol in SUPPORTED else None
        self.server_info: Optional[dict] = None

    # ------------------------------------------------------------- transport

    async def _post(self, body: dict, headers: Dict[str, str]) -> Tuple[int, Dict[str, str], Optional[dict]]:
        return await jsonrpc(self.url, body, headers={**self.auth, **headers}, timeout=self.timeout)

    # ---------------------------------------------------------------- modern

    def _modern_body(self, method: str, params: Optional[dict] = None) -> dict:
        p = dict(params or {})
        p["_meta"] = {"io.modelcontextprotocol/protocolVersion": MODERN,
                      "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
                      "io.modelcontextprotocol/clientCapabilities": {}}
        return {"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": p}

    async def _modern(self, method: str, params: Optional[dict] = None,
                      extra_headers: Optional[Dict[str, str]] = None) -> Tuple[int, Optional[dict]]:
        headers = {"MCP-Protocol-Version": MODERN, "Mcp-Method": method, **(extra_headers or {})}
        if params and "name" in params and method in ("tools/call", "prompts/get"):
            headers["Mcp-Name"] = header_value(params["name"])
        status, _, msg = await self._post(self._modern_body(method, params), headers)
        return status, msg

    # ---------------------------------------------------------------- legacy

    async def _legacy_session(self, fresh: bool = False) -> Tuple[Optional[str], str]:
        cached = _sessions.get(self.server_id)
        if cached and not fresh and cached[2] > time.monotonic():
            return cached[0], cached[1]
        asked = self.version if self.version in LEGACY else LEGACY[0]
        body = {"jsonrpc": "2.0", "id": next(_ids), "method": "initialize",
                "params": {"protocolVersion": asked, "capabilities": {}, "clientInfo": CLIENT_INFO}}
        status, headers, msg = await self._post(body, {})
        if status != 200 or not msg or "result" not in msg:
            raise UpstreamError("upstream.initialize_failed", f"HTTP {status}")
        version = (msg["result"] or {}).get("protocolVersion")
        if version not in LEGACY:
            raise UpstreamError("upstream.unsupported_version", f"server answered {version!r}")
        session = headers.get("mcp-session-id")
        h = {"MCP-Protocol-Version": version} if version != "2025-03-26" else {}
        if session:
            h["Mcp-Session-Id"] = session
        await self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, h)
        _sessions[self.server_id] = (session, version, time.monotonic() + SESSION_TTL_SECONDS)
        self.server_info = (msg["result"] or {}).get("serverInfo")
        return session, version

    async def _legacy(self, method: str, params: Optional[dict] = None) -> Tuple[int, Optional[dict]]:
        for attempt in (0, 1):
            session, version = await self._legacy_session(fresh=attempt == 1)
            h = {"MCP-Protocol-Version": version} if version != "2025-03-26" else {}
            if session:
                h["Mcp-Session-Id"] = session
            body = {"jsonrpc": "2.0", "id": next(_ids), "method": method}
            if params is not None:
                body["params"] = params
            status, _, msg = await self._post(body, h)
            if status == 404 and session and attempt == 0:
                continue  # the server dropped the session: initialize again, once
            return status, msg
        return status, msg  # pragma: no cover

    # ------------------------------------------------------------------ API

    async def detect(self) -> str:
        """The protocol version to use with this server (and its serverInfo,
        kept for display only - it is self-reported)."""
        self.server_info = None
        if self.protocol in LEGACY:
            await self._legacy_session(fresh=True)
            self.version = _sessions[self.server_id][1]
            return self.version
        if self.protocol in ("auto", MODERN):
            status, msg = await self._modern("server/discover")
            if status == 200 and msg and "result" in msg:
                result = msg["result"] or {}
                if MODERN in (result.get("supportedVersions") or [MODERN]):
                    self.server_info = (result.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo")
                    self.version = MODERN
                    return MODERN
            err = (msg or {}).get("error") or {}
            if err.get("code") in MODERN_ERRORS:
                supported = set((err.get("data") or {}).get("supported") or [])
                legacy = [v for v in LEGACY if v in supported]
                if MODERN not in supported and not legacy:
                    raise UpstreamError("upstream.unsupported_version", f"server supports {sorted(supported)}")
                if MODERN not in supported:
                    self.protocol = legacy[0]
                    return await self.detect()
                raise UpstreamError("upstream.refused", err.get("message") or "")
            if self.protocol == MODERN:
                raise UpstreamError("upstream.not_modern", f"HTTP {status}")
        await self._legacy_session(fresh=True)
        self.version = _sessions[self.server_id][1]
        return self.version

    async def _request(self, method: str, params: Optional[dict] = None,
                       extra_headers: Optional[Dict[str, str]] = None) -> dict:
        if self.version is None:
            await self.detect()
        if self.version == MODERN:
            status, msg = await self._modern(method, params, extra_headers)
        else:
            status, msg = await self._legacy(method, params)
        if msg is None:
            raise UpstreamError("upstream.bad_response", f"HTTP {status}, no JSON-RPC response")
        if "error" in msg:
            err = msg["error"] or {}
            raise UpstreamError("upstream.error", f"{err.get('code')}: {str(err.get('message'))[:200]}")
        result = msg.get("result")
        if not isinstance(result, dict):
            raise UpstreamError("upstream.bad_response", "result is not an object")
        return result

    async def list_tools(self) -> List[dict]:
        tools: List[dict] = []
        cursor = None
        for _ in range(MAX_PAGES):
            result = await self._request("tools/list", {"cursor": cursor} if cursor else {})
            page = result.get("tools")
            if not isinstance(page, list):
                raise UpstreamError("upstream.bad_response", "tools is not a list")
            tools += [t for t in page if isinstance(t, dict)]
            if len(tools) > MAX_TOOLS:
                raise UpstreamError("upstream.too_many_tools", f"more than {MAX_TOOLS}")
            cursor = result.get("nextCursor")
            if not cursor:
                return tools
        raise UpstreamError("upstream.too_many_pages")

    async def call_tool(self, name: str, arguments: Dict[str, Any], input_schema: Any = None) -> dict:
        return await self._request("tools/call", {"name": name, "arguments": arguments},
                                   extra_headers=param_headers(input_schema, arguments))
