# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
provenza-mcp: Provenza's MCP gateway for clients that start MCP servers as
a local command (stdio) - Claude Desktop, Claude Code, Cursor, Windsurf,
Gemini CLI, VS Code, ...

    {"mcpServers": {"provenza": {
        "command": "uvx", "args": ["provenza-mcp"],
        "env": {"PROVENZA_URL": "https://provenza.example.com",
                "PROVENZA_TOKEN": "pvz_enr_..."}}}}

On the first start the agent enrolls with the one-time token: its keys are
made on this machine and only the public key goes to Provenza
(~/.config/provenza/agents/<name>.json). Afterwards the identity file is
enough and the token can be removed.

Every message from the client is passed to the organization's MCP gateway
(/api/v1/mcp) as this agent: the client sees only the tools an administrator
approved, and every call is checked against the organization's policies and
recorded. Nothing else is written to stdout; diagnostics go to stderr.

Environment: PROVENZA_URL, PROVENZA_TOKEN (first start only),
PROVENZA_AGENT_NAME (default "mcp"), PROVENZA_IDENTITY (identity file path).
"""

import base64
import json
import os
import sys
from typing import Any, Dict, Optional, TextIO

import httpx

from provenza.integrations.mcp import MCP_PATH

META_VERSION = "io.modelcontextprotocol/protocolVersion"


def _log(msg: str) -> None:
    print(f"provenza-mcp: {msg}", file=sys.stderr, flush=True)


def _header_value(value: str) -> str:
    """Mcp-Name carries a tool name; one that is not plain ASCII goes base64 (=?base64?...?=)."""
    try:
        value.encode("ascii")
        if value.isprintable():
            return value
    except UnicodeEncodeError:
        pass
    return "=?base64?" + base64.b64encode(value.encode("utf-8")).decode() + "?="


def _error(rid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


class Bridge:
    """One JSON-RPC message in, at most one out - the gateway is stateless."""

    def __init__(self, url: str, api_key: str, *, transport: Optional[httpx.BaseTransport] = None,
                 timeout: float = 120.0):
        self.http = httpx.Client(timeout=timeout, transport=transport, headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json, text/event-stream",
        })
        self.url = url
        self.version: Optional[str] = None   # negotiated by initialize (legacy revisions)

    def headers_for(self, msg: Dict[str, Any]) -> Dict[str, str]:
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        h = {"Content-Type": "application/json"}
        if isinstance(meta.get(META_VERSION), str):        # modern: the headers mirror the body
            h["MCP-Protocol-Version"] = meta[META_VERSION]
            h["Mcp-Method"] = str(msg.get("method"))
            if msg.get("method") == "tools/call" and isinstance(params.get("name"), str):
                h["Mcp-Name"] = _header_value(params["name"])
        elif self.version and msg.get("method") != "initialize":
            h["MCP-Protocol-Version"] = self.version
        return h

    def handle(self, msg: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(msg, dict):
            return _error(None, -32600, "Invalid Request: one JSON-RPC message per line")
        rid = msg.get("id")
        is_request = "id" in msg and "method" in msg
        if "method" not in msg:
            return None  # a response to a server request: this gateway sends none
        try:
            resp = self.http.post(self.url, content=json.dumps(msg).encode(), headers=self.headers_for(msg))
        except httpx.HTTPError as exc:
            return _error(rid, -32000, f"Provenza is not reachable: {type(exc).__name__}") if is_request else None
        if not is_request:
            return None
        try:
            body = resp.json()
        except ValueError:
            body = None
        if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
            if resp.status_code in (401, 403):
                return _error(rid, -32001, "Provenza refused this agent's key (retired, killed or revoked?)")
            return _error(rid, -32000, f"Provenza answered HTTP {resp.status_code}")
        if msg.get("method") == "initialize" and isinstance(body.get("result"), dict):
            v = body["result"].get("protocolVersion")
            self.version = v if isinstance(v, str) else None
        return body

    def serve(self, stdin: TextIO, stdout: TextIO) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                out: Optional[Dict[str, Any]] = _error(None, -32700, "Parse error")
            else:
                out = self.handle(msg)
            if out is not None:
                stdout.write(json.dumps(out, separators=(",", ":")) + "\n")
                stdout.flush()


def main() -> int:
    url = os.environ.get("PROVENZA_URL", "").rstrip("/")
    if not url:
        _log("set PROVENZA_URL (your Provenza, e.g. https://provenza.example.com) and, on the first start, "
             "PROVENZA_TOKEN (Agents -> New agent)")
        return 2
    from provenza import Agent
    from provenza.errors import ProvenzaError

    try:
        agent = Agent(os.environ.get("PROVENZA_AGENT_NAME") or "mcp", server_url=url)
        creds = agent.credentials()
    except ProvenzaError as exc:
        _log(str(exc))
        return 1
    _log(f"agent {agent.agent_id} ({agent.fingerprint}) -> {creds['server_url']}{MCP_PATH}")
    try:
        Bridge(creds["server_url"] + MCP_PATH, creds["api_key"]).serve(sys.stdin, sys.stdout)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
