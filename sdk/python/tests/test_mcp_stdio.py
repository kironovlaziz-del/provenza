"""provenza-mcp: the MCP gateway over stdio (src/provenza/mcp_stdio.py)."""

import io
import json

import httpx

from provenza.mcp_stdio import Bridge, META_VERSION


def _bridge(handler):
    seen = []

    def h(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return Bridge("https://pvz.example/api/v1/mcp", "agent-key", transport=httpx.MockTransport(h)), seen


def _run(bridge, *messages) -> list:
    out = io.StringIO()
    bridge.serve(io.StringIO("".join(json.dumps(m) + "\n" for m in messages) + "not json\n"), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_legacy_session_passes_through_with_the_agent_key_and_the_negotiated_version():
    def handler(req):
        body = json.loads(req.content)
        if "id" not in body:
            return httpx.Response(202)
        if body["method"] == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"],
                                             "result": {"protocolVersion": "2025-06-18"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"tools": []}})

    bridge, seen = _bridge(handler)
    out = _run(bridge,
               {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
               {"jsonrpc": "2.0", "method": "notifications/initialized"},
               {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    # a notification gets no answer; the bad line gets a parse error
    assert [m.get("id") for m in out] == [1, 2, None]
    assert out[2]["error"]["code"] == -32700
    assert all(r.headers["authorization"] == "Bearer agent-key" for r in seen)
    assert "mcp-protocol-version" not in seen[0].headers
    assert seen[2].headers["mcp-protocol-version"] == "2025-06-18"


def test_modern_requests_mirror_their_headers_and_non_ascii_names_go_base64():
    bridge, seen = _bridge(lambda req: httpx.Response(
        200, json={"jsonrpc": "2.0", "id": json.loads(req.content)["id"], "result": {}}))
    _run(bridge, {"jsonrpc": "2.0", "id": "a", "method": "tools/call",
                  "params": {"name": "crm.lés", "arguments": {}, "_meta": {META_VERSION: "2026-07-28"}}})
    h = seen[0].headers
    assert h["mcp-protocol-version"] == "2026-07-28" and h["mcp-method"] == "tools/call"
    assert h["mcp-name"].startswith("=?base64?") and h["mcp-name"].endswith("?=")


def test_refusals_and_outages_become_json_rpc_errors():
    bridge, _ = _bridge(lambda req: httpx.Response(401, json={"detail": "auth.invalid_key"}))
    assert _run(bridge, {"jsonrpc": "2.0", "id": 7, "method": "tools/list"})[0]["error"]["code"] == -32001

    def down(req):
        raise httpx.ConnectError("refused")

    bridge, _ = _bridge(down)
    out = _run(bridge, {"jsonrpc": "2.0", "id": 8, "method": "tools/list"},
               {"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert [m["id"] for m in out[:-1]] == [8] and out[0]["error"]["code"] == -32000
