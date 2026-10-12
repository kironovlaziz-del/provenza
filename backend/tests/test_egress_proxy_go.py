# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The egress proxy (proxy/, Go) against THIS server, end to end: the real
binary, the real endpoints, a fake upstream. Both modes:

  mediated  the agent sends its key; the proxy checks, redeems, forwards with
            the server-held credential and completes;
  SDK       the Python SDK's proxy_check, then the proxy redeems that check.

The server is reached over real HTTP through a small bridge to the ASGI app,
so the test keeps its one database transaction. Needs the go command;
a proxy that does not build is a failure, never a skip.
"""

import asyncio
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.models.agent_action import AgentAction
from app.models.egress_proxy import EgressRoute
from tests.conftest import auth_headers

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from provenza.proxy import descriptor  # noqa: E402

SECRET = "Bearer sk_live_go_" + "y" * 16


@pytest.fixture(scope="module")
def proxy_binary(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("needs the go command")
    binary = tmp_path_factory.mktemp("proxy") / "provenza-proxy"
    build = subprocess.run(["go", "build", "-o", str(binary), "."], cwd=ROOT / "proxy", capture_output=True,
                           text=True, timeout=600)
    assert build.returncode == 0, f"the proxy does not build: {build.stderr[-500:]}"
    return binary


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _http_server(handle):
    """A minimal HTTP/1.1 server in this event loop: handle(method, target, headers, body) -> (status, headers, body)."""
    async def serve(reader, writer):
        try:
            line = (await reader.readline()).decode()
            method, target, _ = line.split(" ", 2)
            headers = {}
            while (h := (await reader.readline()).decode().rstrip("\r\n")):
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
            size = int(next((v for k, v in headers.items() if k.lower() == "content-length"), "0"))
            body = await reader.readexactly(size) if size else b""
            status, out_headers, out = await handle(method, target, headers, body)
            head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(out)}\r\nConnection: close\r\n"
            head += "".join(f"{k}: {v}\r\n" for k, v in out_headers.items())
            writer.write(head.encode() + b"\r\n" + out)
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    return server, f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"


@pytest.mark.asyncio
async def test_the_go_proxy_against_this_server(client, admin_token, db_session, tmp_path, proxy_binary):
    seen = []

    async def upstream(method, target, headers, body):
        seen.append((method, target, headers, body))
        return 201, {"Content-Type": "application/json"}, b'{"id":"ch_1"}'

    async def bridge(method, target, headers, body):   # real HTTP -> this test's app and transaction
        keep = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length", "connection")}
        r = await client.request(method, target, headers=keep, content=body)
        return r.status_code, {"Content-Type": r.headers.get("content-type", "application/json")}, r.content

    up_server, up_url = await _http_server(upstream)
    api_server, api_url = await _http_server(bridge)

    r = await client.post("/api/v1/egress/routes", json={
        "slug": "stripe", "name": "Stripe", "upstream_url": "https://api.stripe.com", "methods": ["GET", "POST"],
        "path_prefixes": ["/v1/charges"], "credential_source": "server", "secret": SECRET},
        headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    route = await db_session.get(EgressRoute, r.json()["id"])
    route.upstream_url = up_url        # the API refuses loopback upstreams (SSRF); the fake one is local
    await db_session.flush()
    proxy = (await client.post("/api/v1/egress/proxies", json={"name": "go"}, headers=auth_headers(admin_token))).json()
    agent = (await client.post("/api/v1/agents/register", json={
        "name": "go-proxy-bot", "agent_type": "custom", "capabilities": ["pay"], "allowed_tools": ["proxy.stripe"],
        "allowed_models": [], "max_delegation_depth": 2}, headers=auth_headers(admin_token))).json()

    port = _free_port()
    cfg = tmp_path / "proxy.json"
    cfg.write_text(json.dumps({"server_url": api_url, "listen": f"127.0.0.1:{port}"}))
    proc = await asyncio.create_subprocess_exec(str(proxy_binary), "-config", str(cfg),
                                                env={**os.environ, "PROVENZA_PROXY_KEY": proxy["key"]},
                                                stderr=asyncio.subprocess.PIPE)
    try:
        base = f"http://127.0.0.1:{port}"
        async with httpx.AsyncClient(base_url=base, timeout=30) as agent_http:
            for _ in range(100):           # until it has the route table and listens
                try:
                    await agent_http.get("/")
                    break
                except httpx.TransportError:
                    assert proc.returncode is None, (await proc.stderr.read()).decode()
                    await asyncio.sleep(0.1)

            # mediated: the agent's own key, the server-held credential upstream
            body = b'{"amount":1000,"currency":"usd"}'
            resp = await agent_http.post("/stripe/v1/charges", content=body, headers={
                "X-Agent-Key": agent["api_key"], "Authorization": "Bearer agent-own"})
            assert resp.status_code == 201 and resp.content == b'{"id":"ch_1"}', resp.text
            method, target, headers, sent = seen[-1]
            assert (method, target, sent, headers.get("Authorization")) == ("POST", "/v1/charges", body, SECRET)
            assert "X-Agent-Key" not in headers

            # outside the route: refused by the proxy itself, nothing leaves
            resp = await agent_http.delete("/stripe/v1/charges", headers={"X-Agent-Key": agent["api_key"]})
            assert resp.status_code == 405 and len(seen) == 1

            # SDK mode: the Python SDK's descriptor is exactly what the Go proxy redeems
            desc = descriptor("stripe", "GET", "/v1/charges/ch_1", query="expand%5B%5D=customer")
            chk = (await client.post("/api/v1/agents/actions/check", json={
                "agent_id": agent["id"], "action_type": "proxy", "tool_name": "proxy.stripe", "input": desc},
                headers={"X-Agent-Key": agent["api_key"]})).json()
            assert chk["decision"] == "allowed", chk
            resp = await agent_http.get("/stripe/v1/charges/ch_1?expand%5B%5D=customer",
                                        headers={"X-Provenza-Check-Id": chk["check_id"]})
            assert resp.status_code == 201, resp.text
            assert seen[-1][1] == "/v1/charges/ch_1?expand%5B%5D=customer"
            # a check spent is spent
            resp = await agent_http.get("/stripe/v1/charges/ch_1?expand%5B%5D=customer",
                                        headers={"X-Provenza-Check-Id": chk["check_id"]})
            assert resp.status_code == 403 and len(seen) == 2
    finally:
        proc.terminate()
        await proc.wait()
        up_server.close()
        api_server.close()

    actions = (await db_session.execute(select(AgentAction).where(
        AgentAction.agent_id == agent["id"]).order_by(AgentAction.id))).scalars().all()
    assert [(a.policy_check_result, a.executed_by) for a in actions] == [
        ("allowed", "egress_proxy"), ("allowed", "egress_proxy")]
    assert actions[0].output_data == {"status": 201, "response_sha256": hashlib.sha256(b'{"id":"ch_1"}').hexdigest(),
                                      "response_bytes": 13}
    assert actions[1].input_data == desc
