# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from provenza.crypto import canonical, content_hash
from provenza.proxy import descriptor

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "testdata" / "proxy-descriptor-vectors.json")
                     .read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: f"{v['method']} {v['path']}")
def test_descriptor_matches_the_proxy(v):
    assert descriptor(v["route"], v["method"], v["path"], query=v["query"], body=v["body"]) == v["descriptor"]
    # bytes and str are the same request
    assert descriptor(v["route"], v["method"], v["path"], query=v["query"].encode(),
                      body=v["body"].encode()) == v["descriptor"]


def test_descriptor_refuses_what_the_proxy_would_not_see():
    with pytest.raises(ValueError):
        descriptor("stripe", "GET", "v1/charges")
    with pytest.raises(ValueError):
        descriptor("stripe", "GET", "/v1/charges?limit=3")


def test_proxy_check_asks_the_server_and_hands_out_the_header(agent, server):
    body = b'{"amount":1000}'
    chk = agent.proxy_check("stripe", "post", "/v1/charges", body=body)
    sent = server.checks[chk.check_id]
    assert (sent["action_type"], sent["tool_name"]) == ("proxy", "proxy.stripe")
    assert sent["input"] == descriptor("stripe", "POST", "/v1/charges", body=body)
    headers = chk.proxy_headers
    assert chk.allowed and headers["X-Provenza-Check-Id"] == chk.check_id
    assert server.records == []      # the proxy records it, not the agent
    # the agent's signed request, which a proxy enforcing the signed policy verifies itself
    raw = headers["X-Provenza-Request"]
    req = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    p = req["payload"]
    assert (p["type"], p["agent_id"], p["tool_name"], p["nonce"]) == \
        ("action.request", agent.agent_id, "proxy.stripe", sent["nonce"])
    assert p["input_sha256"] == content_hash(sent["input"]) and req["signature"] == sent["signature"]
    assert req["public_key"] == agent.identity.keys.public_key
    Ed25519PublicKey.from_public_bytes(base64.b64decode(req["public_key"])).verify(
        base64.b64decode(req["signature"]), canonical(p))


def test_proxy_request_headers_offline(agent, server):
    """While Provenza is unreachable: only the agent's signed request, for a
    proxy that judges it by the signed release alone."""
    body = b'{"amount":1}'
    online = agent.proxy_request_headers("stripe", "POST", "/v1/charges", body=body)
    assert set(online) == {"X-Provenza-Check-Id", "X-Provenza-Request"}
    server.down.add("/agents/actions/check")
    offline = agent.proxy_request_headers("stripe", "POST", "/v1/charges", body=body)
    assert set(offline) == {"X-Provenza-Request"}
    raw = offline["X-Provenza-Request"]
    req = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    p = req["payload"]
    assert (p["action_type"], p["tool_name"], p["chain_id"]) == ("proxy", "proxy.stripe", None)
    assert p["input_sha256"] == content_hash(descriptor("stripe", "POST", "/v1/charges", body=body))
    Ed25519PublicKey.from_public_bytes(base64.b64decode(req["public_key"])).verify(
        base64.b64decode(req["signature"]), canonical(p))
    assert p["nonce"] != json.loads(base64.urlsafe_b64decode(
        online["X-Provenza-Request"] + "=" * (-len(online["X-Provenza-Request"]) % 4)))["payload"]["nonce"]


@pytest.mark.asyncio
async def test_aproxy_request_headers_offline(agent, server):
    server.down.add("/agents/actions/check")
    assert set(await agent.aproxy_request_headers("stripe", "GET", "/v1/charges")) == {"X-Provenza-Request"}


@pytest.mark.asyncio
async def test_aproxy_check(agent, server):
    chk = await agent.aproxy_check("stripe", "GET", "/v1/charges", query="limit=3")
    assert server.checks[chk.check_id]["input"]["query_sha256"] == descriptor(
        "stripe", "GET", "/v1/charges", query="limit=3")["query_sha256"]


def test_http_tools_go_through_the_egress_proxy_when_one_is_set(server, tmp_path):
    """A tool whose credential is sealed to the proxies is called there (/_tools/call),
    with the same signed request the server's gateway takes."""
    import httpx

    from provenza import Agent

    sent, signed = [], []

    def handle(request):
        if request.url.host == "proxy.local":
            sent.append((str(request.url), request.headers.get("x-agent-key"), json.loads(request.content)))
            signed.append((request.headers.get("x-provenza-request"), request.content))
            return httpx.Response(200, json={"decision": "allowed", "action_id": 3, "status": 200, "body": {"ok": 1}})
        return server.handle(request)

    a = Agent("billing-bot", server_url="https://provenza.example", enrollment_token="pvz_enr_" + "x" * 20,
              identity_path=str(tmp_path / "id.json"), transport=httpx.MockTransport(handle),
              async_transport=httpx.MockTransport(handle), egress_proxy="http://proxy.local:8443")
    try:
        out = a.invoke("crm.set_tier", {"id": "c/42"})
        assert out["body"] == {"ok": 1}
        url, key, body = sent[-1]
        assert url == "http://proxy.local:8443/_tools/call" and key == "pvz_agent_key"
        assert (body["tool_name"], body["input"], body["agent_id"]) == ("crm.set_tier", {"id": "c/42"}, a.agent_id)
        assert body["signature"] and body["nonce"]
        # and the HTTP request itself, signed: what a proxy in enforce mode requires on every path
        header, raw = signed[-1]
        request = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
        p = request["payload"]
        assert (p["tool_name"], p["action_type"], p["agent_id"]) == ("proxy._tools", "proxy", a.agent_id)
        assert p["input_sha256"] == content_hash(descriptor("_tools", "POST", "/call", body=raw))
        assert json.loads(raw) == body
        Ed25519PublicKey.from_public_bytes(base64.b64decode(request["public_key"])).verify(
            base64.b64decode(request["signature"]), canonical(p))
    finally:
        a.close()
