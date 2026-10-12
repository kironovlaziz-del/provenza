# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

import json
from pathlib import Path

import pytest

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
    assert chk.allowed and chk.proxy_headers == {"X-Provenza-Check-Id": chk.check_id}
    assert server.records == []      # the proxy records it, not the agent


@pytest.mark.asyncio
async def test_aproxy_check(agent, server):
    chk = await agent.aproxy_check("stripe", "GET", "/v1/charges", query="limit=3")
    assert server.checks[chk.check_id]["input"]["query_sha256"] == descriptor(
        "stripe", "GET", "/v1/charges", query="limit=3")["query_sha256"]
