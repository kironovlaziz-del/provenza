# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
provenza.auto: direct calls to AI providers become governed egress actions.
The agent talks to the in-memory Provenza (conftest.py); "providers" are
mock transports that count what reached them.
"""

import json

import httpx
import pytest

import provenza.auto as auto

PROMPT = "patient John Smith, diagnosis ..."


class Provider:
    def __init__(self):
        self.hits = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.hits.append(str(request.url))
        return httpx.Response(200, json={"id": "x", "object": "chat.completion", "created": 1, "model": "m",
                                         "choices": [{"index": 0, "finish_reason": "stop",
                                                      "message": {"role": "assistant", "content": "ok"}}]})


@pytest.fixture
def instrumented(agent):
    inst = auto.instrument(agent)
    yield inst
    auto.uninstrument()


def _egress(server):
    return [c for c in server.checks.values() if c["action_type"] == "egress"]


class TestHttpx:
    def test_ai_call_is_checked_sent_and_recorded_without_the_prompt(self, agent, server, instrumented):
        provider = Provider()
        with httpx.Client(transport=httpx.MockTransport(provider.handle)) as c:
            r = c.post("https://api.openai.com/v1/chat/completions?key=abc", json={"prompt": PROMPT})
        assert r.status_code == 200 and len(provider.hits) == 1
        [chk] = _egress(server)
        assert chk["tool_name"] == "egress.api.openai.com"
        assert chk["input"]["path"] == "/v1/chat/completions" and chk["input"]["method"] == "POST"
        assert len(chk["input"]["body_sha256"]) == 64
        assert PROMPT not in json.dumps(server.checks) + json.dumps(server.records)   # nor the query string
        assert "abc" not in json.dumps(chk)
        assert server.records[-1]["output"]["status"] == 200

    def test_other_hosts_are_untouched(self, agent, server, instrumented):
        provider = Provider()
        with httpx.Client(transport=httpx.MockTransport(provider.handle)) as c:
            c.get("https://example.com/")
            c.get("https://evilopenai.com/")                 # not a dot-bounded suffix of openai.com
        assert _egress(server) == [] and len(provider.hits) == 2

    def test_refusal_is_a_403_that_is_not_retried(self, agent, server, instrumented):
        server.verdicts["egress.api.blocked-ai.com"] = "denied"
        provider = Provider()
        with httpx.Client(transport=httpx.MockTransport(provider.handle)) as c:
            r = c.post("https://api.blocked-ai.com/v1/x", content=b"{}")
        assert r.status_code == 403 and r.headers["x-should-retry"] == "false"
        assert r.json()["error"]["code"] == "provenza_denied" and provider.hits == []
        assert server.records[-1]["output"] is None            # the refused attempt is on record

    def test_fail_closed_is_a_503_and_nothing_is_sent(self, agent, server, instrumented):
        server.down.add("/agents/actions/check")
        provider = Provider()
        with httpx.Client(transport=httpx.MockTransport(provider.handle)) as c:
            r = c.post("https://api.openai.com/v1/x", content=b"{}")
        assert r.status_code == 503 and provider.hits == []

    async def test_async(self, agent, server, instrumented):
        provider = Provider()
        async with httpx.AsyncClient(transport=httpx.MockTransport(provider.handle)) as c:
            r = await c.post("https://api.openai.com/v1/x", content=b"{}")
        assert r.status_code == 200 and len(_egress(server)) == 1

    def test_uninstrument_restores(self, agent, server):
        import importlib.util

        auto.instrument(agent)
        # a library that is not installed is skipped (CI installs only the SDK's own dependencies)
        expected = ["httpx"] + (["requests"] if importlib.util.find_spec("requests") else [])
        assert auto.instrumented() == expected
        auto.uninstrument()
        provider = Provider()
        with httpx.Client(transport=httpx.MockTransport(provider.handle)) as c:
            c.get("https://api.openai.com/v1/models")
        assert _egress(server) == [] and auto.instrumented() == []


def test_openai_sdk_sees_a_permission_error_and_does_not_retry(agent, server, instrumented):
    openai = pytest.importorskip("openai")
    server.verdicts["egress.api.openai.com"] = "denied"
    provider = Provider()
    client = openai.OpenAI(api_key="sk-direct", http_client=httpx.Client(transport=httpx.MockTransport(provider.handle)))
    with pytest.raises(openai.PermissionDeniedError, match="Refused by Provenza"):
        client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
    assert provider.hits == [] and len(_egress(server)) == 1    # one check, no retries


def test_requests(agent, server, instrumented):
    requests = pytest.importorskip("requests")
    from requests.adapters import BaseAdapter

    hits = []

    class Adapter(BaseAdapter):
        def send(self, request, **kwargs):
            hits.append(request.url)
            r = requests.Response()
            r.status_code, r._content, r.url, r.request = 200, b"{}", request.url, request
            return r

        def close(self):
            pass

    s = requests.Session()
    s.mount("https://", Adapter())
    assert s.post("https://api.openai.com/v1/x", data=PROMPT).status_code == 200
    server.verdicts["egress.api.blocked-ai.com"] = "denied"
    refused = s.get("https://api.blocked-ai.com/v1/models")
    assert refused.status_code == 403 and refused.json()["error"]["code"] == "provenza_denied"
    assert hits == ["https://api.openai.com/v1/x"]
    assert PROMPT not in json.dumps(server.checks)
