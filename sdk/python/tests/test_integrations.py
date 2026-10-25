# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The framework integrations, each against its real framework (skipped when
that framework is not installed - CI installs them one environment each,
crewai and autogen-core cannot share one). Governance runs through the
in-memory Provenza of conftest.py, which verifies the record signatures.
"""

import json

import httpx
import pytest

from provenza import ProvenzaDenied


def _checked(server):
    return [(c["tool_name"], c["input"], c["decision"]) for c in server.checks.values()]


# ---------------------------------------------------------------------------
# gateways
# ---------------------------------------------------------------------------

def test_mcp_connection(agent):
    from provenza.integrations.mcp import client_config, connection

    conn = connection(agent)
    assert conn == {"url": "https://provenza.test/api/v1/mcp", "headers": {"Authorization": "Bearer pvz_agent_key"}}
    assert client_config(agent, "corp")["mcpServers"]["corp"]["url"] == conn["url"]


def test_openai_goes_through_the_gateway(agent):
    openai = pytest.importorskip("openai")
    from provenza.integrations.openai import gateway_client, wrap

    seen = []

    def gateway(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={
            "id": "c1", "object": "chat.completion", "created": 1, "model": "gpt-4o-mini",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hi"}}]})

    client = gateway_client(agent, http_client=httpx.Client(transport=httpx.MockTransport(gateway)))
    out = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hello"}])
    assert out.choices[0].message.content == "hi"
    assert str(seen[0].url) == "https://provenza.test/api/v1/gateway/v1/chat/completions"
    assert seen[0].headers["authorization"] == "Bearer pvz_agent_key"   # the agent's key, never a provider key

    original = openai.OpenAI(api_key="sk-provider-key", base_url="https://api.openai.com/v1")
    wrapped = wrap(original, agent)
    assert str(wrapped.base_url).startswith("https://provenza.test/api/v1/gateway/v1")
    assert wrapped.api_key == "pvz_agent_key" and original.api_key == "sk-provider-key"

    chained = gateway_client(agent, chain_id=9, http_client=httpx.Client(transport=httpx.MockTransport(gateway)))
    chained.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hello"}])
    assert seen[-1].headers["x-provenza-chain-id"] == "9"
    assert "x-provenza-chain-id" not in seen[0].headers
    with pytest.raises(ValueError):
        gateway_client(agent, chain_id=0)


# ---------------------------------------------------------------------------
# LangChain
# ---------------------------------------------------------------------------

class TestLangChain:
    def _tools(self):
        lc = pytest.importorskip("langchain_core.tools")
        ran = []

        @lc.tool
        def search(query: str, limit: int = 3) -> str:
            """Search the knowledge base."""
            ran.append(query)
            return f"{limit} results for {query}"

        return search, ran

    def test_same_interface_governed_call(self, agent, server):
        from provenza.integrations.langchain import govern_tool

        search, ran = self._tools()
        governed = govern_tool(agent, search, name="kb.search")
        assert (governed.name, governed.description, governed.args) == (search.name, search.description, search.args)
        assert governed.invoke({"query": "refunds"}) == "3 results for refunds"
        assert ran == ["refunds"]
        assert _checked(server) == [("kb.search", {"query": "refunds", "limit": 3}, "allowed")]
        assert server.records[0]["output"] == {"result": "3 results for refunds"}

    def test_refusal_reaches_the_model_and_nothing_runs(self, agent, server):
        from provenza.integrations.langchain import govern_tools

        search, ran = self._tools()
        server.verdicts["kb.search"] = "denied"
        [governed] = govern_tools(agent, [search], prefix="kb.")
        answer = governed.invoke({"query": "salaries"})
        assert answer.startswith("Refused by Provenza") and ran == []

    async def test_async(self, agent, server):
        from provenza.integrations.langchain import govern_tool

        search, _ = self._tools()
        assert await govern_tool(agent, search).ainvoke({"query": "x", "limit": 1}) == "1 results for x"


# ---------------------------------------------------------------------------
# AutoGen
# ---------------------------------------------------------------------------

class TestAutoGen:
    def _tool(self):
        tools = pytest.importorskip("autogen_core.tools")
        ran = []

        async def lookup(city: str) -> str:
            ran.append(city)
            return f"sunny in {city}"

        return tools.FunctionTool(lookup, description="Weather by city", name="weather"), ran

    async def test_same_schema_governed_call(self, agent, server):
        tool, ran = self._tool()                       # skips when autogen-core is absent
        from autogen_core import CancellationToken

        from provenza.integrations.autogen import govern_tool

        governed = govern_tool(agent, tool, name="weather.lookup")
        assert governed.schema == tool.schema
        assert await governed.run_json({"city": "Tashkent"}, CancellationToken()) == "sunny in Tashkent"
        assert ran == ["Tashkent"] and _checked(server) == [("weather.lookup", {"city": "Tashkent"}, "allowed")]

    async def test_refused(self, agent, server):
        tool, ran = self._tool()
        from autogen_core import CancellationToken

        from provenza.integrations.autogen import govern_tools

        server.verdicts["weather"] = "denied"
        [governed] = govern_tools(agent, [tool])
        with pytest.raises(ProvenzaDenied):
            await governed.run_json({"city": "x"}, CancellationToken())
        assert ran == []


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------

class TestCrewAI:
    def _tool(self):
        crewai_tools = pytest.importorskip("crewai.tools")
        ran = []

        @crewai_tools.tool("Ticket reader")
        def read_ticket(ticket_id: int) -> str:
            """Read one support ticket."""
            ran.append(ticket_id)
            return json.dumps({"id": ticket_id, "status": "open"})

        return read_ticket, ran

    def test_same_interface_governed_call(self, agent, server):
        from provenza.integrations.crewai import govern_tool

        tool, ran = self._tool()
        governed = govern_tool(agent, tool, name="zendesk.read")
        assert governed.name == tool.name and governed.args_schema is tool.args_schema
        assert json.loads(governed.run(ticket_id=7)) == {"id": 7, "status": "open"}
        assert ran == [7] and _checked(server) == [("zendesk.read", {"ticket_id": 7}, "allowed")]

    def test_refused(self, agent, server):
        from provenza.integrations.crewai import govern_tools

        tool, ran = self._tool()
        server.verdicts["zendesk." + tool.name] = "denied"     # prefix + the tool's own name
        [governed] = govern_tools(agent, [tool], prefix="zendesk.")
        with pytest.raises(ProvenzaDenied):
            governed.run(ticket_id=7)
        assert ran == []
