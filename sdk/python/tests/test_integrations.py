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
import sys

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

    def test_wait_for_approval(self, agent, server):
        from provenza.integrations.crewai import govern_tool

        tool, ran = self._tool()
        server.verdicts["zendesk.close"] = ["pending_approval", "allowed"]
        server.decisions[1] = ["approved"]
        governed = govern_tool(agent, tool, name="zendesk.close", approval="wait", approval_timeout=5)
        assert json.loads(governed.run(ticket_id=7)) == {"id": 7, "status": "open"}
        assert ran == [7] and [c[2] for c in _checked(server)] == ["pending_approval", "allowed"]


# ---------------------------------------------------------------------------
# a call held for a person (integrations/_approvals.py): approval="wait"
# ---------------------------------------------------------------------------

class TestApprovalWait:
    def _tool(self):
        lc = pytest.importorskip("langchain_core.tools")
        ran = []

        @lc.tool
        def refund(order: str, amount: int) -> str:
            """Refund an order."""
            ran.append((order, amount))
            return f"refunded {amount} on {order}"

        return refund, ran

    def test_approved_runs_once_after_the_decision(self, agent, server):
        from provenza.integrations.langchain import govern_tool

        tool, ran = self._tool()
        server.verdicts["shop.refund"] = ["pending_approval", "allowed"]
        server.decisions[1] = ["approved"]                      # action 1: the held call, recorded first
        governed = govern_tool(agent, tool, name="shop.refund", approval="wait", approval_timeout=5)
        assert governed.invoke({"order": "A-1", "amount": 30}) == "refunded 30 on A-1"
        assert ran == [("A-1", 30)]
        assert [c[2] for c in _checked(server)] == ["pending_approval", "allowed"]
        assert [c[1] for c in _checked(server)] == [{"order": "A-1", "amount": 30}] * 2   # exactly the same call

    def test_denied_is_refused_and_nothing_runs(self, agent, server):
        from provenza.integrations.langchain import govern_tool

        tool, ran = self._tool()
        server.verdicts["shop.refund"] = "pending_approval"
        server.decisions[1] = ["denied"]
        governed = govern_tool(agent, tool, name="shop.refund", approval="wait", approval_timeout=5)
        answer = governed.invoke({"order": "A-1", "amount": 30})
        assert answer.startswith("Refused by Provenza") and "the approval was denied" in answer
        assert ran == [] and len(_checked(server)) == 1          # not asked again

    def test_still_pending_when_the_wait_ends(self, agent, server):
        from provenza import ProvenzaApprovalRequired
        from provenza.integrations import _approvals

        server.verdicts["shop.refund"] = "pending_approval"
        ran = []
        with pytest.raises(ProvenzaApprovalRequired) as err:
            _approvals.call(agent, "shop.refund", {"order": "A-1"}, lambda: ran.append(1), "wait", timeout=0)
        assert err.value.action_id == 1 and ran == [] and len(_checked(server)) == 1

    async def test_async(self, agent, server):
        from provenza.integrations import _approvals

        server.verdicts["shop.refund"] = ["pending_approval", "allowed"]
        server.decisions[1] = ["approved"]

        async def run():
            return "done"

        assert await _approvals.acall(agent, "shop.refund", {"order": "A-1"}, run, "wait", timeout=5) == "done"

    def test_refuse_is_the_default_and_modes_are_checked(self, agent, server):
        from provenza.integrations.langchain import govern_tool

        tool, ran = self._tool()
        server.verdicts["refund"] = "pending_approval"
        answer = govern_tool(agent, tool).invoke({"order": "A-1", "amount": 1})
        assert "pending_approval" in answer and ran == [] and len(_checked(server)) == 1
        with pytest.raises(ValueError):
            govern_tool(agent, tool, approval="later")


# ---------------------------------------------------------------------------
# LangGraph: a held call pauses the graph
# ---------------------------------------------------------------------------

class TestLangGraph:
    def _graph(self, agent, approval="interrupt"):
        pytest.importorskip("langgraph")
        from langchain_core.messages import AIMessage
        from langchain_core.tools import tool
        from langgraph.checkpoint.memory import InMemorySaver
        from langgraph.graph import END, START, MessagesState, StateGraph
        from langgraph.prebuilt import ToolNode

        from provenza.integrations.langgraph import govern_tools

        ran = []

        @tool
        def refund(order: str, amount: int) -> str:
            """Refund an order."""
            ran.append((order, amount))
            return f"refunded {amount} on {order}"

        def model(state: MessagesState):
            # a scripted model: ask for the refund once, then answer with what the tool said
            if state["messages"][-1].type == "tool":
                return {"messages": [AIMessage(content="tool said: " + state["messages"][-1].content)]}
            return {"messages": [AIMessage(content="", tool_calls=[
                {"name": "refund", "args": {"order": "A-1", "amount": 30}, "id": "call_1"}])]}

        g = StateGraph(MessagesState)
        g.add_node("model", model)
        g.add_node("tools", ToolNode(govern_tools(agent, [refund], prefix="shop.", approval=approval)))
        g.add_edge(START, "model")
        g.add_conditional_edges("model", lambda s: "tools" if s["messages"][-1].tool_calls else END)
        g.add_edge("tools", "model")
        return g.compile(checkpointer=InMemorySaver()), ran

    CONFIG = {"configurable": {"thread_id": "order-A-1"}}

    def test_pauses_and_resumes_after_approval(self, agent, server):
        from provenza.integrations.langgraph import approvals, resume_command

        graph, ran = self._graph(agent)
        server.verdicts["shop.refund"] = ["pending_approval", "allowed"]
        server.decisions[1] = ["approved"]
        result = graph.invoke({"messages": [("user", "refund A-1")]}, self.CONFIG)
        [held] = approvals(result)
        assert held.value["tool"] == "shop.refund" and held.value["action_id"] == 1
        assert held.value["arguments"] == {"order": "A-1", "amount": 30}
        assert ran == []                                       # paused: nothing ran
        assert approvals(graph.get_state(self.CONFIG)) == [held]

        command = resume_command(agent, result, timeout=5)
        result = graph.invoke(command, self.CONFIG)
        assert "__interrupt__" not in result
        assert result["messages"][-1].content == "tool said: refunded 30 on A-1"
        assert ran == [("A-1", 30)]
        assert [c[2] for c in _checked(server)] == ["pending_approval", "allowed"]

    def test_denied_reaches_the_model_without_a_second_request(self, agent, server):
        from provenza.integrations.langgraph import resume_command

        graph, ran = self._graph(agent)
        server.verdicts["shop.refund"] = "pending_approval"
        server.decisions[1] = ["denied"]
        result = graph.invoke({"messages": [("user", "refund A-1")]}, self.CONFIG)
        result = graph.invoke(resume_command(agent, result, timeout=5), self.CONFIG)
        assert "the approval was denied" in result["messages"][-1].content
        assert ran == [] and len(_checked(server)) == 1

    def test_undecided_gives_no_command(self, agent, server):
        from provenza.integrations.langgraph import resume_command

        graph, ran = self._graph(agent)
        server.verdicts["shop.refund"] = "pending_approval"
        result = graph.invoke({"messages": [("user", "refund A-1")]}, self.CONFIG)
        assert resume_command(agent, result, timeout=0) is None
        assert resume_command(agent, {"messages": []}) is None   # nothing held

    def test_resumed_before_a_decision_never_runs(self, agent, server):
        graph, ran = self._graph(agent)                        # skips when langgraph is absent
        from langgraph.types import Command

        server.verdicts["shop.refund"] = "pending_approval"
        result = graph.invoke({"messages": [("user", "refund A-1")]}, self.CONFIG)
        result = graph.invoke(Command(resume="go"), self.CONFIG)      # a resume of the app's own
        assert result["messages"][-1].content.startswith("tool said: Refused by Provenza")
        assert ran == []

    def test_wait_mode_in_a_graph(self, agent, server):
        graph, ran = self._graph(agent, approval="wait")
        server.verdicts["shop.refund"] = ["pending_approval", "allowed"]
        server.decisions[1] = ["approved"]
        result = graph.invoke({"messages": [("user", "refund A-1")]}, self.CONFIG)
        assert result["messages"][-1].content == "tool said: refunded 30 on A-1" and ran == [("A-1", 30)]

    def _create_agent(self, agent):
        """LangChain's create_agent (langchain >= 1.0, a LangGraph graph with a
        ToolNode) and a scripted chat model."""
        pytest.importorskip("langchain.agents")
        from langchain.agents import create_agent
        from langchain_core.language_models.chat_models import BaseChatModel
        from langchain_core.messages import AIMessage
        from langchain_core.outputs import ChatGeneration, ChatResult
        from langchain_core.tools import tool
        from langgraph.checkpoint.memory import InMemorySaver

        from provenza.integrations.langgraph import govern_tools

        class Scripted(BaseChatModel):
            def bind_tools(self, tools, **kwargs):
                return self

            @property
            def _llm_type(self) -> str:
                return "scripted"

            def _generate(self, messages, stop=None, run_manager=None, **kwargs):
                if messages[-1].type == "tool":
                    m = AIMessage(content="tool said: " + messages[-1].content)
                else:
                    m = AIMessage(content="", tool_calls=[
                        {"name": "refund", "args": {"order": "A-1", "amount": 30}, "id": "call_1"}])
                return ChatResult(generations=[ChatGeneration(message=m)])

        ran = []

        @tool
        def refund(order: str, amount: int) -> str:
            """Refund an order."""
            ran.append((order, amount))
            return f"refunded {amount} on {order}"

        graph = create_agent(Scripted(), govern_tools(agent, [refund], prefix="shop."), checkpointer=InMemorySaver())
        return graph, ran

    def test_create_agent(self, agent, server):
        from provenza.integrations.langgraph import resume_command

        graph, ran = self._create_agent(agent)
        server.verdicts["shop.refund"] = ["pending_approval", "allowed"]
        server.decisions[1] = ["approved"]
        result = graph.invoke({"messages": [("user", "refund A-1")]}, self.CONFIG)
        assert "__interrupt__" in result and ran == []
        result = graph.invoke(resume_command(agent, result, timeout=5), self.CONFIG)
        assert result["messages"][-1].content == "tool said: refunded 30 on A-1" and ran == [("A-1", 30)]

    @pytest.mark.skipif(sys.version_info < (3, 11), reason="interrupt() in async code needs Python 3.11 (LangGraph)")
    async def test_create_agent_async(self, agent, server):
        from provenza.integrations.langgraph import aresume_command

        graph, ran = self._create_agent(agent)
        server.verdicts["shop.refund"] = ["pending_approval", "allowed"]
        server.decisions[1] = ["approved"]
        result = await graph.ainvoke({"messages": [("user", "refund A-1")]}, self.CONFIG)
        assert "__interrupt__" in result and ran == []
        result = await graph.ainvoke(await aresume_command(agent, result, timeout=5), self.CONFIG)
        assert result["messages"][-1].content == "tool said: refunded 30 on A-1" and ran == [("A-1", 30)]


# ---------------------------------------------------------------------------
# OpenAI Agents SDK
# ---------------------------------------------------------------------------

class TestOpenAIAgents:
    def _setup(self, agent, approval="refuse"):
        agents_sdk = pytest.importorskip("agents")
        from provenza.integrations.openai_agents import gateway_model, govern_tools

        agents_sdk.set_tracing_disabled(True)
        ran, seen = [], []

        @agents_sdk.function_tool
        def refund(order: str, amount: int) -> str:
            """Refund an order."""
            ran.append((order, amount))
            return f"refunded {amount} on {order}"

        def gateway(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            seen.append((str(request.url), request.headers["authorization"], body))
            tool_msgs = [m for m in body["messages"] if m["role"] == "tool"]
            if tool_msgs:
                message = {"role": "assistant", "content": "tool said: " + tool_msgs[-1]["content"]}
            else:
                message = {"role": "assistant", "content": None, "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "refund", "arguments": json.dumps({"order": "A-1", "amount": 30})}}]}
            return httpx.Response(200, json={
                "id": "c1", "object": "chat.completion", "created": 1, "model": body["model"],
                "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

        model = gateway_model(agent, "gpt-4o-mini", http_client=httpx.AsyncClient(transport=httpx.MockTransport(gateway)))
        assistant = agents_sdk.Agent(name="Support", instructions="Refund what is asked.", model=model,
                                     tools=govern_tools(agent, [refund], prefix="shop.", approval=approval))
        return agents_sdk, assistant, ran, seen, refund

    async def test_governed_tool_and_gateway_model(self, agent, server):
        agents_sdk, assistant, ran, seen, refund = self._setup(agent)
        [governed] = assistant.tools
        assert (governed.name, governed.description, governed.params_json_schema) == (
            refund.name, refund.description, refund.params_json_schema)
        assert refund.on_invoke_tool is not governed.on_invoke_tool       # the original is left as it was
        result = await agents_sdk.Runner.run(assistant, "Refund order A-1")
        assert result.final_output == "tool said: refunded 30 on A-1"
        assert ran == [("A-1", 30)]
        assert _checked(server) == [("shop.refund", {"order": "A-1", "amount": 30}, "allowed")]
        assert server.records[0]["output"] == {"result": "refunded 30 on A-1"}
        assert all(url == "https://provenza.test/api/v1/gateway/v1/chat/completions" for url, _, _ in seen)
        assert all(auth == "Bearer pvz_agent_key" for _, auth, _ in seen)

    async def test_refusal_is_the_tool_result(self, agent, server):
        agents_sdk, assistant, ran, _, _ = self._setup(agent)
        server.verdicts["shop.refund"] = "denied"
        result = await agents_sdk.Runner.run(assistant, "Refund order A-1")
        assert result.final_output.startswith("tool said: Refused by Provenza") and ran == []

    async def test_wait_for_approval(self, agent, server):
        agents_sdk, assistant, ran, _, _ = self._setup(agent, approval="wait")
        server.verdicts["shop.refund"] = ["pending_approval", "allowed"]
        server.decisions[1] = ["approved"]
        result = await agents_sdk.Runner.run(assistant, "Refund order A-1")
        assert result.final_output == "tool said: refunded 30 on A-1" and ran == [("A-1", 30)]

    def test_hosted_tools_are_not_passed_through(self, agent):
        agents_sdk = pytest.importorskip("agents")
        from provenza.integrations.openai_agents import govern_tool

        with pytest.raises(TypeError):
            govern_tool(agent, agents_sdk.WebSearchTool())
