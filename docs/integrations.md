# Agent frameworks

Provenza governs the agents you build with LangChain, LangGraph, the OpenAI
Agents SDK, CrewAI and AutoGen. Your agent keeps its framework, its tools
and its code. You wrap the tools in one line, and every tool call is:

1. **checked** by Provenza before it runs: the agent's rights, the policy
   hierarchy, the Tool Registry, limits, quarantine and the kill switch;
2. **run only if allowed**: a refused call never reaches the tool, and the
   model gets the refusal as the tool's answer;
3. **recorded**, signed with the agent's own key, in the audit log.

A call that policy holds for a person waits for an approval in the Inbox.

All of this is in the Python SDK (`pip install provenza`). Each framework
is an optional extra.

| Framework | Install | Module |
|---|---|---|
| LangChain | `pip install 'provenza[langchain]'` | `provenza.integrations.langchain` |
| LangGraph (incl. LangChain's `create_agent`) | `pip install 'provenza[langgraph]'` | `provenza.integrations.langgraph` |
| OpenAI Agents SDK | `pip install 'provenza[openai-agents]'` | `provenza.integrations.openai_agents` |
| CrewAI | `pip install 'provenza[crewai]'` | `provenza.integrations.crewai` |
| AutoGen (`autogen-core`) | `pip install 'provenza[autogen]'` | `provenza.integrations.autogen` |
| Any OpenAI-compatible client | `pip install 'provenza[openai]'` | `provenza.integrations.openai` |
| Any MCP client | (no extra) | `provenza.integrations.mcp` |

CrewAI and AutoGen need conflicting `protobuf` versions, so install them in
separate environments.

## 1. Give the agent an identity

In Provenza, open **AI agents → Connect an agent → More options → the full
registration form** (in the full console: **Register agent**). In
**Allowed tools**, list the names your code will give its tools (see
[Tool names](#tool-names)), then press **Issue enrollment token** and copy
the token, `pvz_enr_…`. The two-step **Connect an agent** itself offers only
the tools of Provenza's gateways (MCP and HTTP tools); the tools in your
agent's own code are named on the form.

Where the agent runs:

```bash
pip install 'provenza[pq,langgraph]'           # pq: the hybrid keys the token asks for by default
export PROVENZA_URL=https://provenza.example.com
export PROVENZA_TOKEN=pvz_enr_...              # used once; afterwards the identity file is enough
```

```python
from provenza import Agent

agent = Agent("support-bot")
```

On the first start, the agent makes its keys on that machine, proves it
holds them and enrolls. Only the public keys reach the server. The identity
is kept in `~/.config/provenza/agents/support-bot.json` (readable by its
owner only). To keep the private keys in the OS keychain, see the
[SDK README](../sdk/python/README.md#getting-an-identity).

## 2. Wrap the tools

### LangChain

```python
from langchain_core.tools import tool
from provenza.integrations.langchain import govern_tools

@tool
def refund(order: str, amount: int) -> str:
    """Refund an order."""
    ...

tools = govern_tools(agent, [refund], prefix="shop.")     # give these to your agent instead
```

Each governed tool keeps its name, description and argument schema, so the
model sees no difference. A refusal comes back as the tool's answer
(`Refused by Provenza: …`, through LangChain's `ToolException`): the run
goes on and the model can adapt.

### LangGraph

The tools of a LangGraph graph (a `ToolNode`, or LangChain's
`create_agent`, which builds one) are wrapped the same way. The difference
is what happens when a call waits for a person: **the graph pauses**. Its
state is kept by the checkpointer for as long as the decision takes; no
thread is blocked.

```python
from langchain.agents import create_agent
from langgraph.checkpoint.memory import InMemorySaver
from provenza.integrations.langgraph import govern_tools, resume_command

graph = create_agent(model, govern_tools(agent, [refund, lookup], prefix="shop."),
                     checkpointer=InMemorySaver())
config = {"configurable": {"thread_id": "order-1042"}}

result = graph.invoke({"messages": [("user", "Refund order 1042")]}, config)
while "__interrupt__" in result:                   # a call waits for a person
    command = resume_command(agent, result)        # waits up to 10 minutes for the decision
    if command is None:
        break                                      # still undecided: resume later, from any process
    result = graph.invoke(command, config)
```

When the graph is resumed:

- **approved**: the tool runs again. Provenza lets exactly that call
  through, once — same agent, tool and arguments;
- **denied** or **expired**: the model is told so, and nothing ran.

A graph needs a checkpointer to be paused. For production, use a durable
one (Postgres, SQLite, Redis) instead of `InMemorySaver`.

`resume_command` notes the decision in the process that calls it. If the
graph is resumed elsewhere, or with a `Command` of your own, an unapproved
call still never runs: the repeat is checked again, and if it is still held
it is refused, and its new request waits in the Inbox. So resume after the
decision. `approvals(result)` lists the held calls (tool, arguments,
`action_id`). `agent.approval(action_id)` tells where one stands.

`aresume_command` is the same for async code. An async graph needs
Python 3.11 or newer to be paused: that is LangGraph's own requirement.

### OpenAI Agents SDK

```python
from agents import Agent as OpenAIAgent, Runner, function_tool, set_tracing_disabled
from provenza.integrations.openai_agents import gateway_model, govern_tools

@function_tool
def refund(order: str, amount: int) -> str:
    """Refund an order."""
    ...

assistant = OpenAIAgent(
    name="Support",
    instructions="Refund what the customer asks for, within policy.",
    model=gateway_model(agent, "gpt-4o-mini"),      # the model calls go through Provenza
    tools=govern_tools(agent, [refund], prefix="shop."),
)
result = await Runner.run(assistant, "Refund order 1042")
```

- **Tools.** `govern_tools` keeps every setting of a function tool: its
  name, description, schema, guardrails, `needs_approval` and timeouts.
  Only the invocation changes. A refusal is the tool's result.
- **Hosted tools.** Web search, file search and computer use run on
  OpenAI's side, not in your process. They cannot be governed here, so
  `govern_tools` refuses them with a `TypeError` instead of passing them
  through ungoverned.
- **Model.** `gateway_model` sends the model calls through Provenza's LLM
  gateway, with the agent's own key. Allowed models and providers, policies
  and limits are decided by the server, and the provider key never reaches
  the agent.
  - The gateway speaks Chat Completions and does not stream: use
    `Runner.run` or `run_sync`, not `run_streamed`.
  - The Agents SDK exports traces to OpenAI with `OPENAI_API_KEY`. Turn that
    off (`set_tracing_disabled(True)`) or point it elsewhere if that key
    should not be used.
- **MCP servers.** Connect the Agents SDK to Provenza's MCP gateway (see
  [Through the gateways](#through-the-gateways)). The tools are then
  governed on the server.

### CrewAI

```python
from crewai import Agent as CrewAgent
from provenza.integrations.crewai import govern_tools

researcher = CrewAgent(role="Support", goal="...", backstory="...",
                       tools=govern_tools(agent, [read_ticket, close_ticket], prefix="zendesk."))
```

A refused call raises `ProvenzaDenied` inside the tool. CrewAI reports the
failure to the model, and nothing ran.

### AutoGen

```python
from autogen_core.tools import FunctionTool
from provenza.integrations.autogen import govern_tools

tools = govern_tools(agent, [FunctionTool(lookup, description="Look up an order")], prefix="shop.")
```

The same JSON schema reaches the model. A refused call raises
`ProvenzaDenied` inside the tool, and AutoGen reports it as a failed tool
call.

### Anything else

Govern a single call with `agent.call(name, arguments, lambda: ...)`, or
`await agent.acall(...)` for a coroutine. Every integration ends there.

## 3. Approve the tools once

A tool Provenza has not seen before is added to the **Tool Registry** on its
first call. With the registry enforcing - the default - that call is refused (`… is not approved in the Tool
Registry (ASI04); it was added for review`). An administrator approves it
once: open **Tool Registry** (search with **Ctrl K**, or **Rules** in the
full console). From then on, its calls are decided by the agent's rights
and the policies. This keeps a tool that appeared in the code, or changed
its name, from running before someone has looked at it.

## 4. Calls that wait for a person

Policy can hold a call until someone approves it, for example a refund over
a limit or an e-mail outside the company. The approver sees it in the Inbox,
with the exact arguments, and signs the decision with a passkey. Every
wrapper takes `approval=`:

| `approval=` | What the call does |
|---|---|
| `"refuse"` (default; LangGraph: `"interrupt"`) | Refused like any other call: the model is told it waits for approval. |
| `"wait"` | Waits until a person decides (`approval_timeout=`, 10 minutes by default). Approved: the same call is made again and runs once. Denied or expired: refused. |
| `"interrupt"` (LangGraph only) | The graph pauses, and is resumed after the decision ([LangGraph](#langgraph)). |

An approval is never a free pass. The repeated call is checked by the
server like the first one. Only an approval signed for exactly this agent,
chain, tool and arguments lets it through, and only once, within an hour.
A later stop, quarantine or tripped breaker still wins.

## Tool names

Policies, the agent's rights and the audit log see the **governed name**.
That is the tool's own name, with `prefix=` in front if you give one:
`prefix="shop."` turns `refund` into `shop.refund`. The agent may call only
the tools in its rights. You list them on the registration form, and you can
change them later on the agent's page. A name the agent has no right to is
refused, and recorded.

## Through the gateways

The wrappers run inside the agent's process. They are the agent's honest
record and cooperative enforcement, but code in that process could still
call a tool around them. For enforcement that does not depend on the
agent's code, send its calls **through** Provenza:

- **The LLM gateway.** `provenza.integrations.openai.gateway_client(agent)`
  is an `openai.OpenAI` client pointed at Provenza. It reaches every model
  the organization routed (OpenAI, Anthropic, Azure, …) through one
  OpenAI-compatible endpoint. `gateway_model` is the same for the OpenAI
  Agents SDK.
- **The MCP gateway.** `provenza.integrations.mcp.connection(agent)` gives
  the URL and headers for any MCP client. The client sees only the tools an
  administrator approved, and Provenza holds the servers' credentials.
- **The egress proxy and the sensor.** They keep the agent's machine from
  reaching the internet around Provenza
  ([egress-lockdown.md](egress-lockdown.md)).

Wrappers and gateways combine. For example: tools governed in the process,
the model through the LLM gateway, and the machine behind the egress proxy.
