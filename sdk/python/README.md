# Provenza Python SDK

Governed, signed and auditable actions for AI agents.

```bash
pip install provenza
```

```python
from provenza import Agent

agent = Agent("support-bot")   # reads PROVENZA_URL and PROVENZA_TOKEN

@agent.tool(name="zendesk.read")
def open_tickets(status: str = "open") -> list:
    return zendesk.tickets.list(status=status)

open_tickets()   # checked by Provenza, run, recorded and signed
```

## What happens on a call

In **connected** mode (when `PROVENZA_URL` is set):

1. The SDK asks the server whether this call may run. The server checks
   the agent's rights, your organization's policies, the Tool Registry,
   prompt injection in the arguments, behaviour, and the circuit breaker.
2. The tool runs only if the call is allowed. Otherwise:
   - a denied call raises `ProvenzaDenied` (a `PermissionError`);
   - a call that needs a human decision raises `ProvenzaApprovalRequired`.

   In both cases the attempt is recorded.
3. The result is recorded and signed with the agent's own key. Provenza
   seals it into its signed audit log, so you can download a receipt for
   it that is verifiable offline.

The SDK **fails closed**: if the server cannot be reached, the tool does not
run and the SDK raises `ProvenzaUnavailable`. Pass `fail_open=True` to run
anyway and log the call locally as unchecked.

In **standalone** mode (no server), calls run and are written to a local,
signed, hash-chained audit log. You can restrict them with
`allowed_tools=[...]`.

Only hashes of arguments and results are written to the local audit log,
never the content.

## Getting an identity

An admin issues a one-time enrollment token in Provenza (**Agents → New
agent**). The agent's keys are generated on its own machine, and only the
public key goes to the server:

```bash
export PROVENZA_URL=https://provenza.example.com
export PROVENZA_TOKEN=pvz_enr_...      # used once; afterwards the identity file is enough
```

The identity is stored in `~/.config/provenza/agents/<name>.json` (mode
600). The SDK refuses to load it if other users can read it. It is the same
file `tools/provenza_sign.py enroll` writes, so you can enroll with the CLI
and run with the SDK.

To keep the private keys in the OS keychain instead:

```bash
pip install 'provenza[keychain]'
```

```python
Agent("bot", key_store="keychain")
```

For post-quantum hybrid keys (Ed25519 + ML-DSA-65):

```bash
pip install 'provenza[pq]'
```

```python
Agent("bot", hybrid=True)
```

`agent.fingerprint` is the value to give whoever verifies the agent's
signatures.

## More

```python
with agent.chain(chain_id):            # act inside a delegation chain
    open_tickets()

agent.delegate(other_agent_id, "summarize Q3", ["read"], tools=["db.read"], expires_in=600)

chk = agent.check("files.delete", {"path": p})   # ask for something that is not a decorated tool
if chk.allowed:
    delete(p)
    agent.record(chk, {"deleted": True})
```

Async tools work the same way (`async def`). If a call ran but could not be
recorded on the server (the server went down mid-call), the SDK does not
hide the result. It writes a signed **gap** entry to the local audit log and
emits a `ProvenzaWarning`.

## Latency

A governed call costs the SDK's own work plus round-trips to the server.
The SDK's own work was measured against an in-process server (no network)
on 2026-10-11:

| `record_mode` | round-trips before the tool returns | median | p95 |
|---|---|---|---|
| `"sync"` (default) | 2 (check, record) | 0.42 ms | 0.59 ms |
| `"background"` | 1 (check) | 0.15 ms | 0.33 ms |

Add your network round-trip (×2 or ×1) and the server's checks.

With `"sync"`, the record is on the server when the tool returns.

With `"background"`, records are sent from a queue, in order. A failure
becomes a signed gap in the local audit log, the same as in sync mode.
`flush()` / `aflush()` wait for the queue, and `close()` and interpreter
exit drain it. A process that is **killed** loses whatever is still
queued; that is the price of not waiting.

Refusals are always recorded before the exception is raised, so
`ProvenzaDenied.action_id` is known at once.

## Auto-instrumentation

```python
import provenza.auto
provenza.auto.instrument(agent)        # httpx (sync and async) and requests
```

Every **direct** call from this process to an AI provider becomes a
governed action. That covers the OpenAI, Anthropic, Mistral, Cohere and
Gemini SDKs, LangChain's provider clients, or plain HTTP. The provider
hosts come from your organization's AI domain catalog (Shadow AI), and the
**server** decides each call:

| catalog status | result |
|---|---|
| `blocked` | refused; incident `ai_domain_blocked` |
| `allowed` | sent, unless a policy refuses it |
| not classified | sent, unless a policy refuses it; recorded for an admin to classify |

Only the host, method, path (without the query string), and the hash and
size of the body are recorded. The prompt is never recorded.

A refusal comes back as an HTTP answer: 403 with an OpenAI-style error
body and `x-should-retry: false`. Provider SDKs therefore raise their usual
permission error with Provenza's reason and do not retry. With the server
unreachable, nothing is sent (503). Other hosts, and calls to Provenza
itself, are untouched. `provenza.auto.uninstrument()` puts everything back.

## Integrations

Each framework is an optional extra. The SDK never requires one: `crewai`
and `autogen-core` even need conflicting `protobuf` versions.

**Through Provenza's gateways.** The call goes through the server, which
holds the provider credentials, so it is enforced whatever the agent's
code does.

```python
# pip install 'provenza[openai]'
from provenza.integrations.openai import gateway_client, wrap
client = gateway_client(agent)              # an openai.OpenAI pointed at the LLM gateway, with the agent's key
client = wrap(existing_client, agent)       # or a copy of one you already configured

# MCP: no extra needed. Point any MCP client at Provenza instead of at the servers.
from provenza.integrations.mcp import connection, client_config
conn = connection(agent)                    # {"url": ".../api/v1/mcp", "headers": {...}}
```

Through the LLM gateway, the server checks allowed models and limits. PII
is masked and blocked terms are refused. Every model the organization has
routed (OpenAI, Anthropic, Azure, …) is reached through this one
OpenAI-compatible endpoint. Streaming is not supported yet.

**Tool wrappers.** These keep the tool's name, description and argument
schema, so the model sees no difference:

```python
# pip install 'provenza[langchain]'
from provenza.integrations.langchain import govern_tools
tools = govern_tools(agent, [search, read_file])        # a refusal reaches the model as the tool's answer

# pip install 'provenza[autogen]'
from provenza.integrations.autogen import govern_tools
tools = govern_tools(agent, [FunctionTool(lookup, description="...")])

# pip install 'provenza[crewai]'
from provenza.integrations.crewai import govern_tools
researcher = crewai.Agent(role="...", goal="...", tools=govern_tools(agent, [search_tool]))
```

`prefix=` namespaces the names policies see, so `prefix="kb."` turns
`search` into `kb.search`. For anything else, govern a single call with
`agent.call(name, arguments, lambda: ...)` or `await agent.acall(...)`.

## What this is, and what it is not

The SDK runs inside your agent's process. It is the agent's honest record
and cooperative enforcement: code in the same process could call a tool
around it, and could read the agent's keys. Enforcement that does not
depend on the agent's code comes from Provenza's gateways (LLM, MCP, A2A),
which hold the credentials so the agent never has them.

Verify a local audit log with `provenza.audit_log.verify(path, public_key)`.
Verify a server receipt with `tools/provenza_audit.py receipt`.
