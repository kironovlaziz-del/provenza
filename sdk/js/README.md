# Provenza JS/TS SDK

Governed, signed and auditable actions for AI agents in Node.js.

```bash
npm install provenza       # Node >= 20.19
```

```ts
import { Agent } from "provenza";

const agent = await Agent.create({ name: "support-bot" });   // reads PROVENZA_URL and PROVENZA_TOKEN

const openTickets = agent.tool("zendesk.read", async ({ status }: { status: string }) =>
  zendesk.tickets.list({ status }));

await openTickets({ status: "open" });   // checked by Provenza, run, recorded and signed
```

It behaves the same as the [Python SDK](../python/README.md), and speaks
the same bytes: an identity file, a signature or a local audit log made by
one is accepted by the other and by the server. The repository's tests
check this against the real server.

## What happens on a call

In **connected** mode (when `PROVENZA_URL` is set):

1. The server checks the call: the agent's rights, policies, the Tool
   Registry, injection, behaviour, and the breaker.
2. The tool runs only if the call is allowed. Otherwise:
   - a denied call rejects with `ProvenzaDenied`;
   - a call that needs a human decision rejects with `ProvenzaApprovalRequired`.

   In both cases the attempt is recorded.
3. The result is recorded and signed with the agent's key.

The SDK **fails closed**: if the server cannot be reached, the tool does
not run and the call rejects with `ProvenzaUnavailable`. Pass
`failOpen: true` to run it anyway and log it locally.

In **standalone** mode (no server), calls go to a local, signed,
hash-chained audit log. Only hashes of arguments and results are written,
never the content. You can restrict which tools run with `allowedTools`.

Tools take **one arguments object**: it is what policies and argument
rules inspect.

## Identity

An admin issues a one-time enrollment token in Provenza (**Agents → New
agent**). The keys are generated on the agent's side:

```bash
export PROVENZA_URL=https://provenza.example.com
export PROVENZA_TOKEN=pvz_enr_...
```

The identity is stored in `~/.config/provenza/agents/<name>.json` (mode
600, the Python SDK's format). It is refused if other users can read it,
and never sent to a server other than the one it was enrolled with.

`Agent.create({ hybrid: true })` adds an ML-DSA-65 (post-quantum) key next
to Ed25519; this uses `@noble/post-quantum`.

Node has no OS keychain in its standard library, so keep the file on an
encrypted volume.

## More

```ts
await agent.withChain(chainId, () => openTickets({ status: "open" }));
await agent.delegate(otherAgentId, "summarize Q3", ["read"], { tools: ["db.read"], expiresIn: 600 });
await agent.call("files.delete", { path }, () => fs.rm(path));          // govern any single call

const check = await agent.check("files.delete", { path });             // or by hand
if (check.decision === "allowed") { await fs.rm(path); await agent.record(check, { deleted: true }); }
```

With `recordMode: "background"`, the tool returns after one round-trip and
the records follow; `flush()` waits for them. Refusals are always recorded
before the rejection.

If a call ran but could not be recorded on the server, the result still
stands. A signed gap is written to the local log, and a process warning
`PROVENZA_UNRECORDED` is emitted.

## Auto-instrumentation

```ts
import { instrument } from "provenza/auto";
await instrument(agent);
```

Every **direct** call from this process to an AI provider through the
global `fetch` becomes a governed action. That covers the OpenAI,
Anthropic and Google SDKs, LangChain.js provider clients, and plain
`fetch`. The provider hosts come from your organization's AI domain
catalog, and the **server** decides each call:

- a domain **blocked** in the catalog is refused, with an incident;
- an allowed or not-yet-classified domain is sent, unless a policy refuses it.

Only the host, method, path (without the query string), and the hash and
size of the body are recorded. The prompt is never recorded.

A refusal comes back as a `Response`: 403 with an OpenAI-style error body
and `x-should-retry: false`. Provider SDKs therefore raise their usual
permission error with Provenza's reason and do not retry. With the server
unreachable, nothing is sent (503). `uninstrument()` restores `fetch`.

Clients that do not use the global `fetch` (`node:http`, axios, got) are
not covered.

## LangChain.js

```ts
// npm install @langchain/core
import { governTools } from "provenza/integrations/langchain";
const tools = governTools(agent, [search, readFile], { prefix: "kb." });
```

Each tool keeps its name, description and schema. A refusal reaches the
model as the tool's answer ("Refused by Provenza: …"), and nothing ran.
Pass `{ refusal: "error" }` to throw instead. `@langchain/core` is an
optional peer dependency: it is installed only if you use it.

## Provenza's gateways

```ts
import OpenAI from "openai";
import { gatewayOptions } from "provenza/integrations/openai";
const client = new OpenAI(gatewayOptions(agent));     // the LLM gateway, with the agent's own key

import { connection } from "provenza/integrations/mcp";
const { url, headers } = connection(agent);           // point any MCP client at Provenza
```

## Egress proxy

Behind a Provenza egress proxy (`proxy/` in the repository), the agent can
send its key and let the proxy check each request. Or it can check a
request itself and send the check id:

```ts
import { proxyHeaders } from "provenza";

const chk = await agent.proxyCheck("stripe", "POST", "/v1/charges", { body });
await fetch("http://127.0.0.1:8443/stripe/v1/charges", { method: "POST", body, headers: proxyHeaders(chk) });
```

`path`, `query` and `body` must be exactly what goes on the wire; the proxy
refuses any other request under that check, and records it itself.

## HTTP tools through Provenza

An API registered in Provenza (**Gateways → HTTP tools**) is called through
Provenza, and the agent never holds its key:

```ts
const out = await agent.invoke("crm.set_tier", { id: "42", tier: "gold" });   // ProvenzaDenied on a refusal
const tools = await agent.httpTools();   // names, descriptions and input schemas, for the model
```

## Permits for tools

An allowed check carries a permit signed by the organization. The agent
sends it with the call, and the tool runs nothing without a valid one:

```ts
import { permitHeaders, permitMiddleware, PermitVerifier, withPermit } from "provenza";

// the agent
const chk = await agent.check("crm.update", payload);
await fetch(url, { method: "POST", body: JSON.stringify(payload), headers: permitHeaders(chk) });

// the tool
const verifier = new PermitVerifier("https://provenza.example.com", "acme");
app.post("/update", express.json(), permitMiddleware(verifier, { tool: "crm.update" }), handler);
export const POST = withPermit(verifier, "crm.update", async (request, permit, input) => Response.json({ ok: true }));
```

The verifier checks the signature against the organization's JWKS, the
tool, the hash of the JSON body (it must be the checked input) and the
expiry, then redeems the permit with Provenza: once, across every replica.

## What this is, and what it is not

The SDK runs inside the agent's process. It is the agent's honest record
and cooperative enforcement: code in the same process could act around
it. Enforcement that does not depend on the agent's code comes from the
gateways, which hold the credentials so the agent never has them.

Verify a local audit log with `verifyAuditLog(path, publicKey)`.
