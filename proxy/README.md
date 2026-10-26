# Provenza egress proxy

Agents reach external APIs only through this proxy, and the proxy holds the
credentials. Every request is checked by Provenza before it leaves, and what it
did is recorded as a signed, sealed PVP action (`executed_by: "egress_proxy"`).
Go standard library only; one static binary.

```
agent ──► http://127.0.0.1:8443/<route>/<path>
            │ the route table (from Provenza): upstream, methods, path prefixes, body limit
            │ check  - mediated: POST /egress-proxy/check with its own key and the agent's (X-Agent-Key)
            │        - SDK:      the agent's own check (X-Provenza-Check-Id)
            │ redeem - the exact request, hashes only; a different one burns the check
            ▼
          upstream + the injected credential ──► response streamed back
            │ complete - status, response hash and size -> the recorded action
```

The request never chooses the upstream or the credential. The agent's own
`Authorization`, `Cookie`, `X-Agent-Key` and `X-Provenza-*` headers are not
forwarded, redirects are returned to the agent rather than followed (the
credential would follow them), and paths with `.`/`..` segments or encoded
separators are refused. If Provenza is unreachable, nothing is sent (503).

## Setup

1. In Provenza, **Gateways → External APIs → Routes**: add a route, e.g. slug `stripe`,
   upstream `https://api.stripe.com`, methods `GET, POST`, prefixes
   `/v1/charges`. Credential:
   - `sealed` - typed in the browser and sealed there to each proxy's own
     encryption key (below); Provenza stores envelopes it cannot open, the
     proxy opens its own and keeps the credential in memory only;
   - `local`  - the proxy injects it from its own configuration
     (`local_secrets`); Provenza never sees it;
   - `none`.
2. Give the agent the right `proxy.stripe`.
3. **Gateways → External APIs → Proxies → New**: the key (`pvz_proxy_…`) is shown once. It
   authenticates the proxy; it opens no credential.
4. Run the proxy (it registers its keys on start), then seal the route's
   credential to it - a proxy added later needs the credential sealed again.

On the Provenza server itself, steps 3 and 4 are done by the installer
(`provenza edge setup`, [docs/self-hosting.md](../docs/self-hosting.md)): the
proxy runs there as `provenza-proxy.service` with its key in
`/etc/provenza-proxy/`, following the signed policy (`"pin": "tofu"`). On
another host, the binary for it is served by Provenza:
`/api/v1/egress-sensor/download/provenza-proxy-linux-amd64` (or `-arm64`),
listed in `SHA256SUMS` next to it.

```sh
go build -trimpath -o provenza-proxy ./proxy      # or: docker build -t provenza-proxy proxy/
PROVENZA_PROXY_KEY=pvz_proxy_... ./provenza-proxy -config proxy.json
# docker: docker run -v provenza-proxy:/var/lib/provenza-proxy ... (state_dir)
```

`proxy.json` ([example](deploy/proxy.example.json)):

| field | default | |
|---|---|---|
| `server_url` | - | Provenza |
| `proxy_key_file` / `proxy_key_env` | `PROVENZA_PROXY_KEY` | the proxy's key |
| `listen` | `127.0.0.1:8443` | another address needs `allow_non_loopback`: whoever reaches it can use the credentials |
| `local_secrets` | - | `{"<route>": {"header", "value_file" \| "value_env"}}`; for the gateways' upstreams (below) the key is `"<object>:<id>"` - `provider:3` (the API key itself), `mcp_server:5`, `a2a_peer:2`, `http_tool:7` (the header's value); `"upstream": "https://api.example.com"` sends it only to that origin - set it: otherwise it goes wherever the server's configuration points; a file is re-read on every request |
| `upstream_timeout` / `server_timeout` | `60s` / `10s` | |
| `relay_provenza` | `false` | relay `/_provenza/api/v1/...` to `server_url` unchanged, so an agent that may reach only this proxy still reaches Provenza (`PROVENZA_URL=http://<proxy>/_provenza`). Only `/api/v1` is relayed; the proxy's key and the agent's cookies are not passed |
| `state_dir` | `/var/lib/provenza-proxy` | the proxy's own signing key, its receipt log, the last signed policy it verified. Must be writable and kept across restarts |
| `signing_key_file` | - | the signing key from a file made once with `provenza-proxy -genkey` (e.g. a Kubernetes Secret) instead of one generated in `state_dir` |
| `policy.mode` | `off` | `enforce`: a request goes out only if the signed policy this proxy verified itself allows it too (below) |
| `policy.pin` | - | with `enforce`: the SHA-256 of a key manifest you trust (Policies → Policy hierarchy → *Signed policy*), or `tofu` to trust the first release the server shows |
| `policy.require_agent_signature` | `false` | with `enforce`: refuse requests without the agent's own signed request (mediated requests, bare check ids) |

Unknown fields are an error: a typo in a security setting is not ignored.

## Agents

Mediated (no SDK needed) - point the client at the route and send the agent key:

```python
client = OpenAI(base_url="http://127.0.0.1:8443/openai/v1", api_key="unused",
                default_headers={"X-Agent-Key": os.environ["PROVENZA_AGENT_KEY"]})
```

SDK mode - the agent checks first and sends `X-Provenza-Check-Id`; the proxy
redeems that check instead of making its own.

The checked action is `action_type: "proxy"`, `tool_name: "proxy.<route>"`,
`input: {"route", "method", "path", "query_sha256", "body_sha256", "body_bytes"}`
(`path` as sent, percent-encoding kept; a hash is `null` when the query or the
body is empty). Policies and argument rules on `method` and `path` apply as to
any action.

Refusals come back as JSON with `X-Provenza-Refused: 1`:
`{"error": {"code": "provenza_denied", "message": "Refused by Provenza: …"}}`.

## The gateways' protocols

An HTTP tool, an AI connection, an MCP server or an A2A peer whose credential
is sealed to the proxies (or kept in `local_secrets`) is reached only
through a proxy: Provenza's own gateways serve only upstreams that take no
credential. The agent speaks the gateway's protocol to the proxy, with its
own key:

| path | what | instead of |
|---|---|---|
| `/_tools/call` | an HTTP tool call: the SDKs' `invoke` with `egress_proxy` / `PROVENZA_EGRESS_PROXY` | `/api/v1/http-tools/call` |
| `/_llm/v1/chat/completions`, `/_llm/v1/models` | OpenAI chat completions: `base_url="http://<proxy>/_llm/v1"`, the agent's key as the API key | `/api/v1/gateway/v1` |
| `/_mcp` | an MCP endpoint (Streamable HTTP, both protocol eras) | `/api/v1/mcp` |
| `/_a2a/<peer>` | A2A JSON-RPC, and `/.well-known/agent-card.json` | `/api/v1/a2a-gateway/<peer>` |

For each call the proxy sends Provenza only what its gateway records - for
an LLM call the model, the messages' count and hash, never their text - and
Provenza decides exactly as its gateway does (rights, policies, approvals,
the Tool Registry, routes, connections, limits, the kill switch) and
records a refusal at once. The proxy then judges the call itself under the
signed policy (`policy.mode: "enforce"`), sends it with the credential - only
to the origin it was sealed for - and reports what happened: status, token
counts and hashes, with its receipt. The answer goes back to the agent; it
is not recorded.

- **HTTP tools**: the proxy builds the request itself from the tool's pinned
  definition (it checks the digest) and the arguments.
- **MCP**: the proxy syncs the servers it serves every refresh (and at once
  when a credential is sealed) and reports their tools to Provenza, where
  new ones wait for approval and changed ones drift; before each call it
  hashes the live definition itself. `tools/list` and the rest are relayed to
  Provenza's MCP endpoint.
- **A2A**: the proxy fetches the peer's card with the credential (also every
  refresh: changed cards drift); Provenza returns the exact JSON-RPC request
  for the peer and reads the answer (task ownership). The peer's endpoint
  must be on the card's origin - the credential goes nowhere else.
- **LLM**: OpenAI, Groq, Azure OpenAI, Anthropic and custom connections, as
  the server's gateway calls them; streaming is not supported. With the
  organization's "self-hosted providers only" policy the proxy connects only
  to non-public addresses.

## The proxy's own key and receipts

On first start the proxy generates an Ed25519 key in `state_dir` (or uses
`signing_key_file`) and registers its public half with Provenza, once. For
every request it forwards - or refuses under the signed policy - it signs a
receipt naming the action exactly (check, agent, route, request and response
hashes, decision, whether it verified the agent's signature, the signed
policy release it judged by) and appends it to `state_dir/receipts.jsonl`,
each line carrying the SHA-256 of the line before. Provenza keeps the
receipt in the action's sealed evidence; `tools/provenza_audit.py receipt
--proxy-fingerprint <fingerprint>` checks it offline. The fingerprint is
shown under **Gateways → External APIs → Proxies**. A proxy that comes back with another key
is refused: a new key is a new proxy.

The X25519 key credentials are sealed to is derived from the same key, and
registered signed by it; its fingerprint is pinned in the signed policy's
manifest. The proxy logs both fingerprints on start (`keys registered`):
compare them with **Gateways → External APIs → Proxies** before you seal a credential. An
envelope opens only for the route (or connection, server, tool) and the
proxy it was sealed for (`internal/egress/sealed.go`,
`backend/app/pvp/sealed.py`); one the server moved elsewhere does not open,
and its requests are refused (`proxy.sealed_credential_missing`).

## Enforcing the signed policy

With `"policy": {"mode": "enforce", "pin": "<manifest SHA-256>"}` the proxy
judges every request itself, by the signed policy release
([docs/pvp/edge.md](../docs/pvp/edge.md), sections 3-4):

- it fetches releases from Provenza and takes one only when the quorum of
  administrators of the manifest it already trusts signed it with their
  passkeys - the pinned manifest before the first one. A release the server
  forged or altered is not taken; the proxy keeps the last one it verified
  (also across restarts);
- the request must be allowed by the server's check **and** by the release
  (`internal/policy`, the same decisions as the server,
  `sdk/testdata/policy-vectors.json`). The upstream, methods, prefixes and
  body limit come from the release;
- the SDKs send the agent's signed request (`X-Provenza-Request`) with the
  check id; the proxy verifies it with the key fingerprint the release's
  manifest names, and a nonce is accepted once;
- a call the release holds for approval goes out with a human approval the
  proxy verifies itself (the approver's passkey must be in the manifest);
- with no verified release yet, every request is refused.

A refusal of the proxy's own is recorded in Provenza with its receipt.
`require_agent_signature` refuses mediated requests and bare check ids.
A sealed credential is opened only when an administrator of the verified
release vouched for its envelope (signed when sealing in the interface): the
server cannot slip in one of its own. One the server sealed from a
credential it held before is used once an administrator vouches for it
(*Vouch for it* on the object).

## Enforce mode

When the signed policy itself is in enforce mode (Policies → Signed policy →
settings, *Mode*: the release's `enforcement` section), no action runs
without the agent's own signature and the signed policy
([docs/pvp/edge.md](../docs/pvp/edge.md), section 4.2). A proxy with
`policy.mode` "enforce" that verified such a release then:

- takes, on every path - egress routes and `/_tools`, `/_llm`, `/_mcp`,
  `/_a2a` - only requests the agent signed: `X-Provenza-Request` over the
  HTTP request itself (`route` is the first path segment, `_llm` for
  `/_llm/v1/chat/completions`; `method`, the rest of the `path`, the hashes
  of the query and the body), verified with the key the release names for
  that agent, fresh and once. Reads (`GET /_llm/v1/models`, an agent card)
  need none;
- passes the signed request on to Provenza, which verifies it again with
  the agent's registered key (`X-Provenza-Request`, `X-Provenza-Descriptor`
  on a plan; a mediated check becomes the agent's own check);
- says so to Provenza (`X-Provenza-Proxy-Mode: enforce`): Provenza takes
  part in nothing else, executes nothing on its own gateways (every MCP
  server and A2A peer is then served by the proxies, whatever their
  credential) and raises a critical incident for an action a proxy reports
  without a receipt naming a signed release and the agent's verified
  signature.

The SDKs sign their requests (also `invoke` through the proxy). Clients that
cannot - a stock OpenAI, MCP or A2A client, plain HTTP for an egress route -
go through **agent mode**: the same binary next to the agent, signing with
its key.

```sh
provenza-proxy -agent-identity ~/.config/provenza/agents/bot.json \
    -listen unix:/run/provenza/bot.sock -upstream http://egress-proxy:8443
```

```python
http = httpx.Client(transport=httpx.HTTPTransport(uds="/run/provenza/bot.sock"))
client = OpenAI(base_url="http://agent/_llm/v1", api_key="unused", http_client=http)
```

The identity is the agent's identity file: `provenza-agent.json`, saved at
enrollment by the interface (**Agents** → the agent) or by the SDK
(`key_store="file"`), mode 600. Agent mode reads its `agent_id`, `api_key`,
the Ed25519 key and, for a hybrid key, the ML-DSA-65 one: it signs with both,
as the SDKs do. Whoever reaches the listener acts as the agent: on a unix
socket (`unix:<path>`, created with mode 0600, a stale one replaced) only its
owner - run agent mode as the agent's user - and root reach it; a TCP address
is taken on the loopback only (`127.0.0.1:8480`), where every local process
reaches it, and agent mode warns so. It signs each request
(`X-Provenza-Chain-Id` goes into the signed request), drops the client's
`Authorization` and sends the agent's key; answers, streams included, come
back as the proxy sends them.

### Connecting a client in one command

From the interface: Agents → **New agent** (or **Issue re-key token** on an
agent's page) → **Connect an AI client** gives one command for the client's
machine. It downloads this binary from Provenza
(`/api/v1/agent-enrollment/connect.sh`, checked against `SHA256SUMS`), enrolls
the agent there - `provenza-proxy enroll --server <provenza>` with the token in
`$PROVENZA_ENROLL_TOKEN`: the keys are made on that machine, Ed25519 or
Ed25519 + ML-DSA-65, and proven to the server over its challenge - and runs
`connect`. By hand:

```sh
provenza-proxy connect gemini-cli      # or: claude-code, cursor, openai
```

As the agent's user, with its identity in `~/.config/provenza/provenza-agent.json`
(or `--identity <file>`, `$PROVENZA_IDENTITY`):

- the egress proxy is the one on this host (`--proxy auto`: `127.0.0.1:8443` when it
  listens), otherwise Provenza's own gateways (`<server>/api/v1`, from the identity):
  `/_mcp`, `/_llm`, `/_a2a` and `/_tools` go to them, egress routes need an egress proxy;
- agent mode runs as a service of this user (`~/.config/systemd/user/provenza-agent-<id>.service`,
  `127.0.0.1:8480` - `--port` - in front of `--proxy`, default `http://127.0.0.1:8443`);
  `sudo loginctl enable-linger <user>` keeps it running after the user logs out.
  Without a systemd session (`su`, `sudo -u`, a container) it starts in the background
  (`~/.local/state/provenza/agent-<id>.log`) and says how to bring it back after a restart;
- the client gets Provenza's MCP endpoint (`http://127.0.0.1:8480/_mcp`), with no key in it:
  Gemini CLI in `~/.gemini/settings.json` (`"httpUrl"`), Cursor in `~/.cursor/mcp.json`,
  Claude Code with `claude mcp add --transport http --scope user provenza ...`. The rest of
  the file is kept, the original is saved once as `<file>.provenza-backup`, and a file that is
  not plain JSON is left alone (the entry to add is printed);
- `openai`: nothing to write - `base_url` `http://127.0.0.1:8480/_llm/v1`, any API key.

The client reaches the MCP servers of **Gateways → MCP tools**; each call is checked
against the agent's rights. `--remove` takes the entry and the service out again. A signed
policy names each agent's key: after the agent gets a new key, sign a release.

## When Provenza is unreachable

With `policy.mode` `enforce` ([docs/pvp/edge.md](../docs/pvp/edge.md),
sections 6-7):

- **Offline requests.** An egress-route request the agent signed and sent
  without a check id (the SDKs do it when Provenza does not answer:
  `proxy_request_headers` / `proxyRequestHeaders`) is judged by the signed
  release alone - the agent's signature with the key its manifest names,
  once; allowed outright (no approval, no delegation chain); the signed
  route. Each is kept with the proxy's receipt in `state_dir/offline.jsonl`
  and handed to Provenza when it answers again, where it is recorded as an
  action. An agent key alone, and the gateways' protocols, are refused offline.
- **The local kill switch.** After the release's `offline_seconds` (Policies
  → Signed policy → settings; at least 60) without an answer, every request
  is refused (`503 provenza_kill_switch`) until administrators lift it, also
  across restarts (`state_dir/killswitch.json`). When Provenza answers, the
  proxy sends a reconciliation report signed with its key: what the server
  states differently from the release it held before the outage. The quorum
  of that release lifts it under **Gateways → External APIs → Proxies**, each with a passkey,
  accepting every difference no signed release explains; the proxy checks
  the signatures itself.

## Make it the only way out

The proxy governs what goes through it. Close the other paths: an agent
that may reach anything else can call APIs without asking. With
`relay_provenza` the agent needs to reach this proxy and nothing else, and
**Gateways → External APIs → Lock agents down** in Provenza generates the rules for
Kubernetes, Docker compose or nftables. To verify a host, run the SDKs' egress
self-check. See [docs/egress-lockdown.md](../docs/egress-lockdown.md).

### On a host with the egress sensor

The sensor ([sensor/README.md](../sensor/README.md)) can make the proxy the
only process on its host that holds credentials and gets out
([docs/pvp/edge.md](../docs/pvp/edge.md), section 5). Start the proxy through it:

```sh
provenza-sensor --proxy run -- /usr/local/bin/provenza-proxy -config /etc/provenza/proxy.json
```

The proxy runs in a cgroup the sensor holds - nothing in or out - until it
has checked that every process there runs a pinned proxy binary: its
SHA-256 (`sha256sum provenza-proxy`) listed under **Policies → Signed
policy → egress proxy binaries** in a release the sensor verified itself,
or in the sensor's `proxy_binaries` when it has no `policy.pin`. A replaced
or patched binary, or a process being traced, is held. The check takes a
fraction of a second; the proxy retries its first contact with Provenza for
up to 30 s meanwhile. In the systemd unit, the commented `ExecStart` does
this (the proxy's user needs the sensor's `run_group` and must be in its
`proxy_users`). A new proxy version
gets out once a release names its hash: sign that release before you
upgrade.

Its configuration is pinned too: the proxy tells the sensor the SHA-256 of
the configuration file it read (on the sensor's run socket, which
`--proxy run` passes in `PROVENZA_SENSOR_SOCKET`), and the cgroup stays held
until that hash is listed under **Policies → Signed policy → egress proxy
configurations** (`sha256sum /etc/provenza/proxy.json`; or the sensor's
`proxy_configs`). The pinned binary started with another configuration -
another server, another pin, `policy.mode` "off" - is refused by the sensor
and exits. Changing the configuration means signing a release with its new
hash first.

[deploy/kubernetes.yaml](deploy/kubernetes.yaml) runs the proxy as a sidecar,
which is simpler but weaker. The pod's NetworkPolicy must then let the
upstreams through, and the agent container shares that network.
