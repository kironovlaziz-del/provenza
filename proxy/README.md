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

1. In Provenza, **Egress → Routes**: add a route, e.g. slug `stripe`,
   upstream `https://api.stripe.com`, methods `GET, POST`, prefixes
   `/v1/charges`. Credential:
   - `server` - stored encrypted in Provenza; the proxy keeps it in memory only;
   - `local`  - the proxy injects it from its own configuration
     (`local_secrets`); Provenza never sees it;
   - `none`.
2. Give the agent the right `proxy.stripe`.
3. **Egress → Proxies → New**: the key (`pvz_proxy_…`) is shown once. It can
   read the server-held secrets of your routes - store it like them.
4. Run the proxy:

```sh
go build -trimpath -o provenza-proxy ./proxy      # or: docker build -t provenza-proxy proxy/
PROVENZA_PROXY_KEY=pvz_proxy_... ./provenza-proxy -config proxy.json
```

`proxy.json` ([example](deploy/proxy.example.json)):

| field | default | |
|---|---|---|
| `server_url` | - | Provenza |
| `proxy_key_file` / `proxy_key_env` | `PROVENZA_PROXY_KEY` | the proxy's key |
| `listen` | `127.0.0.1:8443` | another address needs `allow_non_loopback`: whoever reaches it can use the credentials |
| `local_secrets` | - | `{"<route>": {"header", "value_file" \| "value_env"}}`; a file is re-read on every request |
| `upstream_timeout` / `server_timeout` | `60s` / `10s` | |
| `relay_provenza` | `false` | relay `/_provenza/api/v1/...` to `server_url` unchanged, so an agent that may reach only this proxy still reaches Provenza (`PROVENZA_URL=http://<proxy>/_provenza`). Only `/api/v1` is relayed; the proxy's key and the agent's cookies are not passed |

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

## Make it the only way out

The proxy governs what goes through it. Close the other paths: an agent
that may reach anything else can call APIs without asking. With
`relay_provenza` the agent needs to reach this proxy and nothing else, and
**Gateways → Egress → Lock agents down** in Provenza generates the rules for
Kubernetes, Docker compose or nftables. To verify a host, run the SDKs' egress
self-check. See [docs/egress-lockdown.md](../docs/egress-lockdown.md).

[deploy/kubernetes.yaml](deploy/kubernetes.yaml) runs the proxy as a sidecar,
which is simpler but weaker. The pod's NetworkPolicy must then let the
upstreams through, and the agent container shares that network.
