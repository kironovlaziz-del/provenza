# Locking agents down: one way out

Provenza decides what an agent may do. But the agent only meets those
decisions when it uses Provenza: an SDK call, a gateway, the egress proxy. An
agent that calls an API directly, with its own key, never asks and is never
refused. Every control is then cooperative.

The fix is in the network, not in Provenza. Give the agent's host **one way
out: the Provenza egress proxy**. The proxy:

- checks and records every call to an external API (`proxy/README.md`);
- relays the agent's calls to Provenza itself (`relay_provenza`).

So the agent needs no other destination: not the internet, not Provenza, and
no DNS for outside names.

```
agent ──► provenza-proxy:8443 ──► /<route>/...      checked, credential injected, recorded
                              └─► /_provenza/api/v1/...   relayed to Provenza unchanged
          (nothing else is reachable)
```

## 1. Generate the rules

Go to **Gateways → External APIs → Lock agents down**, or call
`POST /api/v1/egress-lockdown/render`. Pick where the agent runs:

| | What you get |
|---|---|
| **Kubernetes** | The proxy in its own namespace, plus two NetworkPolicies: agent pods may reach only the proxy and the cluster DNS, and only those pods may reach the proxy. The proxy is not a sidecar: a sidecar shares the pod's network, so the agent could use the proxy's way out. NetworkPolicy needs a CNI that enforces it, such as Calico or Cilium. |
| **Docker compose** | The agent on an `internal: true` network, which has no route out. The proxy is on that network and on one with a way out. |
| **Host / VM (nftables)** | Connections opened by the agent's Unix user may go only to the proxy's IP and port. The proxy runs as another user. DNS is blocked too: the proxy is addressed by IP. |

Then point the agent at the proxy:

```sh
PROVENZA_URL=http://provenza-proxy:8443/_provenza          # the SDKs talk to Provenza through the relay
STRIPE_BASE_URL=http://provenza-proxy:8443/stripe          # one per egress route
```

The proxy's configuration must have `"relay_provenza": true`. The generated
`proxy.json` has it.

## 2. Verify

The agent's host runs an **egress self-check**:

```python
agent.egress_selfcheck()            # Python;  egressSelfcheck() in JS, EgressSelfcheck() in Go
# {"verdict": "confined", ...}
```

Provenza names a few targets on the internet and a beacon URL on itself. The
host tries each target directly and fetches the beacon, then reports what it
reached, signed with the agent's key. The verdict is:

- `open` if any target was reached, or if Provenza saw the beacon being
  fetched. Provenza sees the beacon itself, whatever the report says, even
  after the report. An `egress_unconfined` incident is raised.
- `confined` otherwise.

**Agent identity** shows each agent's latest verdict. Turn on **Require
confined egress** there to make it a condition: an agent then acts only while
its latest check is `confined` and recent (24 hours by default). Otherwise
it gets `agent.egress_unchecked`, `agent.egress_unconfined` or
`agent.egress_check_stale`. Run the check at start-up and then periodically,
for example every few hours.

An agent connected with **AI agents → Connect an agent** needs none of this
by hand: `provenza-proxy connect` runs the check once the client is connected
and prints the verdict, and agent mode runs it again when it starts and once a
day (`provenza-proxy egress-check` runs it on demand: exit 0 confined, 3 open).
**Settings → Protection coverage** shows the result for every agent. On a
developer's laptop the answer is usually `open`: the laptop reaches the
internet directly, so Provenza sees only what the client sends through it.

### What the check proves, and what it does not

It catches a host whose lockdown is missing or broken, which is the common
case. It cannot catch an agent that cheats on purpose: such an agent can skip
the beacon and report that it reached nothing. Only the network rule itself
stops that agent. The check tells you the rule is in place. The rule is the
control.

### The beacon

The beacon is served at `/egress-beacon/<token>`, outside `/api/v1`. The
proxy's relay passes only `/api/v1`, so it cannot carry the beacon. Your
reverse proxy must send `/egress-beacon/` to the backend. The bundled Caddy
configuration does. With nginx:

```nginx
location /egress-beacon/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

If your agents may reach Provenza directly instead of through the relay,
give the beacon a name of its own that points at the same server. Set it in
`EGRESS_BEACON_BASE_URL`, for example `https://egress-check.example.com`,
and keep that name off the agents' allowlist. Otherwise a host that may reach
Provenza and nothing else would look open.

| Setting | Default | |
|---|---|---|
| `EGRESS_PROBE_TARGETS` | `api.openai.com:443,1.1.1.1:443` | what a confined host must fail to reach |
| `EGRESS_BEACON_BASE_URL` | `PUBLIC_BASE_URL` | where the beacon is |

## The agent's network

The egress sensor gives the same control from inside the host's kernel,
for one agent at a time, without rules written by hand. **Every agent has
a workload of its own from the moment it is made**, named `agent-<id>`:

| | |
|---|---|
| Mode | **observe**: every connection is recorded, nothing is blocked |
| DNS | `any`: every name resolves, through the sensor, which learns the name behind each address |
| Allowed | nothing yet |
| cgroup patterns | none: it governs only what is started for the agent |

It governs nothing until it knows which processes are the agent, on a
Linux host with the Provenza sensor (the Provenza server has one by
default). On the agent's page (**AI agents → the agent → Network**,
administrators), **Attach to a service or container…** lists what each
sensor found on its host - its systemd services (Quadlet containers
included) and its Docker and rootful Podman containers - and one click
attaches the agent to what it runs as: that cgroup becomes the workload's,
nothing on the host is changed, and the agent need not be restarted. A
service stays attached across restarts of the service and the host; a
container until it is recreated (a new container has a new id), so attach
the systemd service that runs a container you recreate. One workload
governs a cgroup: a service another workload governs is shown as such.

The sensor sends that list with its heartbeat when it changes: the unit
or container name and its cgroup path, nothing from inside the processes.
Login sessions and rootless containers are not listed.

An agent started by hand can go through the sensor instead:

```sh
provenza-sensor --agent <id> run -- <the agent's command>
```

as root or as a member of the sensor's group (`provenza`).

From then on every connection the agent opens is recorded. Its page shows
the hosts that run it and where it went: the names it resolved, or the
bare address of what it reached without asking the sensor's DNS.

When the list looks right, **Allow the checked and enforce** makes it the
agent's allow list and switches the workload to **enforce**: from then on
the kernel refuses everything else, on every host that runs the agent under
the sensor, within a minute. Names in the list resolve through the sensor,
and no other name does (`dns: listed`). The workload stays editable on the
Runtime page like any other.

Observe by default, enforce by a person's decision: a new agent is never
blocked by a list nobody wrote. An agent made before this was done by
default gets the same workload with **Observe its network** on its page.
So does a new agent of an organization that already has 1000 workloads:
every workload goes to every sensor, and a sensor holds about 4096, so
Provenza stops making them on its own there and leaves the room to people.

An agent that runs where there is no sensor - a developer's laptop with
Claude Code or Cursor, say - is not contained by this: only its calls
through Provenza (MCP tools, the LLM gateway) are governed. Its page says
so.
