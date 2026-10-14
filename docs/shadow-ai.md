# Shadow AI Monitor: collectors

Shadow AI Monitor finds AI that nobody sanctioned. The data comes from three
collectors, and all of them feed one **Sightings** list. Working with that
list in the UI is covered in the [user guide](../USER_GUIDE.md#8-shadow-ai-monitor).
This page covers the collectors themselves.

| Collector | Finds | Lives in |
|---|---|---|
| Endpoint agent | local models and AI agents on a machine | `agent/` (Go) |
| Network discovery | services on the local network (part of the endpoint agent) | `agent/collectors/discovery/` |
| Browser extension | visits to AI services, secrets about to be pasted into them | `extension/` (Chrome, Manifest V3) |

## How data arrives

Collectors send batches to `POST /api/v1/shadow-ai/ingest`. They
authenticate with a machine key (`X-Ingestion-Key`) from an **Ingestion
Source**, never with a user's session. Every event is kept raw for later
analysis. Domain visits are classified against the organization's **AI
Domain Catalog** (allow, block or unknown), which decides what becomes a
sighting or an incident.

Sightings are deduplicated. They show human-readable detail (port, file,
device) and a "seen N times" counter, and convert in one click into a
sanctioned provider or a dismissal. Agents found on endpoints appear on
**Agents Found** for review: register them as governed agents or ignore
them. Every machine or browser that reports is listed on **Devices** with
its user, OS and last activity.

## Endpoint agent

A native Go binary that detects:

- **local AI tools:** processes such as `ollama` and `vllm`, listening
  ports, model weight files on disk;
- **AI agents:** Claude Code, Cursor, Copilot, Codex CLI, Aider, CrewAI,
  LangGraph, n8n, and others. Agents that no catalog knows are found by
  behavior: a process that talks to an LLM API or has an LLM SDK loaded.

It sends only what it recognized, never a process command line or a key
value.

```bash
cd agent
cp config.example.json config.json
# set api_url and ingestion_key (create an Ingestion Source in the UI to get a key)
go build -o shadow-agent .
./shadow-agent -config config.json
```

`config.json`:

| Field | Description |
|-------|-------------|
| `api_url` | the ingest endpoint, `…/api/v1/shadow-ai/ingest` |
| `ingestion_key` | the machine key from an Ingestion Source (never a user token) |
| `scan_interval_sec` / `batch_interval_sec` / `batch_size` | how often it scans and reports |
| `model_search_paths` | directories scanned for local model weight files |
| `discovery_enabled` | network discovery on or off |
| `discovery_interval_sec` | discovery sweep interval (default 900 s) |

## Network discovery

The endpoint agent passively discovers services on its network: DNS, the
gateway, Active Directory (via DNS SRV), mDNS and LLMNR. With the
`CAP_NET_RAW` capability it also runs an ARP scan and listens for DHCP.
Discovery is read-only: nothing is connected until an admin supplies
credentials for a specific service.

ARP scan and DHCP listening need raw sockets. Never run the agent as root;
grant just that one capability. If the agent runs as a systemd service
(here `shadow-agent.service`), add a drop-in:

```bash
sudo mkdir -p /etc/systemd/system/shadow-agent.service.d
sudo tee /etc/systemd/system/shadow-agent.service.d/override.conf >/dev/null <<'CONF'
[Service]
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
CONF
sudo systemctl daemon-reload
sudo systemctl restart shadow-agent
```

The agent checks for the capability at startup. Without it, it logs that
it runs the unprivileged methods only.

## Browser extension

A Manifest V3 Chrome extension that flags visits to known AI services and
warns the user before they paste or type secrets (API keys, card numbers,
private keys) into an AI tool. It reports only *that* something sensitive
was detected (type and label), never any part of the value, and it does
not send full page URLs. Admins download it from the **Ingestion Sources**
page (**Download extension**) and push it to employees' browsers.

## Related

- [Egress sensor](../sensor/README.md): an eBPF sensor that enforces the
  egress policy for governed workloads on a host and reports what it
  blocked.
- [Egress lockdown](egress-lockdown.md): leaving agents one way out.
