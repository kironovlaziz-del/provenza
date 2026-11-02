# Shadow AI Monitor: collectors

Shadow AI Monitor finds AI that nobody sanctioned. The data comes from three
collectors, and all of them feed one **Sightings** list. Working with that
list in the UI is covered in the [user guide](../USER_GUIDE.md#8-shadow-ai-monitor).
This page covers the collectors themselves.

| Collector | Finds | Lives in |
|---|---|---|
| Endpoint agent | local models and AI agents on a machine | `agent/` (Go) |
| Network discovery | services on the local network (part of the endpoint agent) | `agent/collectors/discovery/` |
| Browser extension | visits to AI services; closes the ones the organization blocks | `extension/` (Chrome and Edge, Manifest V3) |

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
value. Every 15 minutes it also says it is alive, so its machine is listed
on **Devices** even when nothing AI-related runs there.

**On the Provenza server** the installer runs it already, with its key
(`provenza-agent.service`, `provenza edge setup`; see
[self-hosting](self-hosting.md)).

**On another machine:** create an Ingestion Source of type *Endpoint agent*
(Settings → Ingestion Sources) and download the agent from your Provenza -
no Go needed:

```bash
base=https://provenza.example.com/api/v1/egress-sensor/download
curl -fsSL -O $base/provenza-agent-linux-amd64 -O $base/SHA256SUMS   # or -arm64
grep " provenza-agent-linux-amd64$" SHA256SUMS | sha256sum -c -
sudo install -m 0755 provenza-agent-linux-amd64 /usr/local/bin/provenza-agent
# config.json from agent/config.example.json: api_url and the key (or ingestion_key_file)
provenza-agent -config config.json
```

From the repository: `cd agent && go build -o provenza-agent .` (Go 1.26+).

`config.json`:

| Field | Description |
|-------|-------------|
| `api_url` | the ingest endpoint, `…/api/v1/shadow-ai/ingest` |
| `ingestion_key` | the machine key from an Ingestion Source (never a user token) |
| `ingestion_key_file` | the key from a file (mode 600) instead, as the installer writes it |
| `agent_id` | the name the machine is listed under (default: the host name) |
| `scan_interval_sec` / `batch_interval_sec` / `batch_size` | how often it scans and reports |
| `heartbeat_sec` | how often it says it is alive (default 900 s) |
| `model_search_paths` | directories scanned for local model weight files; `*` is expanded on every scan (`/home/*/.ollama/models`) |
| `discovery_enabled` | network discovery on or off |
| `discovery_interval_sec` | discovery sweep interval (default 900 s) |

## Network discovery

The endpoint agent passively discovers services on its network: DNS, the
gateway, Active Directory (via DNS SRV), mDNS and LLMNR. With the
`CAP_NET_RAW` capability it also runs an ARP scan and listens for DHCP.
Discovery is read-only: nothing is connected until an admin supplies
credentials for a specific service.

ARP scan and DHCP listening need raw sockets. Do not give the agent full
root: run it as a user with just that one capability, or as root with every
other capability dropped, as the installer does on the Provenza server
(`deploy/edge/provenza-agent.service`: `CAP_DAC_READ_SEARCH` to read other
users' model directories, and `CAP_NET_RAW`). For an agent of your own as a
systemd service (here `provenza-agent.service`), a drop-in:

```bash
sudo mkdir -p /etc/systemd/system/provenza-agent.service.d
sudo tee /etc/systemd/system/provenza-agent.service.d/override.conf >/dev/null <<'CONF'
[Service]
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
CONF
sudo systemctl daemon-reload
sudo systemctl restart provenza-agent
```

The agent checks for the capability at startup. Without it, it logs that
it runs the unprivileged methods only.

## Browser extension

A Manifest V3 extension for Chrome and Edge (2.0+). It acts on the
organization's **AI Domain Catalog**:

| Domain in the catalog | In the browser | Reported |
|---|---|---|
| **blocked** | the page is replaced by "*Name* is not allowed", with the organization's allowed AI services offered instead | the attempt (`action_taken: blocked`), and Provenza opens an incident |
| **unknown** (or a built-in AI service nobody classified) | opens normally | the visit: a sighting for review |
| **allowed** | opens normally | the visit, logged only |

- **The list** comes from `GET /api/v1/shadow-ai/extension/catalog` (the
  extension's ingestion key) when the extension starts and every hour: the
  organization's catalog plus the built-in AI services. A change in the
  catalog reaches every browser within the hour. Until the server has
  answered once, a built-in list is used.
- **What is sent:** the host name (never a full URL: a path or a query can
  hold what was typed), the service's name and category, and a random id per
  browser install. Events wait in the browser when the server cannot be
  reached and are sent later.
- **Secret warning:** on the AI services it watches, the extension warns
  before an API key, a card number, a private key or a token is pasted or
  typed. The warning stays in the browser: Provenza receives nothing about it.
- An extension's ingestion key ships inside the extension, so it may report
  domain visits and read the catalog, nothing else, and is rate-limited.

### Installing it for a pilot

On **Settings → Ingestion Sources**, click **Download extension**: the server
packages it with this server's address and a fresh key. Unzip it into a folder
that stays, open `chrome://extensions` (or `edge://extensions`), turn on
**Developer mode**, click **Load unpacked** and pick the folder.

### Installing it for the whole organization

Two policies: one installs the extension so that people cannot remove it, the
other gives it its server and key so that people cannot change them (its popup
then says *Managed by your organization*).

1. **Install.** Chrome and Edge force-install extensions from their stores, or
   a packed `.crx` that you host with an update manifest. Publish the
   downloaded extension once as an *unlisted* item in the Chrome Web Store
   (and Edge Add-ons for Edge), or pack and host it yourself; then list its id
   in the `ExtensionInstallForcelist` (or `ExtensionSettings`) policy through
   Group Policy, Intune, Jamf or the Google Admin console.
2. **Configure.** Create one ingestion source of type *Browser extension* on
   **Settings → Ingestion Sources** and give its key to every browser through
   the extension's managed configuration (`managed_schema.json`):

   | Key | Value |
   |---|---|
   | `serverUrl` | your Provenza address, e.g. `https://provenza.example.com` |
   | `ingestionKey` | the browser-extension key |

   Replace `<ID>` with the extension's id (shown on `chrome://extensions`, or
   on its store page):

   - **Windows** (Group Policy preferences, Intune or a script), values of type
     `REG_SZ` under
     `HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\<ID>\policy`
     (Edge: `HKLM\Software\Policies\Microsoft\Edge\3rdparty\extensions\<ID>\policy`).
   - **macOS** (a configuration profile through your MDM): the preference
     domain `com.google.Chrome.extensions.<ID>` (Edge:
     `com.microsoft.Edge.extensions.<ID>`) with the two keys as strings.
   - **Linux**: `/etc/opt/chrome/policies/managed/provenza.json` (Edge:
     `/etc/opt/edge/policies/managed/`, Chromium: `/etc/chromium/policies/managed/`):

     ```json
     {"3rdparty": {"extensions": {"<ID>": {
       "serverUrl": "https://provenza.example.com",
       "ingestionKey": "<key>"}}}}
     ```

   - **Google Admin console**: Devices → Chrome → Apps & extensions → the
     extension → *Policy for extensions*:

     ```json
     {"serverUrl": {"Value": "https://provenza.example.com"},
      "ingestionKey": {"Value": "<key>"}}
     ```

   A configuration that arrives later takes effect without a browser restart.

## Related

- [Egress sensor](../sensor/README.md): an eBPF sensor that enforces the
  egress policy for governed workloads on a host and reports what it
  blocked.
- [Egress lockdown](egress-lockdown.md): leaving agents one way out.
