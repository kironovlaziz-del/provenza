# Shadow AI Monitor: collectors

Shadow AI Monitor finds AI that nobody sanctioned. The data comes from four
collectors, and all of them feed one **Sightings** list. Working with that
list in the UI is covered in the [user guide](../USER_GUIDE.md#8-shadow-ai-monitor).
This page covers the collectors themselves.

| Collector | Finds | Lives in |
|---|---|---|
| Endpoint agent | local models and AI agents on a machine | `agent/` (Go) |
| Network discovery | services on the local network (part of the endpoint agent) | `agent/collectors/discovery/` |
| Browser extension | visits to AI services; closes the ones the organization blocks | `extension/` (Chrome and Edge, Manifest V3) |
| DNS and proxy logs | who reached which AI service, from logs you already keep | `backend/app/services/log_import.py` |

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

A native Go binary for **Windows, macOS and Linux** (amd64 and arm64). It
runs as a service and detects:

- **local AI tools:** processes such as `ollama`, LM Studio and `vllm`,
  listening ports, model weight files on disk;
- **AI agents:** Claude Code, Cursor, Copilot, Codex CLI, Aider, CrewAI,
  LangGraph, n8n, and others. Agents that no catalog knows are found by
  behavior (below).

It sends only what it recognized, never a process command line, a file's
content or a key value. Every 15 minutes it also says it is alive, so its
machine is listed on **Devices** even when nothing AI-related runs there.

**On the Provenza server** the installer runs it already, with its key
(`provenza-agent.service`, `provenza edge setup`; see
[self-hosting](self-hosting.md)).

### Installing it on a computer

1. Create an Ingestion Source of type *Endpoint agent* (Settings → Ingestion
   Sources). One source for the whole fleet is enough; its key is shown once.
2. The same page then shows the install command for each system. Run it as
   an administrator; it asks for the key with the input hidden.

**Windows** (PowerShell, *Run as administrator*; Windows 10/11, Server 2016+):

```powershell
$s='https://provenza.example.com'; & ([scriptblock]::Create((irm "$s/api/v1/egress-sensor/download/install-agent.ps1"))) -Server $s
```

**macOS** (Terminal; macOS 12+, Intel or Apple silicon) and **Linux**
(systemd):

```bash
f=$(mktemp) && curl -fsSL https://provenza.example.com/api/v1/egress-sensor/download/install-agent.sh -o "$f" \
  && sudo sh "$f" --server https://provenza.example.com
```

The script downloads the agent for this machine from your Provenza, checks
it against `SHA256SUMS` next to it, and runs `provenza-agent install`:

| | Windows | macOS | Linux |
|---|---|---|---|
| Service | `ProvenzaAgent`, automatic start, LocalSystem, restarted on failure | LaunchDaemon `com.provenza.agent`, root, starts at boot, kept alive | `provenza-agent.service`, root with two capabilities (below) |
| Binary | `C:\Program Files\Provenza\provenza-agent.exe` | `/usr/local/bin/provenza-agent` | `/usr/local/bin/provenza-agent` |
| Configuration and key | `C:\ProgramData\Provenza\Agent\` (SYSTEM and Administrators only) | `/Library/Application Support/Provenza Agent/` (root only) | `/etc/provenza-agent/` (root only) |
| Queue of undelivered events | `…\Agent\state\queue` | `…/Provenza Agent/state/queue` | `/var/lib/provenza-agent/queue` |
| Log | `…\Agent\state\agent.log` | `/Library/Logs/provenza-agent.log` | `journalctl -u provenza-agent` |

The machine appears on **Devices** within a minute. On the machine:

```text
provenza-agent status              the service, the server, the queue
provenza-agent install             upgrade in place with the binary you run (keeps the configuration)
provenza-agent uninstall [--purge] remove the service and the binary (--purge: also the configuration and the key)
```

Running the install command again upgrades the agent; the key is not asked
for then. Options of the scripts: `--agent-id` / `-AgentId` (the name the
machine is listed under, default the host name), `--discovery` /
`-Discovery` (network discovery, below), `--uninstall` / `-Uninstall`.

### Installing it on the whole fleet

For an unattended install the key comes from a parameter or the
`PROVENZA_KEY` environment variable instead of the prompt. Keep the
deployment script where only administrators can read it: the key lets
anyone who has it send events as your organization's endpoints (nothing
more).

**Microsoft Intune** (Devices → Scripts and remediations → Platform
scripts → Windows; *Run this script using the logged on credentials*: No;
*Run script in 64-bit PowerShell*: Yes):

```powershell
$s = 'https://provenza.example.com'
$k = 'ing_...'   # the Endpoint agent key
& ([scriptblock]::Create((Invoke-RestMethod "$s/api/v1/egress-sensor/download/install-agent.ps1"))) -Server $s -Key $k
```

The same script works as a Win32 app install command, from SCCM / ConfigMgr,
or as a **Group Policy** computer startup script (Computer Configuration →
Policies → Windows Settings → Scripts → Startup → PowerShell Scripts). It
is idempotent: on a computer that has the agent it upgrades it.

**Jamf Pro** (Settings → Computer management → Scripts; parameter 4: the
server, parameter 5: the key; add it to a policy with the trigger you use):

```bash
#!/bin/sh
f=$(mktemp) && curl -fsSL "$4/api/v1/egress-sensor/download/install-agent.sh" -o "$f" \
  && PROVENZA_KEY="$5" sh "$f" --server "$4"
```

Kandji, Mosyle and other MDMs take the same script. For model files in
folders macOS protects (Desktop, Documents, Downloads), grant
`/usr/local/bin/provenza-agent` *Full Disk Access* with a PPPC
configuration profile; the default model folders (`~/.ollama`, `~/.cache`,
`~/.lmstudio`) do not need it.

**Linux** (Ansible, Puppet, a cloud-init script): the same command with
`--key-file PATH` or `PROVENZA_KEY`.

### Not signed yet

The binaries are not code-signed yet. Downloaded by the scripts (not by a
browser) they carry no "downloaded from the internet" mark, so Windows
SmartScreen and macOS Gatekeeper do not stop them. Endpoint protection
(Defender for Endpoint, CrowdStrike, SentinelOne) may still flag an
unsigned service: allow it by path (above) or by its SHA-256 from
`/api/v1/egress-sensor/download/SHA256SUMS`. A binary downloaded through a
browser on macOS needs `xattr -d com.apple.quarantine provenza-agent`.

### What it sees on each system

| Signal | Linux | macOS | Windows |
|---|---|---|---|
| Known agents and runtimes by process name and command line | yes | yes | yes |
| Unknown agents: connection to an LLM API | yes | yes (`lsof`) | yes (`netstat`) |
| Unknown agents: LLM API key names in the environment | yes | yes | no |
| Unknown agents: LLM SDK libraries loaded | yes | no | no |
| Local model ports, model files | yes | yes | yes |
| Network discovery: DNS SRV, mDNS, LLMNR | yes | yes | yes |
| Network discovery: DNS servers, gateway | yes | DNS servers | no |
| Network discovery: ARP scan, DHCP listening | yes (`CAP_NET_RAW`) | no | no |

On Windows and macOS an unknown agent is therefore found mostly by its
connection to an LLM API, which is "medium" confidence on its own (an API
address behind a shared CDN can also serve other sites). Processes the
system protects (Windows protected processes, macOS system processes) are
listed by name only. Model files are attributed to the user whose home
folder holds them.

### Offline and restarts

A batch the server does not accept (no network, server down, HTTP 5xx,
429, 401/403) is written to the queue on disk and sent again later, oldest
first, with a growing pause between attempts (10 s up to 5 minutes). It
survives a restart of the agent or the computer. The queue is bounded
(`queue_max_mb`, 50 MB by default); when full, the oldest batches go first.
A batch the server rejects as malformed (another 4xx) is dropped.

### By hand

```bash
base=https://provenza.example.com/api/v1/egress-sensor/download
curl -fsSL -O $base/provenza-agent-linux-amd64 -O $base/SHA256SUMS   # or -arm64, -darwin-*, -windows-*.exe
grep " provenza-agent-linux-amd64$" SHA256SUMS | sha256sum -c -
chmod +x provenza-agent-linux-amd64
sudo ./provenza-agent-linux-amd64 install --server https://provenza.example.com --key -   # reads the key from stdin
# or in the foreground, without a service:
./provenza-agent-linux-amd64 run -config config.json
```

From the repository: `cd agent && go build -o provenza-agent .` (Go 1.26+;
`GOOS=windows` / `GOOS=darwin` cross-compile without cgo).

`config.json` (`provenza-agent install` writes it):

| Field | Description |
|-------|-------------|
| `api_url` | the ingest endpoint, `…/api/v1/shadow-ai/ingest` |
| `ingestion_key` | the machine key from an Ingestion Source (never a user token) |
| `ingestion_key_file` | the key from a file readable by the service only, as the installers write it |
| `agent_id` | the name the machine is listed under (default: the host name) |
| `scan_interval_sec` / `batch_interval_sec` / `batch_size` | how often it scans and reports |
| `heartbeat_sec` | how often it says it is alive (default 900 s) |
| `model_search_paths` | directories scanned for model weight files; `*` is expanded on every scan (`/home/*/.ollama/models`). Left out: every user's Ollama, Hugging Face, LM Studio, GPT4All and Jan folders for the system; `[]` turns the scan off |
| `state_dir` | where the queue lives (default per system, above) |
| `queue_max_mb` | the queue's size limit (default 50) |
| `discovery_enabled` | network discovery on or off |
| `discovery_interval_sec` | discovery sweep interval (default 900 s) |

## Network discovery

The endpoint agent passively discovers services on its network: DNS, the
gateway, Active Directory (via DNS SRV), mDNS and LLMNR. On Linux, with the
`CAP_NET_RAW` capability, it also runs an ARP scan and listens for DHCP
(see the table above for Windows and macOS).
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

## DNS and proxy logs

Your DNS servers and web proxy already record who reaches which site. Those
logs show AI use on every computer and phone on the network - without
installing anything - and, when the proxy authenticates people, who it was.

Provenza reads a log, keeps only the lines that reach an AI service (the
organization's **AI Domain Catalog** plus the built-in list, API hosts
included), and folds them into one visit per service, person and computer,
with how many lines it stands for, how many were blocked, and when first and
last. The visits go through the same pipeline as the browser extension's:
an unknown service becomes a sighting (source *DNS log* or *Proxy log*), a
blocked one also an incident, an allowed one is only counted; reviewers see
who uses each service and how often. Nothing else of the log is kept: no
URL path, no query, no other site.

### Formats

Recognized line by line, so one file may mix them:

| Format | Example | Person |
|---|---|---|
| Squid `access.log` (native) | `1730512345.123 150 10.0.0.5 TCP_TUNNEL/200 3456 CONNECT chatgpt.com:443 alice ...` | yes, when the proxy authenticates |
| BIND query log | `client @0x7f.. 10.0.0.5#53211 (chatgpt.com): query: chatgpt.com IN A + ...` | no |
| dnsmasq / Pi-hole | `dnsmasq[123]: query[A] chatgpt.com from 10.0.0.5` | no |
| Unbound (`log-queries: yes`) | `info: 10.0.0.5 chatgpt.com. A IN` | no |
| Windows DNS debug log | `... UDP Rcv 10.0.0.5 1234 Q [...] A (7)chatgpt(3)com(0)` | no |
| Zeek `dns.log` / `http.log` | TSV with its `#fields` header, or JSON | no |
| JSON lines | keys such as `query`, `domain`, `host`, `url`, `user`, `client_ip`, `ts`, `action` | when present |
| key=value (Fortinet, CEF, ...) | `srcip=10.0.0.5 user="alice" hostname="chatgpt.com" action="blocked"` | when present |
| CSV with a header | Cisco Umbrella, Zscaler, Netskope, Palo Alto exports; columns found by name | when present |

From any other line the host names in it are still taken, and its first IPv4
address as the computer. A DNS log names computers by address; a proxy that
authenticates names people (`alice`, `CORP\alice`, an e-mail). gzip files
are unpacked on the fly. A line counts as blocked when its action says so
(`TCP_DENIED`, `blocked`, `deny`, ...).

### Importing a file

**Shadow AI → Import logs** (administrators): choose the file, **Import**.
The page tells what it found - lines read, how many reach AI services, the
services, people and computers - and the sightings appear within a minute.
Up to 200 MB of log text per file (`LOG_IMPORT_MAX_MB`); split a larger one.
Each upload is recorded in the audit trail, under the source *Log uploads*.

Import each log once: the same lines imported twice count twice.

### A continuous feed

A log forwarder sends new lines itself with a **Gateway** ingestion key
(Settings → Ingestion Sources → type *Gateway*):

```text
POST /api/v1/shadow-ai/ingest/logs
X-Ingestion-Key: <the Gateway key>
<the log lines, as text or gzip>
```

Up to 20 MB of log text per request (`LOG_INGEST_MAX_MB`), 30 requests per
minute per key. The answer is the same summary the upload page shows.

**Squid**, after each rotation (`/etc/logrotate.d/squid`, with
`delaycompress` so yesterday's file is still plain text):

```bash
postrotate
    /usr/sbin/squid -k rotate
    split -C 18M -d /var/log/squid/access.log.1 /tmp/provenza-log-
    for f in /tmp/provenza-log-*; do
        curl -fsS -H "X-Ingestion-Key: $(cat /etc/provenza/gateway.key)" \
          --data-binary @"$f" https://provenza.example.com/api/v1/shadow-ai/ingest/logs >/dev/null
        rm -f "$f"
    done
endscript
```

The same works for BIND, dnsmasq, Pi-hole and Unbound logs.

**Windows DNS** (enable *Debug logging* → *Log packets for debugging*,
incoming, queries, to `C:\dns\dns.log`), a scheduled task every hour:

```powershell
$s = 'https://provenza.example.com'
$k = Get-Content 'C:\ProgramData\Provenza\gateway.key'
Copy-Item C:\dns\dns.log C:\dns\dns-send.log -Force
Clear-Content C:\dns\dns.log
Invoke-RestMethod -Method Post -Uri "$s/api/v1/shadow-ai/ingest/logs" -Headers @{ 'X-Ingestion-Key' = $k } `
  -InFile C:\dns\dns-send.log -ContentType 'application/octet-stream'
```

**Cloud DNS and secure web gateways** (Cisco Umbrella, Zscaler, Netskope,
Cloudflare Gateway): export their logs as CSV or JSON and upload them, or
have the export job post each file to `/ingest/logs`.

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
   | `userEmail` | optional, per user: who uses this browser (below) |

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

### Who uses the browser (userEmail)

With `userEmail`, every visit carries the person's address: a Shadow AI
sighting then shows how many people use the service and, for reviewers and
the oversight roles, who, how often and when last (other users see only the
count). Without it, a browser is counted as "a browser without a name".

The address comes **only** from policy, never from what a person types, and
the server keeps nothing from an extension but a well-formed address. It is
attribution, not authentication: the key is public, and a person with
administrator rights on their own computer can change their own user-level
policy. Use it to see who needs which AI service, not as evidence against
someone.

`userEmail` differs per person, so it is set as a **user-level** policy,
written when the person signs in:

- **Windows** (a logon script through Group Policy, or an Intune PowerShell
  script that runs as the signed-in user), on domain- or Entra-joined
  computers:

  ```powershell
  $id  = "<ID>"
  $upn = (whoami /upn).Trim()
  $key = "HKCU:\Software\Policies\Google\Chrome\3rdparty\extensions\$id\policy"
  # Edge: HKCU:\Software\Policies\Microsoft\Edge\3rdparty\extensions\$id\policy
  New-Item -Path $key -Force | Out-Null
  Set-ItemProperty -Path $key -Name userEmail -Value $upn
  ```

  `serverUrl` and `ingestionKey` stay machine-wide (HKLM); Chrome merges the
  two levels.
- **macOS**: a user-level configuration profile for the same preference
  domain, with your MDM's variable for the user's e-mail (for example
  `$EMAIL` in Jamf Pro).
- **Linux**: policies are per machine; set `userEmail` there only on
  computers that one person uses.
- **Google Admin console**: one value applies to a whole organizational unit,
  so it cannot name each person; leave `userEmail` out there.

## Related

- [Egress sensor](../sensor/README.md): an eBPF sensor that enforces the
  egress policy for governed workloads on a host and reports what it
  blocked.
- [Egress lockdown](egress-lockdown.md): leaving agents one way out.
