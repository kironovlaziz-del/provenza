# Quickstart: from install to the first governed agent action

At the end of this guide, Claude Code on your computer calls a tool through
Provenza. You see the call checked and recorded, refuse it with one line of
policy, and prove both decisions offline with a file and a public key,
without trusting the server.

| Step | | Time |
|---|---|---|
| 1 | Install on a server | about 10 min, mostly waiting |
| 2 | Sign in | 1 min |
| 3 | Give agents a tool | 2 min |
| 4 | Create the agent | 1 min |
| 5 | Connect Claude Code and make the first call | 3 min |
| 6 | Refuse it with one line of policy | 1 min |
| 7 | Prove it offline | 2 min |

## Before you start

- **A server:** Linux with systemd (Ubuntu 24.04+, Debian 13+, RHEL/Rocky/Alma
  9.3+ or Fedora), 2 vCPU, 4 GB RAM, ports 80 and 443 open, and a domain whose
  DNS record points at it. The installer sets up everything else, Podman
  included.
- **Your computer,** where the AI client runs: **Linux** (amd64 or arm64) or
  **Windows 10/11**, with Claude Code installed.
  Gemini CLI, Cursor or any OpenAI-compatible client work the same
  way. macOS is not supported by the connect command yet.
- **Python 3** anywhere, for the last step.

## 1. Install

On the server:

```bash
git clone https://github.com/kironovlaziz-del/provenza.git /opt/provenza
cd /opt/provenza
sudo ./install.sh
```

It asks for the domain, the organization's name and the first administrator,
then generates every secret, builds the images, starts the stack and gets an
HTTPS certificate. The build is most of the wait. It ends with:

```
✓ Provenza is running at https://provenza.example.com

  Organization: example
  Administrator: admin@example.com
```

Copy `/opt/provenza/deploy/.env` somewhere off the server, such as a password
manager: no backup can be read without it. [Self-hosting](self-hosting.md)
covers options, HTTPS and upgrades.

## 2. Sign in

Open the address. Sign in with the **organization** the installer printed,
your e-mail and your password.

The browser then asks for a passkey, and a banner stays until you add one. You
can skip it for now. Add it later under **My profile → Passkeys**: you need it
to sign a policy release or to lift a kill switch.

## 3. Give agents a tool

Agents get nothing by default. Here you give them a public, read-only MCP
server: [DeepWiki](https://docs.devin.ai/work-with-devin/deepwiki-mcp), which
answers questions about GitHub repositories and needs no key.

**Settings → Gateways → MCP tools → Add MCP server**:

| | |
|---|---|
| Identifier | `deepwiki` |
| Name | `DeepWiki` |
| Server URL | `https://mcp.deepwiki.com/mcp` |

Leave the rest as it is and save. Press **Sync**: three tools appear, each
*Awaiting approval*. **Approve** two of them:

- `deepwiki.read_wiki_structure`
- `deepwiki.ask_question`

Leave `deepwiki.read_wiki_contents` unapproved. An approval pins the tool's
exact definition. If DeepWiki changes it later, agents lose the tool until
you approve the new one.

## 4. Create the agent

**AI → Agents → Register agent**:

- **Allowed tools:** `deepwiki.read_wiki_structure, deepwiki.ask_question`.
  Use exact names: an agent's rights list tools, not patterns.
- **Signing key:** keep *Enrollment token* and *Post-quantum hybrid*.
- Leave the name empty: the agent is named after the client and the machine,
  for example `claude-code@laptop`.

Press **Issue enrollment token**. The page shows **Connect an AI client**.

## 5. Connect Claude Code and make the first call

In **Connect an AI client**, pick **Claude Code** and your system, then copy
the command. Run it on your computer, as yourself, not as root or
administrator.

On Linux it looks like this; on Windows it is one PowerShell line:

```bash
f=$(mktemp) && curl -fsSL https://provenza.example.com/api/v1/agent-enrollment/connect.sh -o "$f" && sh "$f" claude-code pvz_enr_…
```

The command:

1. downloads `provenza-proxy` from your server and checks it;
2. makes the agent's keys on your computer (they never leave it) and proves
   them to the server;
3. starts agent mode on `127.0.0.1:8480`, which signs each call as the agent;
4. adds Provenza to Claude Code as an MCP server.

The Provenza page switches to **Connected: agent #N**, with a link to the
agent.

Start Claude Code again, so it picks up the new MCP server. `/mcp` lists
`provenza` with the two tools. Ask:

> Use the provenza tools: how does github.com/kironovlaziz-del/provenza verify a delegation?

Claude Code asks permission to use `deepwiki.ask_question`. Allow it, and the
answer comes back.

In Provenza, open the agent (**Open the agent**, or **AI → Agents →
claude-code@…**). Under **Recent actions**
the call is listed: `deepwiki.ask_question`, **allowed**. Provenza checked it
against the agent's rights and the policy before it reached DeepWiki, and
recorded it.

## 6. Refuse it with one line of policy

**Rules → Policy hierarchy → Organization**, in the form:

- **Denied tools:** `deepwiki.ask_question`

Press **Save**. In YAML that is:

```yaml
version: 1
tools:
  deny: ["deepwiki.ask_question"]
```

Ask Claude Code the same question again. This time the tool answers:

```
Refused by Provenza (action #2): Blocked by policy 'organization policy'
```

DeepWiki never received the call. **Recent actions** lists it as **denied**,
with the policy that refused it. `deepwiki.read_wiki_structure` still works:
a stricter rule applies at once and only to what it names.

## 7. Prove it offline

The two records are on your server, and the server could be lying. A receipt
lets anyone check each one without trusting it:

1. In **Recent actions**, click the action's number, for example **#2**. **Audit Log →
   Evidence** opens with its receipt. Press **Download receipt**.
2. On **Audit Log**, copy the **Audit key** fingerprint (`SHA256:…`). This is
   the public key you trust. In real use, take it from somewhere the server
   cannot change, such as a checkpoint you saved or a fingerprint your
   organization published.
3. On any machine:

```bash
curl -fsSLO https://raw.githubusercontent.com/kironovlaziz-del/provenza/main/tools/provenza_audit.py
python3 -m pip install "cryptography>=48"
python3 provenza_audit.py receipt receipt-2.json --fingerprint SHA256:…
```

On Windows, use `curl.exe` and `py` in place of `curl` and `python3`.

```
VERIFIED  action 2 (deepwiki.ask_question, denied) of agent 1: refused and witnessed by the Provenza mcp_gateway
          sealed in seal 1, audit record of organization 1, checkpoint of 7 records signed by SHA256:…
```

The tool shares no code with the server. It checks that the record names this
action and the policy check that decided it, sits in a sealed Merkle batch, is
in the audit log, and that the log is signed by the key you gave it: Ed25519
and ML-DSA-65, both of which must verify. Change one character of the file
and it says `NOT VERIFIED`.

## What you have now

- **An agent with its own key** that holds only the rights you gave it.
- **A tool gateway** that shows agents only approved tool definitions, checks
  every call before it runs, and records it.
- **A policy** that refuses a tool for the whole organization in one line.
- **Evidence** that an auditor verifies without trusting your server.

## Next

- **Make it the only way out.** An agent that calls DeepWiki directly is not
  asked. [Egress lockdown](egress-lockdown.md) leaves it one path, through
  Provenza.
- **Sign the policy.** Add a passkey, then **Rules → Policy hierarchy → Signed
  policy → Prepare the first release → Sign with passkey**. The egress proxy
  on the server enforces only what administrators signed
  ([self-hosting](self-hosting.md#the-edge-services-of-this-host)).
- **Ask a person first:** put a tool under *Tools needing approval* instead of
  *Denied tools* ([policies](policies.md)).
- **Stop everything:** **Stop all** in the top bar ([kill switch](kill-switch.md)).
- **See the AI people use:** the endpoint agent and the browser extension
  ([Shadow AI](shadow-ai.md)).
- **Your own agents:** `pip install provenza`, or the JavaScript or Go SDK,
  enroll with the same kind of token ([SDKs](README.md#agents)).

## If something does not work

| | |
|---|---|
| **Sync** fails | The server must reach `mcp.deepwiki.com` over HTTPS. Check its outbound firewall. |
| The connect command stops with *supports Linux on amd64 and arm64* | It runs on Linux and Windows. On macOS, use a Linux VM for now. |
| `/mcp` in Claude Code does not show `provenza` | Start Claude Code again. `claude mcp list` should list it at `http://127.0.0.1:8480/_mcp`. |
| `/mcp` shows `provenza` with no tools | The tools are not approved, or the names under the agent's **Allowed tools** differ from the approved ones. |
| *Unknown tool* | The tool is not approved, or not in the agent's rights. |

To take the client out again: `~/.local/bin/provenza-proxy connect claude-code --remove`
on Linux, or `& "$env:LOCALAPPDATA\provenza\provenza-proxy.exe" connect claude-code --remove`
on Windows. Then revoke the agent's key on its page.
