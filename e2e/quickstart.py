# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
docs/quickstart.md, end to end, in a browser - the way a person goes
through it, step by step:

  2  sign in (and skip the passkey)
  3  add the MCP server, sync, approve two of its three tools
  4  register the agent with those two tools, issue the enrollment token
  5  run the connect command shown on the page; call a tool through agent mode;
     the agent's page lists the call as allowed
  6  deny the tool with one line of policy; the same call is refused and
     never reaches the server; the other tool still works
  7  download the receipt of the refused call and verify it offline with
     tools/provenza_audit.py and the audit key's fingerprint from the page

Step 1 (install.sh) is done before, by the workflow (.github/workflows/quickstart.yml).
DeepWiki is replaced by e2e/fake_deepwiki.py, which has the same tools.

    python3 e2e/quickstart.py --url https://localhost --org example \\
        --email admin@example.com --password ... --mcp-url http://host.containers.internal:8765/mcp

Screenshots of each step go to --out; the test fails on the first step
that does not do what the quickstart says.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from playwright.sync_api import Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = ("deepwiki.read_wiki_structure", "deepwiki.ask_wiki_question")
LEFT_OUT = "deepwiki.read_wiki_contents"
AGENT_MCP = "http://127.0.0.1:8480/_mcp"


def step(msg: str) -> None:
    print(f"\n== {msg}", flush=True)


class Run:
    def __init__(self, page: Page, args):
        self.page, self.a = page, args
        self.out = Path(args.out)
        self.out.mkdir(parents=True, exist_ok=True)
        self.n = 0

    def shot(self, name: str) -> None:
        self.n += 1
        self.page.screenshot(path=str(self.out / f"{self.n:02d}-{name}.png"), full_page=True)

    def go(self, path: str) -> None:
        self.page.goto(self.a.url.rstrip("/") + path)
        self.page.wait_for_load_state("networkidle")


# ---------------------------------------------------------------- 2. sign in

def sign_in(r: Run) -> None:
    step("2. Sign in")
    r.go("/login")
    p = r.page
    p.fill("#org_slug", r.a.org)
    p.fill("#email", r.a.email)
    p.fill("#password", r.a.password)
    p.click("button[type=submit]")
    # the console opens in simple mode (docs/quickstart.md): its first tab is the agents
    expect(p.get_by_role("navigation", name="Main").get_by_role("link", name="AI agents")).to_be_visible(timeout=30_000)
    # the passkey is skipped: a banner offers it, nothing waits for it
    expect(p.get_by_text("Add a passkey")).to_be_visible()
    r.shot("signed-in")


# ---------------------------------------------------------------- 3. give agents a tool

def tool_row(r: Run, name: str):
    # the tools table sits in a row of the servers table: the innermost row
    return r.page.locator("tr", has=r.page.get_by_text(name, exact=True)).last


def give_tools(r: Run) -> None:
    step("3. Give agents a tool: add the MCP server, sync, approve two tools")
    r.go("/gateway?tab=mcp")
    p = r.page
    p.get_by_role("button", name="Add MCP server").click()
    p.fill("#mcp-name", "DeepWiki")
    p.fill("#mcp-slug", "deepwiki")
    p.fill("#mcp-url", r.a.mcp_url)
    p.get_by_role("button", name="Create").click()
    p.get_by_role("button", name="Sync", exact=True).first.click()
    for name in (*ALLOWED, LEFT_OUT):
        expect(tool_row(r, name)).to_contain_text("Awaiting approval", timeout=30_000)
    for name in ALLOWED:
        tool_row(r, name).get_by_role("button", name="Approve").click()
        expect(tool_row(r, name)).to_contain_text("Approved", timeout=15_000)
    expect(tool_row(r, LEFT_OUT)).to_contain_text("Awaiting approval")
    r.shot("tools-approved")


# ---------------------------------------------------------------- 4. create the agent

def create_agent(r: Run) -> str:
    step("4. Create the agent and issue the enrollment token")
    r.go("/agents/new")
    p = r.page
    p.locator("xpath=//label[normalize-space()='Allowed tools']/following-sibling::input[1]").fill(", ".join(ALLOWED))
    hybrid = p.get_by_label(re.compile("Post-quantum hybrid"))
    if r.a.no_hybrid:
        hybrid.uncheck()
    else:
        expect(hybrid).to_be_checked()
    p.get_by_role("button", name="Issue enrollment token").click()
    expect(p.get_by_text("Connect an AI client")).to_be_visible(timeout=20_000)
    p.select_option("#connect-client", r.a.client)
    p.select_option("#connect-system", "linux")
    cmd = p.locator("code", has_text="connect.sh").inner_text().strip()
    r.shot("agent-token")
    return cmd


# ---------------------------------------------------------------- 5. connect and call

def mcp_call(tool: str, arguments: dict) -> str:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": arguments}}).encode()
    req = urllib.request.Request(AGENT_MCP, body, {"Content-Type": "application/json",
                                                   "Accept": "application/json, text/event-stream"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode()


def agent_mode_logs() -> None:
    """What agent mode said: its user service, or the log of the background process."""
    for cmd in (["systemctl", "--user", "--no-pager", "status", "provenza-agent-*"],
                ["journalctl", "--user", "--no-pager", "-n", "80", "-u", "provenza-agent-*"],
                ["sh", "-c", "tail -n 80 ~/.local/state/provenza/agent-*.log"]):
        out = subprocess.run(cmd, capture_output=True, text=True)
        print("   $", " ".join(cmd), "\n" + (out.stdout + out.stderr)[-6000:])


def fake_calls(r: Run) -> list:
    return [json.loads(x)["tool"] for x in Path(r.a.fake_log).read_text().splitlines() if x.strip()]


def connect_and_call(r: Run, cmd: str) -> int:
    step("5. Connect the client and make the first call")
    if r.a.api_origin:   # local development: the API is not on the page's origin
        cmd = re.sub(r"https?://[^/\s]+(?=/api/v1/agent-enrollment/connect\.sh)", r.a.api_origin, cmd)
    print("   $", re.sub(r"pvz_enr_\S+", "pvz_enr_…", cmd))
    out = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=300)
    print(out.stdout + out.stderr)
    assert out.returncode == 0, "the connect command failed"
    p = r.page
    done = p.get_by_text(re.compile(r"Connected: agent #\d+"))
    expect(done).to_be_visible(timeout=60_000)
    agent_id = int(re.search(r"#(\d+)", done.inner_text()).group(1))
    r.shot("connected")

    answer, last = "", None
    for _ in range(30):   # agent mode starting in the background
        try:
            answer = mcp_call("deepwiki.ask_wiki_question",
                              {"repoName": "kironovlaziz-del/provenza", "question": "How is a delegation verified?"})
            break
        except urllib.error.HTTPError as e:   # agent mode answered, with an error: no point waiting
            last = f"HTTP {e.code}: {e.read().decode(errors='replace')[:2000]}"
            break
        except OSError as e:
            last = repr(e)
            time.sleep(2)
    print("   ", answer[:300] or last)
    if "fake-deepwiki answered ask_wiki_question" not in answer:
        agent_mode_logs()
    assert "fake-deepwiki answered ask_wiki_question" in answer, f"the first call did not come back: {last or answer[:500]}"
    assert fake_calls(r) == ["ask_wiki_question"]

    r.go(f"/agents/{agent_id}")
    recent = p.locator(".panel", has=p.get_by_role("heading", name="Recent actions"))
    expect(recent).to_contain_text("deepwiki.ask_wiki_question", timeout=30_000)
    expect(recent).to_contain_text("allowed")
    r.shot("first-call-allowed")
    return agent_id


# ---------------------------------------------------------------- 6. refuse it with one line of policy

def refuse(r: Run, agent_id: int) -> int:
    step("6. Refuse it with one line of policy")
    r.go("/policy-hierarchy")
    p = r.page
    p.locator("xpath=//label[normalize-space()='Denied tools']/following-sibling::input[1]").first.fill(
        "deepwiki.ask_wiki_question")
    p.get_by_role("button", name="Save", exact=True).first.click()
    expect(p.get_by_text(re.compile(r"Saved \(revision \d+\)"))).to_be_visible(timeout=20_000)
    r.shot("policy-saved")

    answer = mcp_call("deepwiki.ask_wiki_question",
                      {"repoName": "kironovlaziz-del/provenza", "question": "How is a delegation verified?"})
    print("   ", answer[:300])
    m = re.search(r"Refused by Provenza \(action #(\d+)\)", answer)
    assert m and "Blocked by policy" in answer, "the call was not refused by the policy"
    assert fake_calls(r) == ["ask_wiki_question"], "the refused call reached the server"
    still = mcp_call("deepwiki.read_wiki_structure", {"repoName": "kironovlaziz-del/provenza"})
    assert "fake-deepwiki answered read_wiki_structure" in still, "the other tool stopped working"

    r.go(f"/agents/{agent_id}")
    recent = p.locator(".panel", has=p.get_by_role("heading", name="Recent actions"))
    expect(recent).to_contain_text("denied", timeout=30_000)
    r.shot("refused")
    return int(m.group(1))


# ---------------------------------------------------------------- 7. prove it offline

def prove(r: Run, agent_id: int, action_id: int) -> None:
    step("7. Prove it offline")
    p = r.page
    r.go(f"/agents/{agent_id}")
    p.get_by_role("link", name=f"#{action_id}", exact=True).click()
    p.wait_for_load_state("networkidle")
    with p.expect_download(timeout=30_000) as dl:
        p.get_by_role("button", name="Download receipt").click()
    receipt = r.out / f"receipt-{action_id}.json"
    dl.value.save_as(str(receipt))
    r.shot("receipt")

    r.go("/audit")
    key = re.search(r"Audit key: (SHA256:[A-Za-z0-9+/=_-]+)", p.locator("body").inner_text())
    assert key, "no audit key fingerprint on the Audit Log page"
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "provenza_audit.py"), "receipt", str(receipt),
                          "--fingerprint", key.group(1)], capture_output=True, text=True, timeout=60)
    print(out.stdout + out.stderr)
    assert out.returncode == 0 and out.stdout.startswith("VERIFIED"), "the receipt did not verify"
    assert f"action {action_id} (deepwiki.ask_wiki_question, denied)" in out.stdout

    # one character changed, and it no longer verifies
    doc = json.loads(receipt.read_text())
    doc_text = json.dumps(doc).replace('"denied"', '"allowed"', 1)
    forged = r.out / "receipt-forged.json"
    forged.write_text(doc_text)
    bad = subprocess.run([sys.executable, str(ROOT / "tools" / "provenza_audit.py"), "receipt", str(forged),
                          "--fingerprint", key.group(1)], capture_output=True, text=True, timeout=60)
    assert bad.returncode != 0 and "NOT VERIFIED" in bad.stdout + bad.stderr, "a changed receipt still verified"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="the Provenza address, e.g. https://localhost")
    ap.add_argument("--org", required=True)
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", default=os.environ.get("PROVENZA_ADMIN_PASSWORD"))
    ap.add_argument("--mcp-url", required=True, help="where Provenza reaches e2e/fake_deepwiki.py")
    ap.add_argument("--fake-log", default="/tmp/fake-deepwiki-calls.jsonl")
    ap.add_argument("--client", default="gemini-cli")
    ap.add_argument("--no-hybrid", action="store_true", help="Ed25519 only (a build without ML-DSA)")
    ap.add_argument("--api-origin", help="local development: the API's origin when it is not the page's")
    ap.add_argument("--out", default="quickstart-artifacts")
    a = ap.parse_args()
    assert a.password, "--password or PROVENZA_ADMIN_PASSWORD"
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1400, "height": 900}, ignore_https_errors=True,
                                  accept_downloads=True)
        page = ctx.new_page()
        page.set_default_timeout(20_000)
        r = Run(page, a)
        try:
            sign_in(r)
            give_tools(r)
            cmd = create_agent(r)
            agent_id = connect_and_call(r, cmd)
            action_id = refuse(r, agent_id)
            prove(r, agent_id, action_id)
        except Exception:
            r.shot("FAILED")
            raise
        finally:
            browser.close()
    print("\nQUICKSTART PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
