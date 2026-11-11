# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
docs/quickstart.md, step by step, on the server's side: what the guide tells
an administrator to click must give what the guide says it gives.

  3. an MCP server (DeepWiki's tools, faked here) is added, synced, and two of
     its three tools are approved;
  4. the agent has those two in its rights;
  5. it sees exactly the two, and its call runs and is recorded;
  6. one line in the organization's policy refuses one tool, at once, and the
     refusal is recorded too, naming the level;
  7. the action's receipt verifies offline with tools/provenza_audit.py - the
     command line the guide prints - and fails once it is changed.

The client side (provenza-proxy connect, agent mode) has its own tests in
proxy/internal/connect and in CI's "Connect on Windows".
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import auth_headers
from tests.test_mcp_gateway import _agent, _call, _sync, fake  # noqa: F401  (fake: the fixture)

ROOT = Path(__file__).resolve().parents[2]
SERVERS = "/api/v1/mcp-servers"

# the tools of https://mcp.deepwiki.com/mcp, as its tools/list describes them
DEEPWIKI = [
    {"name": "read_wiki_structure", "description": "Get a list of documentation topics for a GitHub repository",
     "inputSchema": {"type": "object", "properties": {"repoName": {"type": "string"}}, "required": ["repoName"]}},
    {"name": "read_wiki_contents", "description": "View documentation about a GitHub repository",
     "inputSchema": {"type": "object", "properties": {"repoName": {"type": "string"}}, "required": ["repoName"]}},
    {"name": "ask_question", "description": "Ask any question about a GitHub repository",
     "inputSchema": {"type": "object", "properties": {"repoName": {"type": "string"}, "question": {"type": "string"}},
                     "required": ["repoName", "question"]}},
]
TOOLS = ("deepwiki.read_wiki_structure", "deepwiki.ask_question")
ASK = {"repoName": "kironovlaziz-del/provenza", "question": "How does Provenza verify a delegation?"}


def _audit_tool(*args) -> subprocess.CompletedProcess:
    # run as the guide does: a separate process, nothing shared with the server
    return subprocess.run([sys.executable, str(ROOT / "tools" / "provenza_audit.py"), *args],
                          capture_output=True, text=True, timeout=60)


async def _actions(client, token, agent_id):
    r = await client.get("/api/v1/agents/actions/", params={"agent_id": agent_id}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    body = r.json()
    return body["items"] if isinstance(body, dict) else body


@pytest.mark.asyncio
async def test_the_quickstart_path(client, admin_token, fake, tmp_path):  # noqa: F811
    fake.tools = [dict(t) for t in DEEPWIKI]
    fake.output = {"content": [{"type": "text", "text": "Provenza checks both signatures of a hybrid key."}]}

    # 3. add the server, sync, approve two of its three tools
    r = await client.post(SERVERS, json={"slug": "deepwiki", "name": "DeepWiki",
                                         "url": "https://mcp.deepwiki.com/mcp"}, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    server = r.json()
    report = await _sync(client, admin_token, server)
    assert sorted(report["added"]) == ["deepwiki.ask_question", "deepwiki.read_wiki_contents",
                                       "deepwiki.read_wiki_structure"]
    listed = (await client.get(f"{SERVERS}/{server['id']}/tools", headers=auth_headers(admin_token))).json()
    for tool in listed:
        if tool["exposed_name"] in TOOLS:
            r = await client.post(f"{SERVERS}/{server['id']}/tools/{tool['id']}/approve",
                                  headers=auth_headers(admin_token))
            assert r.status_code == 200, r.text

    # 4. the agent, with the two names in its rights
    agent = await _agent(client, admin_token, tools=TOOLS)

    # 5. it sees exactly the approved tools of its rights, and a call runs
    r = await _call(client, agent, "tools/list")
    assert sorted(t["name"] for t in r.json()["result"]["tools"]) == sorted(TOOLS)
    r = await _call(client, agent, "tools/call", {"name": "deepwiki.ask_question", "arguments": ASK})
    assert r.status_code == 200, r.text
    assert "hybrid key" in r.json()["result"]["content"][0]["text"]
    allowed = (await _actions(client, admin_token, agent["id"]))[0]
    assert allowed["tool_name"] == "deepwiki.ask_question" and allowed["policy_check_result"] == "allowed"

    # a tool that was not approved is not there at all
    r = await _call(client, agent, "tools/call", {"name": "deepwiki.read_wiki_contents", "arguments": {"repoName": "x/y"}})
    assert r.json()["error"]["code"] == -32602

    # 6. one line in the organization's policy, the YAML the guide shows
    yaml = "version: 1\ntools:\n  deny: [\"deepwiki.ask_question\"]\n"
    r = await client.put("/api/v1/policy-layers", json={"scope": "org", "yaml": yaml, "revision": 0},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    calls_before = len([b for _, b in fake.requests if b["method"] == "tools/call"])
    r = await _call(client, agent, "tools/call", {"name": "deepwiki.ask_question", "arguments": ASK})
    body = r.json()
    refusal = json.dumps(body.get("error") or body.get("result"))
    assert "error" in body or body["result"].get("isError") is True, body
    assert "Blocked by policy 'organization policy'" in refusal, refusal
    assert len([b for _, b in fake.requests if b["method"] == "tools/call"]) == calls_before   # never sent
    denied = (await _actions(client, admin_token, agent["id"]))[0]
    assert denied["tool_name"] == "deepwiki.ask_question" and denied["policy_check_result"] == "denied"
    assert denied["reason"] == "Blocked by policy 'organization policy'", denied["reason"]
    # the other tool still works
    r = await _call(client, agent, "tools/call", {"name": "deepwiki.read_wiki_structure",
                                                  "arguments": {"repoName": ASK["repoName"]}})
    assert "result" in r.json() and not r.json()["result"].get("isError"), r.text

    # 7. the receipt, as Audit Log -> Evidence downloads it, checked offline
    keys = (await client.get("/api/v1/audit-logs/integrity", headers=auth_headers(admin_token))).json()
    for action, decision in ((allowed, "allowed"), (denied, "denied")):
        r = await client.get(f"/api/v1/pvp/receipts/{action['id']}", headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        receipt = r.json()
        path = tmp_path / f"receipt-{action['id']}.json"
        path.write_text(json.dumps(receipt))
        fp = receipt["checkpoint"]["key_fingerprint"]
        assert fp == (keys.get("checkpoint") or keys.get("latest_checkpoint") or {}).get("key_fingerprint", fp)
        done = _audit_tool("receipt", str(path), "--fingerprint", fp)
        assert done.returncode == 0, done.stdout + done.stderr
        did = "executed" if decision == "allowed" else "refused"
        assert done.stdout.startswith(f"VERIFIED  action {action['id']} (deepwiki.ask_question, {decision}) of agent "
                                      f"{agent['id']}: {did} and witnessed by the Provenza mcp_gateway"), done.stdout

        # changed after the fact: refused
        receipt["action"]["tool_name"] = "deepwiki.read_wiki_structure"
        path.write_text(json.dumps(receipt))
        done = _audit_tool("receipt", str(path), "--fingerprint", fp)
        assert done.returncode == 1, done.stdout + done.stderr
