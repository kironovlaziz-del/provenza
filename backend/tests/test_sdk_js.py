# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The JS SDK (sdk/js) against this server and the Python SDK - cross-language
proof that the bytes agree.

  1. A Python-written identity file is loaded by the JS Agent; the JS Agent
     governs a tool under a check issued by THIS server; the record the JS
     code builds and signs is accepted by THIS server - the canonical form,
     the input/output hashes and the signature all agree, with Unicode,
     astral characters and floats like 1e-7 in the input.
  2. A JS standalone audit log verifies with the Python SDK's verifier.

Needs node and a built sdk/js (npm ci && npm run build); skipped otherwise.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import auth_headers
from tests.enrollment_helpers import enroll

ROOT = Path(__file__).resolve().parents[2]
JS = ROOT / "sdk" / "js"
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

pytestmark = pytest.mark.skipif(shutil.which("node") is None or not (JS / "dist" / "index.js").exists(),
                                reason="needs node and a built sdk/js (npm ci && npm run build)")

from provenza import identity as ids  # noqa: E402
from provenza.audit_log import verify  # noqa: E402
from provenza.crypto import Keys  # noqa: E402

INPUT = {"query": "café АБ \U0001F600 €", "ratio": 1e-7, "small": 0.00001, "n": 3,
         "nested": {"z": [1.5, None, True], "דּ": "x", "\U0001F600": "y"}}

# The JS side: load the identity, govern one tool under the given check, print the record body it built.
RUN_TOOL = r"""
import { Agent } from "%(dist)s/index.js";
const cfg = JSON.parse(process.argv[1]);
let recorded = null;
const fetch = async (url, init) => {
  const path = new URL(url).pathname;
  if (path.endsWith("/agents/actions/check")) return new Response(JSON.stringify(cfg.check), { status: 200 });
  if (path.endsWith("/agents/actions/record")) { recorded = JSON.parse(init.body); return new Response('{"id":1}'); }
  return new Response('{"detail":"unexpected"}', { status: 404 });
};
const agent = await Agent.create({ serverUrl: cfg.server, identityPath: cfg.identity, fetch });
await agent.tool(cfg.tool, () => cfg.output)(cfg.input);
process.stdout.write(JSON.stringify(recorded));
"""

STANDALONE = r"""
import { Agent } from "%(dist)s/index.js";
const agent = await Agent.create({ name: "js-solo", identityPath: process.argv[1] });
const add = agent.tool("calc.add", ({ x, y }) => x + y);
for (let i = 0; i < 3; i++) await add({ x: i, y: 1e-7 });
process.stdout.write(JSON.stringify({ log: agent.auditLog.path, pub: agent.identity.keys.publicKey }));
"""


def _node(script: str, arg: str) -> str:
    out = subprocess.run(["node", "--input-type=module", "-e", script % {"dist": (JS / "dist").as_posix()}, arg],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout


@pytest.mark.asyncio
async def test_a_js_signed_record_is_accepted_by_this_server(client, admin_token, tmp_path):
    enrolled = await enroll(client, admin_token, name="js-bot", capabilities=("read",), allowed_tools=("db.read",))
    identity = tmp_path / "js-bot.json"
    ids.save(ids.Identity(keys=Keys(enrolled["private_key"], enrolled["public_key"]), server="http://test",
                          agent_id=enrolled["id"], api_key=enrolled["api_key"], name="js-bot"), identity)

    check = await client.post("/api/v1/agents/actions/check",
                              json={"agent_id": enrolled["id"], "tool_name": "db.read", "input": INPUT},
                              headers=auth_headers(admin_token))
    assert check.status_code == 200 and check.json()["decision"] == "allowed", check.text

    body = json.loads(_node(RUN_TOOL, json.dumps({
        "server": "http://test", "identity": str(identity), "check": check.json(), "tool": "db.read",
        "input": INPUT, "output": {"rows": [1, 2], "note": "é\U0001F600", "p": 0.0001}})))
    assert body["signature"] and body["check_id"] == check.json()["check_id"]

    r = await client.post("/api/v1/agents/actions/record", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text            # hashes and signature agree across languages
    assert r.json()["signed_payload"]["check_id"] == body["check_id"]


def test_a_js_audit_log_verifies_with_the_python_sdk(tmp_path):
    out = json.loads(_node(STANDALONE, str(tmp_path / "js-solo.json")))
    assert verify(Path(out["log"]), out["pub"]) == []
    lines = Path(out["log"]).read_text().splitlines()
    assert len(lines) == 3 and json.loads(lines[1])["seq"] == 2


VERIFY_PERMIT = """
import { PermitVerifier } from "%(dist)s/index.js";
const { permit, jwks, org, input } = JSON.parse(process.argv[1]);
const fetch = async () => Response.json(jwks);
const v = new PermitVerifier("http://test", org, { fetch, redeem: false });
const p = await v.verify(permit, { tool: "db.read", input });
let other = null;
try { await new PermitVerifier("http://test", org, { fetch, redeem: false }).verify(permit, { tool: "db.read", input: { q: 2 } }); }
catch (e) { other = e.code; }
console.log(JSON.stringify({ agentId: p.agentId, tool: p.tool, other }));
"""


@pytest.mark.asyncio
async def test_a_permit_of_this_server_verifies_in_js(client, admin_token, db_session):
    from app.models.agent import Agent as AgentRow
    from app.models.organization import Organization

    agent = await enroll(client, admin_token, name="js-permit", capabilities=("read",), allowed_tools=("db.read",))
    data = {"q": "select 1", "text": "héllo 😀", "n": 1e-7}
    r = await client.post("/api/v1/agents/actions/check", json={
        "agent_id": agent["id"], "action_type": "tool_call", "tool_name": "db.read", "input": data,
    }, headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200 and r.json()["permit"], r.text
    org_id = (await db_session.get(AgentRow, agent["id"])).org_id
    org = (await db_session.get(Organization, org_id)).slug
    jwks = (await client.get(f"/api/v1/pvp/permits/{org}/jwks.json")).json()
    out = json.loads(_node(VERIFY_PERMIT, json.dumps({"permit": r.json()["permit"], "jwks": jwks, "org": org,
                                                      "input": data})))
    assert out == {"agentId": agent["id"], "tool": "db.read", "other": "permit.mismatch"}
