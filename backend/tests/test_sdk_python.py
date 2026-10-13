# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The Python SDK (sdk/python) against this server - not a fake.

The agent is enrolled the way tools/provenza_sign.py enrolls (keys made on
the agent's side), its identity file is written in the CLI's format, and the
SDK takes it from there: governed async tools, a denied tool, and a receipt
that the standalone verifier accepts for the agent's own key fingerprint.
"""

import importlib.util
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport

from app.main import app
from tests.conftest import auth_headers
from tests.enrollment_helpers import enroll

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from provenza import Agent, ProvenzaDenied  # noqa: E402
from provenza import identity as ids  # noqa: E402
from provenza.crypto import Keys  # noqa: E402

_spec = importlib.util.spec_from_file_location("provenza_audit_tool_sdk", ROOT / "tools" / "provenza_audit.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


async def _sdk_agent(client, admin_token, tmp_path):
    enrolled = await enroll(client, admin_token, name="sdk-bot", capabilities=("read",), allowed_tools=("db.read",))
    path = tmp_path / "sdk-bot.json"
    ids.save(ids.Identity(keys=Keys(enrolled["private_key"], enrolled["public_key"]), server="http://test",
                          agent_id=enrolled["id"], api_key=enrolled["api_key"], name="sdk-bot"), path)
    return Agent("sdk-bot", server_url="http://test", identity_path=str(path),
                 async_transport=ASGITransport(app=app))


@pytest.mark.asyncio
async def test_sdk_governs_records_and_proves(client, admin_token, tmp_path):
    agent = await _sdk_agent(client, admin_token, tmp_path)

    @agent.tool(name="db.read")
    async def read(query: str) -> dict:
        return {"rows": 2, "query": query}

    @agent.tool(name="stripe.charge")
    async def charge(amount: int) -> dict:
        raise AssertionError("a denied tool must not run")

    assert await read("select 1") == {"rows": 2, "query": "select 1"}
    with pytest.raises(ProvenzaDenied) as denied:
        await charge(100)
    assert denied.value.action_id is not None          # the refused attempt is on record

    actions = (await client.get("/api/v1/agents/actions/", params={"agent_id": agent.agent_id},
                                headers=auth_headers(admin_token))).json()["items"]
    by_tool = {a["tool_name"]: a for a in actions}
    assert by_tool["db.read"]["policy_check_result"] == "allowed" and by_tool["db.read"]["signature"]
    assert by_tool["stripe.charge"]["policy_check_result"] == "denied"

    receipt = (await client.get(f"/api/v1/pvp/receipts/{by_tool['db.read']['id']}",
                                headers=auth_headers(admin_token))).json()
    # the auditor checks the signature against the fingerprint the agent's owner holds
    action, _, _ = tool.check_receipt(receipt, tool.Trust(), agent.fingerprint)
    assert action["tool_name"] == "db.read"
    await agent.aclose()


@pytest.mark.asyncio
async def test_sdk_permit_from_this_server_runs_the_tool_once(client, admin_token, tmp_path, db_session):
    """The agent's check carries a permit; the tool's verifier (provenza.permit)
    takes the JWKS from this server, verifies it, and redeems it here - once."""
    from app.models.agent import Agent as AgentRow
    from app.models.organization import Organization
    from provenza.permit import PermitError, PermitVerifier

    agent = await _sdk_agent(client, admin_token, tmp_path)
    payload = {"query": "select 1"}
    chk = await agent.acheck("db.read", payload)
    assert chk.allowed and chk.permit
    org_id = (await db_session.get(AgentRow, agent.agent_id)).org_id
    slug = (await db_session.get(Organization, org_id)).slug
    verifier = PermitVerifier("http://test", slug, async_transport=ASGITransport(app=app))
    permit = await verifier.averify(chk.permit_headers["Provenza-Permit"], tool="db.read", input=payload)
    assert permit.redeemed and permit.agent_id == agent.agent_id
    with pytest.raises(PermitError) as e:
        await verifier.averify(chk.permit, tool="db.read", input=payload)
    assert e.value.code == "permit.redeemed"
    await agent.arecord(chk, {"rows": 1})


@pytest.mark.asyncio
async def test_sdk_invokes_an_http_tool_through_provenza(client, admin_token, tmp_path, monkeypatch):
    """agent.ainvoke: one signed request; this server checks, calls the API with
    the key it holds, records. The agent holds no credential of the API."""
    from app.core.config import settings
    from tests.test_http_tools import _Api

    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "127.0.0.1")
    api = _Api()
    try:
        r = await client.post("/api/v1/http-tools", json={
            "name": "db.read", "method": "POST", "url": api.base + "/query", "auth_secret": "Bearer db-key",
            "input_schema": {"type": "object", "required": ["query"], "properties": {"query": {"type": "string"}}},
        }, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        agent = await _sdk_agent(client, admin_token, tmp_path)
        out = await agent.ainvoke("db.read", {"query": "select 1"})
        assert out["status"] == 200 and out["body"]["ok"] is True and out["action_id"]
        assert api.calls[-1]["headers"]["Authorization"] == "Bearer db-key"
        with pytest.raises(ProvenzaDenied):
            await agent.ainvoke("db.read", {"query": 1})
        assert len(api.calls) == 1
    finally:
        api.close()


@pytest.mark.asyncio
async def test_sdk_egress_selfcheck(client, admin_token, tmp_path, monkeypatch):
    """agent.aegress_selfcheck against this server: a closed target -> confined;
    a target this host can reach -> open (and the server records it)."""
    import socket

    from app.core.config import settings

    agent = await _sdk_agent(client, admin_token, tmp_path)
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()                                         # nothing listens there
    monkeypatch.setattr(settings, "EGRESS_PROBE_TARGETS", f"127.0.0.1:{port}")
    out = await agent.aegress_selfcheck(timeout=1.0)
    assert out["verdict"] == "confined" and out["results"] == [{"target": f"127.0.0.1:{port}", "reachable": False}]

    listening = socket.socket()
    listening.bind(("127.0.0.1", 0))
    listening.listen(1)
    try:
        monkeypatch.setattr(settings, "EGRESS_PROBE_TARGETS", f"127.0.0.1:{listening.getsockname()[1]}")
        assert (await agent.aegress_selfcheck(timeout=1.0))["verdict"] == "open"
    finally:
        listening.close()
