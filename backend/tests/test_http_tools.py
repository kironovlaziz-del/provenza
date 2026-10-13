# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
HTTP tool gateway (app/pvp/http_tools.py): the agent names a tool and its
arguments; Provenza checks, calls the API with the credential it holds, and
records - in one operation. A real HTTP server on 127.0.0.1 plays the API.
"""

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.agent_action import AgentAction
from app.models.http_tool import HttpTool
from app.models.tool_registry import ToolRegistryEntry
from app.pvp import permits
from tests.conftest import auth_headers

T = "/api/v1/http-tools"
SECRET = "Bearer crm-secret-" + "x" * 16


class _Api:
    def __init__(self):
        self.calls = []
        self.reply = (200, {"ok": True, "customer": {"tier": "gold"}})
        outer = self

        class H(BaseHTTPRequestHandler):
            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.calls.append({"method": self.command, "path": self.path, "headers": dict(self.headers),
                                    "body": self.rfile.read(n) if n else b""})
                code, body = outer.reply
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                if code in (301, 302):
                    self.send_header("Location", "http://169.254.169.254/")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "127.0.0.1")
    a = _Api()
    yield a
    a.close()


SCHEMA = {"type": "object", "required": ["id", "tier"], "additionalProperties": False,
          "properties": {"id": {"type": "string"}, "tier": {"type": "string", "enum": ["gold", "silver"]}}}


async def _tool(client, token, api, **over):
    body = {"name": "crm.set_tier", "method": "PATCH", "url": api.base + "/customers/{id}", "input_schema": SCHEMA,
            "auth_secret": SECRET, "description": "Set a customer's tier", **over}
    r = await client.post(T, json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _agent(client, token, tools=("crm.set_tier",)):
    r = await client.post("/api/v1/agents/register", json={
        "name": "ht-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": [],
        "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 1,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _call(client, agent, tool="crm.set_tier", args=None, sign=True):
    headers = {"X-Agent-Key": agent["api_key"]}
    body = {"agent_id": agent["id"], "tool_name": tool, "input": args if args is not None else {"id": "c/42", "tier": "gold"}}
    if sign:
        body = client._signed(body, headers)
    return await client.post(f"{T}/call", json=body, headers=headers)


@pytest.mark.asyncio
async def test_the_agent_calls_through_provenza_and_never_sees_the_key(client, admin_token, db_session, api):
    tool = await _tool(client, admin_token, api)
    assert tool["has_secret"] and "secret" not in json.dumps(tool).lower().replace("has_secret", "")
    entry = (await db_session.execute(select(ToolRegistryEntry).where(
        ToolRegistryEntry.id == tool["registry_entry_id"]))).scalar_one()
    assert entry.status == "approved" and entry.pinned_digest == tool["digest"]

    agent = await _agent(client, admin_token)
    listed = (await client.get(f"{T}/available", headers={"X-Agent-Key": agent["api_key"]})).json()["tools"]
    assert listed == [{"name": "crm.set_tier", "description": "Set a customer's tier", "method": "PATCH",
                       "input_schema": SCHEMA}]

    r = await _call(client, agent)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["decision"] == "allowed" and out["status"] == 200 and out["body"]["customer"]["tier"] == "gold"
    sent = api.calls[-1]
    assert sent["method"] == "PATCH" and sent["path"] == "/customers/c%2F42"       # one encoded path segment
    assert sent["headers"]["Authorization"] == SECRET                              # injected here
    assert json.loads(sent["body"]) == {"id": "c/42", "tier": "gold"}
    assert "X-Agent-Key" not in sent["headers"]
    # the permit goes along, for exactly this call - an API behind provenza.permit accepts it
    claims = json.loads(permits._unb64url(sent["headers"][permits.HEADER].split(".")[1]))
    assert claims["aud"] == "crm.set_tier" and claims["sub"] == f"agent:{agent['id']}"

    action = await db_session.get(AgentAction, out["action_id"])
    assert action.executed_by == "http_gateway" and action.policy_check_result == "allowed"
    assert action.output_data["status"] == 200


@pytest.mark.asyncio
async def test_unsigned_or_foreign_calls_are_refused(client, admin_token, api):
    await _tool(client, admin_token, api)
    agent = await _agent(client, admin_token)
    other = await _agent(client, admin_token)
    r = await _call(client, agent, sign=False)
    assert r.status_code == 422                                  # a signed request is required
    body = client._signed({"agent_id": other["id"], "tool_name": "crm.set_tier",
                           "input": {"id": "1", "tier": "gold"}}, {"X-Agent-Key": other["api_key"]})
    r = await client.post(f"{T}/call", json=body, headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 403 and "agent_mismatch" in r.json()["detail"]
    good = client._signed({"agent_id": agent["id"], "tool_name": "crm.set_tier",
                           "input": {"id": "1", "tier": "gold"}}, {"X-Agent-Key": agent["api_key"]})
    assert (await client.post(f"{T}/call", json=good, headers={"X-Agent-Key": agent["api_key"]})).status_code == 200
    r = await client.post(f"{T}/call", json=good, headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 409 and r.json()["detail"] == "action.replayed_request"
    assert len(api.calls) == 1


@pytest.mark.asyncio
async def test_denied_and_bad_arguments_are_recorded_and_not_sent(client, admin_token, db_session, api):
    await _tool(client, admin_token, api)
    no_right = await _agent(client, admin_token, tools=())
    out = (await _call(client, no_right)).json()
    assert out["decision"] == "denied" and out["action_id"]
    agent = await _agent(client, admin_token)
    for args in ({"id": "1"}, {"id": "1", "tier": "platinum"}, {"id": "1", "tier": "gold", "admin": True},
                 {"id": "..", "tier": "gold"}, {"id": 1.5, "tier": "gold"}):
        out = (await _call(client, agent, args=args)).json()
        assert out["decision"] == "denied" and "arguments refused" in out["reason"], (args, out)
        assert (await db_session.get(AgentAction, out["action_id"])).executed_by == "http_gateway"
    assert api.calls == []
    r = await _call(client, agent, tool="crm.unknown")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_query_redirects_errors_and_oversized_answers(client, admin_token, api):
    await _tool(client, admin_token, api, name="crm.find", method="GET", url=api.base + "/customers",
                input_schema={"type": "object", "properties": {"q": {"type": "string"}, "tags": {"type": "array"}}},
                max_response_bytes=1024)
    agent = await _agent(client, admin_token, tools=("crm.find",))
    out = (await _call(client, agent, tool="crm.find", args={"q": "acme", "tags": ["a", "b"]})).json()
    assert out["status"] == 200 and api.calls[-1]["path"] == "/customers?q=acme&tags=a&tags=b"
    assert permits.HEADER not in api.calls[-1]["headers"]     # no body: the permit could not match the input
    api.reply = (302, {})
    out = (await _call(client, agent, tool="crm.find", args={"q": "x"})).json()
    assert out["error"] == "redirects are not followed" and "body" not in out
    api.reply = (500, {"error": {"message": "db down"}})
    out = (await _call(client, agent, tool="crm.find", args={"q": "x"})).json()
    assert out["status"] == 500 and out["error"] == "500: db down"
    api.reply = (200, {"blob": "x" * 5000})
    out = (await _call(client, agent, tool="crm.find", args={"q": "x"})).json()
    assert out["withheld"] == ["response_too_large"] and "body" not in out


@pytest.mark.asyncio
async def test_admin_rules(client, admin_token, approver_token, db_session, api):
    body = {"name": "crm.x", "method": "POST", "url": api.base + "/x"}
    assert (await client.post(T, json=body, headers=auth_headers(approver_token))).status_code == 403
    for bad in ({"url": "http://169.254.169.254/latest"}, {"auth_header": "Host"}, {"name": "Bad Name"},
                {"method": "TRACE"}, {"input_schema": {"type": "array"}}):
        assert (await client.post(T, json={**body, **bad}, headers=auth_headers(admin_token))).status_code == 422, bad
    r = await client.post(T, json={**body, "url": api.base + "/c/{id}", "input_schema": {"type": "object"}},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "http_tool.placeholder_undeclared"

    tool = await _tool(client, admin_token, api)
    assert (await client.post(T, json={**body, "name": "crm.set_tier"},
                              headers=auth_headers(admin_token))).status_code == 409
    # a changed definition is re-pinned by the admin who changed it, and audited
    r = await client.patch(f"{T}/{tool['id']}", json={"url": api.base + "/v2/customers/{id}"},
                           headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["digest"] != tool["digest"]
    entry = await db_session.get(ToolRegistryEntry, tool["registry_entry_id"])
    await db_session.refresh(entry)
    assert entry.pinned_digest == r.json()["digest"] and entry.status == "approved"
    assert (await client.delete(f"{T}/{tool['id']}", headers=auth_headers(admin_token))).json() == {"disabled": True}
    agent = await _agent(client, admin_token)
    assert (await _call(client, agent)).status_code == 404
    row = await db_session.get(HttpTool, tool["id"])
    await db_session.refresh(row)
    assert row.enabled is False and row.auth_secret_encrypted and SECRET not in row.auth_secret_encrypted
