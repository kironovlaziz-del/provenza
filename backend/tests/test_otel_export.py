# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
OpenTelemetry export of PVP decisions (app/services/otel_export.py) and the
callers' W3C trace context (app/core/trace_context.py): settings an
administrator changes only after the collector took a test record, the
header kept encrypted and never shown, metadata only in every record, the
agent's trace and span on its decisions, a collector that is down losing
nothing, a malformed batch dropped as OTLP says, the past never replayed,
other organizations never sent.
"""

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from sqlalchemy import select

from app.core import trace_context
from app.core.config import settings
from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.audit_log import AIAuditLog
from app.models.delegation import DelegationHop
from app.models.gateway import GatewayCall
from app.models.organization import Organization
from app.models.otel_export import OtelExportSettings
from app.services import otel_export
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body
from tests.test_gateway import _chat, _cleanup_route, _setup, msgs
from tests.test_gateway import fake as fake_provider  # noqa: F401 - fixture
from tests.test_mcp_gateway import _call, _ready
from tests.test_mcp_gateway import fake  # noqa: F401 - fixture

O = "/api/v1/otel-export"
CHECK = "/api/v1/agents/actions/check"
SECRET = "jane.doe@example.com"
TOKEN = "otlp-token-" + "x" * 20
TRACE, SPAN = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
TRACEPARENT = f"00-{TRACE}-{SPAN}-01"


class FakeCollector:
    """An OTLP/HTTP logs receiver: keeps every request; answers as told."""

    def __init__(self):
        self.requests, self.mode = [], "ok"      # ok | down | bad | auth | partial
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                code, doc = {"ok": (200, {}), "down": (503, {"message": "down"}),
                             "bad": (400, {"message": "bad data"}), "auth": (401, {"message": "no"}),
                             "partial": (200, {"partialSuccess": {"rejectedLogRecords": "2",
                                                                  "errorMessage": "too old"}})}[outer.mode]
                out = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def records(self, since: int = 0):
        out = []
        for _, _, body in self.requests[since:]:
            for rl in body["resourceLogs"]:
                for sl in rl["scopeLogs"]:
                    out += sl["logRecords"]
        return out

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def collector(monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "127.0.0.1")
    monkeypatch.setattr(otel_export, "LAG_SECONDS", 0)
    server = FakeCollector()
    yield server
    server.close()


def attrs(rec) -> dict:
    out = {}
    for a in rec["attributes"]:
        v = a["value"]
        if "arrayValue" in v:
            out[a["key"]] = [next(iter(x.values())) for x in v["arrayValue"]["values"]]
        else:
            out[a["key"]] = next(iter(v.values()))
    return out


def _code(r) -> str:
    detail = r.json()["detail"]
    return detail if isinstance(detail, str) else detail["code"]


async def _agent(client, token, tools=("db.read",)):
    r = await client.post("/api/v1/agents/register",
                          json={"name": "otel-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
                                "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 1},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _check(client, token, agent, tool, data=None, headers=None):
    r = await client.post(CHECK, json={"agent_id": agent["id"], "chain_id": None, "tool_name": tool,
                                       "input": data or {}}, headers={**auth_headers(token), **(headers or {})})
    assert r.status_code == 200, r.text
    return r.json()


async def _enable(client, token, collector, **over):
    body = {"enabled": True, "endpoint": collector.url, "header_name": "Authorization",
            "header_value": "Bearer " + TOKEN, **over}
    return await client.put(O + "/", json=body, headers=auth_headers(token))


async def _org_id(db, agent) -> int:
    return (await db.get(Agent, agent["id"])).org_id


# ----------------------------------------------------------------------------- trace context

class TestTraceContext:
    @pytest.mark.parametrize("value,expected", [
        (TRACEPARENT, (TRACE, SPAN)),
        (f"00-{TRACE}-{SPAN}-00", (TRACE, SPAN)),                 # not sampled: still the caller's trace
        (f"  {TRACEPARENT} ", (TRACE, SPAN)),
        (f"01-{TRACE}-{SPAN}-01-future", (TRACE, SPAN)),         # a later version may carry more
        (f"00-{TRACE}-{SPAN}-01-more", None),                    # version 00 may not
        (f"ff-{TRACE}-{SPAN}-01", None),
        (f"00-{TRACE.upper()}-{SPAN}-01", None),
        (f"00-{'0' * 32}-{SPAN}-01", None),
        (f"00-{TRACE}-{'0' * 16}-01", None),
        (f"00-{TRACE[:-1]}-{SPAN}-01", None),
        ("00-" + "a" * 600, None),
        ("", None), (None, None), (42, None),
    ])
    def test_parse(self, value, expected):
        assert trace_context.parse(value) == expected

    @pytest.mark.asyncio
    async def test_a_check_keeps_the_callers_trace(self, client, admin_token, db_session):
        agent = await _agent(client, admin_token)
        await _check(client, admin_token, agent, "db.read", headers={"traceparent": TRACEPARENT})
        await _check(client, admin_token, agent, "db.read", headers={"traceparent": "00-not-a-trace-01"})
        await _check(client, admin_token, agent, "db.read")
        rows = (await db_session.execute(select(ActionCheck).where(ActionCheck.agent_id == agent["id"])
                                         .order_by(ActionCheck.id))).scalars().all()
        assert [(r.trace_id, r.span_id) for r in rows] == [(TRACE, SPAN), (None, None), (None, None)]
        assert trace_context.current() is None              # nothing leaks out of a request

    @pytest.mark.asyncio
    async def test_a_recorded_action_keeps_its_own_trace_or_its_checks(self, client, admin_token, db_session):
        agent = await _agent(client, admin_token)
        other = "00-" + "3" * 32 + "-" + "4" * 16 + "-01"
        for header, expected in (({}, (TRACE, SPAN)), ({"traceparent": other}, ("3" * 32, "4" * 16))):
            chk = await _check(client, admin_token, agent, "db.read", {"q": 1}, headers={"traceparent": TRACEPARENT})
            r = await client.post("/api/v1/agents/actions/record",
                                  json=action_record_body(agent, chk["check_id"], "db.read", {"q": 1}),
                                  headers={**auth_headers(admin_token), **header})
            assert r.status_code == 200, r.text
            action = await db_session.get(AgentAction, r.json()["id"])
            await db_session.refresh(action)
            assert (action.trace_id, action.span_id) == expected

    @pytest.mark.asyncio
    async def test_mcp_meta_traceparent_wins_over_the_header(self, client, admin_token, db_session, fake):
        _, agent = await _ready(client, admin_token, fake)
        other = "00-" + "1" * 32 + "-" + "2" * 16 + "-01"
        r = await _call(client, agent, "tools/call",
                        {"name": "files.read", "arguments": {"path": "a.txt"}, "_meta": {"traceparent": TRACEPARENT}},
                        headers={"traceparent": other})
        assert r.status_code == 200, r.text
        r = await _call(client, agent, "tools/call", {"name": "files.read", "arguments": {"path": "b.txt"}},
                        headers={"traceparent": other})
        assert r.status_code == 200, r.text
        checks = (await db_session.execute(select(ActionCheck).where(ActionCheck.agent_id == agent["id"])
                                           .order_by(ActionCheck.id))).scalars().all()
        actions = (await db_session.execute(select(AgentAction).where(AgentAction.agent_id == agent["id"])
                                            .order_by(AgentAction.id))).scalars().all()
        assert [c.trace_id for c in checks] == [TRACE, "1" * 32]
        assert [(a.trace_id, a.span_id) for a in actions] == [(TRACE, SPAN), ("1" * 32, "2" * 16)]

    @pytest.mark.asyncio
    async def test_an_llm_call_keeps_the_callers_trace(self, client, admin_token, db_session, fake_provider):
        a, _, rid = await _setup(client, admin_token, db_session)
        try:
            r = await _chat(client, a, msgs(("user", "hi")), headers_extra={"traceparent": TRACEPARENT})
            assert r.status_code == 200, r.text
            call = await db_session.get(GatewayCall, r.json()["provenza"]["call_id"])
            assert (call.trace_id, call.span_id) == (TRACE, SPAN)
        finally:
            await _cleanup_route(client, admin_token, rid)


# ----------------------------------------------------------------------------- the records

class TestRecords:
    def test_metadata_only_with_pvp_and_genai_attributes(self):
        check = ActionCheck(id=2, org_id=7, agent_id=3, action_type="tool_call", tool_name="stripe.charge",
                            decision="denied", reason=f"ASI02 refused for {SECRET}", input_sha256="0" * 64,
                            incident_type="policy_violation", policy_id=11, trace_id=TRACE, span_id=SPAN)
        ev = otel_export.obs_hooks.to_event(check)[1]
        rec = otel_export.record("action.checked", ev, check, {3: "refund-bot"})
        a = attrs(rec)
        assert rec["eventName"] == "pvp.action.checked" and rec["severityText"] == "WARN"
        assert (rec["traceId"], rec["spanId"]) == (TRACE, SPAN)
        assert a["pvp.decision"] == "denied" and a["pvp.event.type"] == "action.checked" and a["pvp.event.id"] == "2"
        assert a["gen_ai.operation.name"] == "execute_tool" and a["gen_ai.tool.name"] == "stripe.charge"
        assert a["gen_ai.agent.id"] == "3" and a["gen_ai.agent.name"] == "refund-bot"
        assert a["pvp.guards"] == ["ASI02"] and a["pvp.policy.id"] == "11" and a["pvp.incident.type"] == "policy_violation"
        assert SECRET not in json.dumps(rec) and "reason" not in json.dumps(a)

    def test_llm_delegation_and_incident(self):
        g = GatewayCall(id=4, org_id=7, agent_id=3, model="gpt-4o", status="rate_limited", reason=SECRET,
                        flags=["output:asi01"], latency_ms=812, prompt_tokens=345, completion_tokens=120)
        a = attrs(otel_export.record("llm.call", otel_export.obs_hooks.to_event(g)[1], g, {}))
        assert a["gen_ai.operation.name"] == "chat" and a["gen_ai.request.model"] == "gpt-4o"
        assert a["gen_ai.usage.input_tokens"] == "345" and a["gen_ai.usage.output_tokens"] == "120"
        assert a["pvp.llm.status"] == "rate_limited" and SECRET not in json.dumps(a)

        h = DelegationHop(id=6, org_id=7, chain_id=1, from_agent_id=3, to_agent_id=4, depth=1,
                          delegated_capabilities=["read"], task_description=SECRET, verified=True)
        rec = otel_export.record("delegation.hop", otel_export.obs_hooks.to_event(h)[1], h, {3: "a", 4: "b"})
        a = attrs(rec)
        assert a["gen_ai.agent.name"] == "a" and a["pvp.delegation.to_agent.name"] == "b"
        assert a["pvp.delegation.capabilities"] == ["read"] and a["pvp.delegation.verified"] is True
        assert SECRET not in json.dumps(rec) and "traceId" not in rec

        i = AgentIncident(id=1, org_id=7, agent_id=3, incident_type="capability_escalation", severity="critical",
                          details={"reason": SECRET})
        rec = otel_export.record("incident.created", otel_export.obs_hooks.to_event(i)[1], i, {})
        assert rec["severityNumber"] == otel_export.ERROR and attrs(rec)["pvp.incident.severity"] == "critical"
        assert SECRET not in json.dumps(rec)

    def test_payload_shape(self):
        body = otel_export.payload(5, [])
        res = attrs(body["resourceLogs"][0]["resource"])
        assert res["service.name"] == "provenza" and res["provenza.org.id"] == "5"
        assert body["resourceLogs"][0]["scopeLogs"][0]["scope"]["name"] == "provenza.pvp"

    @pytest.mark.parametrize("endpoint,expected", [
        ("https://otel.example.com", "https://otel.example.com/v1/logs"),
        ("https://otel.example.com/", "https://otel.example.com/v1/logs"),
        ("https://api.honeycomb.io/v1/logs", "https://api.honeycomb.io/v1/logs"),
        ("https://gw.example.com/otlp", "https://gw.example.com/otlp/v1/logs"),
    ])
    def test_logs_url(self, endpoint, expected):
        assert otel_export.logs_url(endpoint) == expected


# ----------------------------------------------------------------------------- settings

@pytest.mark.asyncio
async def test_settings_are_for_admins_and_off_by_default(client, admin_token, approver_token):
    r = await client.get(O + "/", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["endpoint"] is None
    for call in (client.get(O + "/", headers=auth_headers(approver_token)),
                 client.put(O + "/", json={"enabled": False}, headers=auth_headers(approver_token)),
                 client.post(O + "/test", headers=auth_headers(approver_token))):
        assert (await call).status_code == 403


@pytest.mark.asyncio
async def test_switched_on_after_a_test_record_header_never_shown(client, admin_token, collector, db_session):
    r = await _enable(client, admin_token, collector)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["enabled"] is True and out["header_name"] == "Authorization" and out["header_set"] is True
    assert out["logs_url"] == collector.url + "/v1/logs" and out["outbound_host"] == "127.0.0.1"
    assert TOKEN not in r.text
    path, headers, body = collector.requests[-1]
    assert path == "/v1/logs" and headers["authorization"] == "Bearer " + TOKEN
    assert headers["content-type"] == "application/json"
    assert collector.records()[-1]["eventName"] == "pvp.test"

    row = (await db_session.execute(select(OtelExportSettings))).scalar_one()
    assert TOKEN not in (row.header_value_enc or "")                     # stored encrypted
    assert TOKEN not in (await client.get(O + "/", headers=auth_headers(admin_token))).text
    log = (await db_session.execute(select(AIAuditLog).where(AIAuditLog.entity_type == "otel_export"))).scalars().all()
    assert log and log[-1].action == "configured" and TOKEN not in json.dumps(log[-1].metadata_json, default=str)

    # the stored value is kept when only the name is sent again, and used for /test
    r = await client.put(O + "/", json={"enabled": True, "endpoint": collector.url, "header_name": "Authorization"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert collector.requests[-1][1]["authorization"] == "Bearer " + TOKEN
    r = await client.post(O + "/test", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["ok"] is True
    assert collector.requests[-1][1]["authorization"] == "Bearer " + TOKEN

    # a different header name needs its value
    r = await client.put(O + "/", json={"enabled": True, "endpoint": collector.url, "header_name": "x-honeycomb-team"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 422 and _code(r) == "otel.no_header_value"


@pytest.mark.asyncio
async def test_settings_are_checked(client, admin_token, collector, monkeypatch):
    for body, code in (
        ({"endpoint": "http://otel.example.com:4318"}, "otel.https_required"),
        ({"endpoint": "ftp://otel.example.com"}, "otel.bad_url"),
        ({"endpoint": "https://otel.example.com/?a=1"}, "otel.bad_url"),
        ({"endpoint": "https://169.254.169.254"}, "otel.bad_url"),
        ({"endpoint": None}, "otel.no_endpoint"),
        ({"header_name": "Content-Type"}, "otel.bad_header_name"),
        ({"header_name": "bad header"}, "otel.bad_header_name"),
        ({"header_value": "a\nb"}, "otel.bad_header_value"),
    ):
        r = await _enable(client, admin_token, collector, **body)
        assert r.status_code == 422 and _code(r) == code, (body, r.text)
    assert collector.requests == []

    collector.mode = "auth"
    r = await _enable(client, admin_token, collector)
    assert r.status_code == 422 and _code(r) == "otel.http_error" and "401" in r.text
    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "")
    collector.mode = "ok"
    r = await _enable(client, admin_token, collector)          # a private address no longer allowed
    assert r.status_code == 422 and _code(r) == "otel.bad_url"
    r = await client.get(O + "/", headers=auth_headers(admin_token))
    assert r.json()["enabled"] is False and r.json()["endpoint"] is None          # nothing was saved


@pytest.mark.asyncio
async def test_switching_off_always_works(client, admin_token, collector, monkeypatch):
    assert (await _enable(client, admin_token, collector)).status_code == 200
    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "")     # the stored endpoint is no longer allowed
    r = await client.put(O + "/", json={"enabled": False, "endpoint": collector.url, "header_name": "Authorization"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["enabled"] is False
    r = await client.put(O + "/", json={"enabled": False}, headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["header_set"] is False         # no name: the header is removed


# ----------------------------------------------------------------------------- the export

@pytest.mark.asyncio
async def test_new_decisions_are_sent_once_and_the_past_is_not(client, admin_token, collector, db_session):
    agent = await _agent(client, admin_token)
    org_id = await _org_id(db_session, agent)
    await _check(client, admin_token, agent, "db.read")                         # before: not sent
    assert (await _enable(client, admin_token, collector)).status_code == 200
    await _check(client, admin_token, agent, "db.read", headers={"traceparent": TRACEPARENT})
    await _check(client, admin_token, agent, "stripe.charge", {"email": SECRET})

    n = len(collector.requests)
    out = await otel_export.export_org(db_session, org_id)
    assert out == {"sent": 2}, out
    recs = collector.records(n)
    assert [attrs(r)["pvp.decision"] for r in recs] == ["allowed", "denied"]
    assert recs[0]["traceId"] == TRACE and "traceId" not in recs[1]
    assert attrs(recs[1])["gen_ai.tool.name"] == "stripe.charge" and attrs(recs[1])["gen_ai.agent.name"] == agent["name"]
    assert SECRET not in json.dumps(collector.requests[n:])
    assert collector.requests[-1][1]["authorization"] == "Bearer " + TOKEN

    assert await otel_export.export_org(db_session, org_id) == {"sent": 0}        # nothing new
    assert len(collector.requests) == n + 1
    st = (await client.get(O + "/", headers=auth_headers(admin_token))).json()
    assert st["exported_total"] == 2 and st["last_success_at"] and st["last_error"] is None


@pytest.mark.asyncio
async def test_a_collector_that_is_down_loses_nothing(client, admin_token, collector, db_session):
    agent = await _agent(client, admin_token)
    org_id = await _org_id(db_session, agent)
    assert (await _enable(client, admin_token, collector)).status_code == 200
    await _check(client, admin_token, agent, "db.read")
    for mode in ("down", "auth"):
        collector.mode = mode
        out = await otel_export.export_org(db_session, org_id)
        assert out["failed"] == "otel.http_error"
        st = (await client.get(O + "/", headers=auth_headers(admin_token))).json()
        assert st["last_error"] and st["last_error_at"] and st["exported_total"] == 0
    collector.mode = "ok"
    n = len(collector.requests)
    assert await otel_export.export_org(db_session, org_id) == {"sent": 1}
    assert len(collector.records(n)) == 1
    assert (await client.get(O + "/", headers=auth_headers(admin_token))).json()["last_error"] is None


@pytest.mark.asyncio
async def test_a_malformed_batch_is_dropped_not_retried(client, admin_token, collector, db_session):
    agent = await _agent(client, admin_token)
    org_id = await _org_id(db_session, agent)
    assert (await _enable(client, admin_token, collector)).status_code == 200
    await _check(client, admin_token, agent, "db.read")
    collector.mode = "bad"
    assert (await otel_export.export_org(db_session, org_id))["failed"] == "otel.http_error"
    collector.mode = "ok"
    assert await otel_export.export_org(db_session, org_id) == {"sent": 0}       # the batch was dropped

    collector.mode = "partial"
    await _check(client, admin_token, agent, "db.read")
    assert await otel_export.export_org(db_session, org_id) == {"sent": 1}
    assert "2 records rejected" in (await client.get(O + "/", headers=auth_headers(admin_token))).json()["last_error"]


@pytest.mark.asyncio
async def test_switched_off_sends_nothing(client, admin_token, collector, db_session):
    agent = await _agent(client, admin_token)
    org_id = await _org_id(db_session, agent)
    assert (await _enable(client, admin_token, collector)).status_code == 200
    r = await client.put(O + "/", json={"enabled": False}, headers=auth_headers(admin_token))
    assert r.status_code == 200
    await _check(client, admin_token, agent, "db.read")
    n = len(collector.requests)
    assert await otel_export.export_org(db_session, org_id) == {"skipped": "off"}
    assert len(collector.requests) == n


@pytest.mark.asyncio
async def test_other_organizations_are_never_sent(client, admin_token, collector, db_session):
    agent = await _agent(client, admin_token)
    org_id = await _org_id(db_session, agent)
    assert (await _enable(client, admin_token, collector)).status_code == 200
    other = Organization(name="Other", slug="other-" + secrets.token_hex(3))
    db_session.add(other)
    await db_session.flush()
    stranger = Agent(org_id=other.id, name="stranger", agent_type="custom", capabilities=[], allowed_tools=[],
                     allowed_models=[], max_delegation_depth=1, status="active",
                     api_key_hash=secrets.token_hex(32))
    db_session.add(stranger)
    await db_session.flush()
    db_session.add(ActionCheck(token=secrets.token_hex(16), org_id=other.id, agent_id=stranger.id,
                               tool_name="secret.tool", input_sha256="0" * 64, decision="allowed",
                               expires_at=otel_export._now()))
    await db_session.commit()
    await _check(client, admin_token, agent, "db.read")
    n = len(collector.requests)
    assert await otel_export.export_org(db_session, org_id) == {"sent": 1}
    assert "secret.tool" not in json.dumps(collector.requests[n:]) and "stranger" not in json.dumps(collector.requests[n:])


@pytest.mark.asyncio
async def test_a_run_under_an_older_configuration_keeps_its_hands_off(client, admin_token, collector, db_session):
    agent = await _agent(client, admin_token)
    org_id = await _org_id(db_session, agent)
    assert (await _enable(client, admin_token, collector)).status_code == 200
    row = await otel_export.get_settings(db_session, org_id)
    before = dict(row.cursors)
    out = await otel_export._note(db_session, org_id, row.config_rev - 1, cursors={k: 10**9 for k in before}, sent=5)
    assert out == {"skipped": "changed"}
    row = await otel_export.get_settings(db_session, org_id)
    await db_session.refresh(row)
    assert row.cursors == before and row.exported_total == 0


@pytest.mark.asyncio
async def test_the_scheduler_runs_every_organization_switched_on(client, admin_token, collector, db_session):
    agent = await _agent(client, admin_token)
    assert (await _enable(client, admin_token, collector)).status_code == 200
    await _check(client, admin_token, agent, "db.read")
    out = await otel_export.export_all(db_session)
    assert out["sent"] == 1 and out["failed"] == 0
