"""
Real-time agent observability: events built from rows carry no personal
data, the after-commit hook publishes what agents do, server-side filters,
history from agent_events_v, aggregates and time series, the SSE stream with
100 ms batches, masked content, unmasked content only for admins.
"""

import json
import secrets

import pytest

from app.core import obs_bus, obs_hooks
from app.models.a2a import A2AMessage
from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.models.delegation import DelegationHop
from app.models.gateway import GatewayCall
from tests.conftest import auth_headers

O = "/api/v1/observability"
CHECK = "/api/v1/agents/actions/check"
SECRET = "jane.doe@example.com"


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register",
                          json={"name": "obs-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
                                "allowed_tools": ["db.read"], "allowed_models": [], "max_delegation_depth": 1},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _check(client, token, agent, tool, data=None):
    r = await client.post(CHECK, json={"agent_id": agent["id"], "chain_id": None, "tool_name": tool, "input": data or {}},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _sse(text):
    frames = []
    for raw in text.split("\n\n"):
        name, data = "message", []
        for line in raw.split("\n"):
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].strip())
        if data:
            frames.append((name, json.loads("\n".join(data))))
    return frames


class TestEventShape:
    def test_metadata_only(self):
        a = AgentAction(id=5, org_id=7, agent_id=3, chain_id=None, action_type="tool_call", tool_name="db.read",
                        input_data={"email": SECRET}, output_data={"rows": [SECRET]}, policy_check_result="allowed",
                        reason=f"ok | ASI05 monitor: shell `{SECRET}` | ASI01 x", duration_ms=42, check_id=9)
        org, ev = obs_hooks.to_event(a)
        assert org == 7
        assert ev["type"] == "action.recorded" and ev["guards"] == ["ASI01", "ASI05"] and ev["has_check"] is True
        assert SECRET not in json.dumps(ev) and "reason" not in ev and "input" not in json.dumps(ev)

        i = AgentIncident(id=1, org_id=7, agent_id=3, incident_type="policy_violation", severity="critical",
                          details={"tool": "x", "reason": SECRET})
        assert SECRET not in json.dumps(obs_hooks.to_event(i)[1])
        c = ActionCheck(id=2, org_id=7, agent_id=3, tool_name="t", decision="denied", reason=SECRET, input_sha256="0" * 64)
        assert obs_hooks.to_event(c)[1]["decision"] == "denied"
        assert obs_hooks.to_event(object()) is None

    def test_llm_a2a_delegation_events(self):
        g = GatewayCall(id=4, org_id=7, agent_id=3, model="gpt-4o", status="completed", reason=None,
                        flags=["masked:email", "output:asi01"], latency_ms=812, prompt_tokens=345, completion_tokens=120)
        ev = obs_hooks.to_event(g)[1]
        assert ev["type"] == "llm.call" and ev["model"] == "gpt-4o" and ev["duration_ms"] == 812
        assert ev["prompt_tokens"] == 345 and ev["guards"] == ["ASI01"] and "masked:email" in ev["flags"]
        m = A2AMessage(id=5, org_id=7, from_agent_id=3, to_agent_id=4, message_type="task", status="quarantined",
                       reasons=[SECRET], findings=[])
        ev = obs_hooks.to_event(m)[1]
        assert ev["agent_id"] == 3 and ev["to_agent_id"] == 4 and ev["guards"] == ["ASI07"] and SECRET not in json.dumps(ev)
        h = DelegationHop(id=6, org_id=7, chain_id=1, from_agent_id=3, to_agent_id=4, depth=1,
                          delegated_capabilities=["read"], task_description=f"mail {SECRET}", verified=True)
        ev = obs_hooks.to_event(h)[1]
        assert ev["type"] == "delegation.hop" and ev["capabilities"] == ["read"] and SECRET not in json.dumps(ev)

    def test_matches(self):
        ev = {"type": "action.checked", "agent_id": 3}
        assert obs_hooks.matches(ev, None, None)
        assert obs_hooks.matches(ev, {3}, {"action.checked"})
        assert not obs_hooks.matches(ev, {4}, None)
        assert not obs_hooks.matches(ev, None, {"incident.created"})
        assert obs_hooks.matches({"type": "a2a.message", "agent_id": 3, "to_agent_id": 4}, {4}, None)


class TestPublishing:
    @pytest.mark.asyncio
    async def test_commit_publishes_without_arguments(self, client, admin_token, monkeypatch):
        sent = []
        monkeypatch.setattr(obs_bus, "publish", lambda org_id, events: sent.append((org_id, events)))
        agent = await _agent(client, admin_token)
        assert (await _check(client, admin_token, agent, "stripe.charge", {"email": SECRET}))["decision"] == "denied"
        mine = [e for _, evs in sent for e in evs if e.get("agent_id") == agent["id"]]
        checked = [e for e in mine if e["type"] == "action.checked"]
        assert checked and checked[-1]["decision"] == "denied" and checked[-1]["tool"] == "stripe.charge"
        assert SECRET not in json.dumps(sent)


class TestHistoryAndSummary:
    @pytest.mark.asyncio
    async def test_history_filters_and_summary(self, client, admin_token, approver_token):
        a, b = await _agent(client, admin_token), await _agent(client, admin_token)
        await _check(client, admin_token, a, "db.read")
        await _check(client, admin_token, a, "stripe.charge", {"email": SECRET})
        await _check(client, admin_token, b, "db.read")

        r = await client.get(O + "/events", params={"agent_id": str(a["id"])}, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        evs = r.json()
        assert evs and all(e["agent_id"] == a["id"] for e in evs)
        assert {e.get("decision") for e in evs if e["type"] == "action.checked"} >= {"allowed", "denied"}
        assert SECRET not in r.text

        both = (await client.get(O + "/events", params={"agent_id": f"{a['id']},{b['id']}", "event_types": "action.checked"},
                                 headers=auth_headers(admin_token))).json()
        assert {e["agent_id"] for e in both} == {a["id"], b["id"]} and {e["type"] for e in both} == {"action.checked"}

        for bad in ({"event_types": "action.deleted"}, {"agent_id": "x"}):
            assert (await client.get(O + "/events", params=bad, headers=auth_headers(admin_token))).status_code == 422

        s = (await client.get(O + "/summary", params={"minutes": 15}, headers=auth_headers(approver_token))).json()
        assert s["totals"]["decisions"] >= 3 and s["totals"]["denied"] >= 1
        row = next(x for x in s["agents"] if x["id"] == a["id"])
        assert row["decisions"] >= 2 and row["denied"] >= 1 and row["last_seen"] and row["name"] == a["name"]
        assert (await client.get(O + "/summary", params={"minutes": 7}, headers=auth_headers(admin_token))).status_code == 422

        ts = (await client.get(O + "/timeseries", params={"dim": "type", "minutes": 15},
                               headers=auth_headers(admin_token))).json()
        assert ts["bucket_seconds"] == 15 and len(ts["buckets"]) >= 60
        checked = next(x for x in ts["series"] if x["key"] == "action.checked")
        assert len(checked["values"]) == len(ts["buckets"]) and checked["total"] >= 3
        dec = (await client.get(O + "/timeseries", params={"dim": "decision", "agent_id": str(a["id"])},
                                headers=auth_headers(admin_token))).json()
        assert {x["key"] for x in dec["series"]} >= {"allowed", "denied"}
        bd = (await client.get(O + "/breakdown", params={"dim": "tool", "by": "decision"},
                               headers=auth_headers(admin_token))).json()
        assert any(r["key"] == "stripe.charge" and r["parts"].get("denied") for r in bd["rows"])
        for bad in ({"dim": "nope"}, {"metric": "nope"}, {"minutes": 7}):
            assert (await client.get(O + "/timeseries", params=bad, headers=auth_headers(admin_token))).status_code == 422

    @pytest.mark.asyncio
    async def test_requires_login(self, client):
        assert (await client.get(O + "/summary")).status_code in (401, 403)


class TestContent:
    @pytest.mark.asyncio
    async def test_masked_by_default_raw_only_for_admin(self, client, admin_token, approver_token, db_session):
        agent = await _agent(client, admin_token)
        org_id = (await db_session.get(Agent, agent["id"])).org_id
        row = AgentAction(org_id=org_id, agent_id=agent["id"], action_type="tool_call", tool_name="crm.lookup",
                          input_data={"customer": SECRET, "q": "orders"}, output_data={"rows": 2},
                          policy_check_result="allowed")
        db_session.add(row)
        await db_session.flush()
        action_id = row.id
        await db_session.commit()

        params = {"agent_id": str(agent["id"]), "event_types": "action.recorded", "detail": "true"}
        r = await client.get(O + "/events", params=params, headers=auth_headers(approver_token))
        assert r.status_code == 200, r.text
        ev = next(e for e in r.json() if e["id"] == action_id)
        assert ev["masked"] is True and SECRET not in r.text
        assert any(c["label"] == "input" and "orders" in c["text"] for c in ev["content"])

        body = {"type": "action.recorded", "id": action_id, "reason": "incident review"}
        assert (await client.post(O + "/reveal", json=body, headers=auth_headers(approver_token))).status_code == 403
        r = await client.post(O + "/reveal", json=body, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["masked"] is False and SECRET in r.text
        assert (await client.post(O + "/reveal", json={**body, "id": 99999999},
                                  headers=auth_headers(admin_token))).status_code == 404
        assert (await client.post(O + "/reveal", json={**body, "type": "nope"},
                                  headers=auth_headers(admin_token))).status_code == 422


class TestStream:
    @pytest.mark.asyncio
    async def test_server_side_filter_and_batching(self, client, admin_token, monkeypatch):
        async def fake_subscribe(org_id):
            for i, agent in enumerate((1, 2, 1, 1)):
                yield {"v": 1, "type": "action.checked" if i < 3 else "incident.created", "id": i, "agent_id": agent}

        monkeypatch.setattr(obs_bus, "subscribe", fake_subscribe)
        r = await client.get(O + "/stream", params={"agent_id": "1", "event_types": "action.checked"},
                             headers=auth_headers(admin_token))
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
        frames = _sse(r.text)
        assert frames[0][0] == "hello" and frames[0][1]["batch_ms"] == 100 and frames[0][1]["agent_id"] == [1]
        batches = [d for name, d in frames if name == "batch"]
        events = [e for d in batches for e in d["events"]]
        assert [e["id"] for e in events] == [0, 2]          # agent 2 and the incident filtered out on the server
        assert len(batches) == 1                            # arrived together -> one frame

        h = (await client.get(O + "/health", headers=auth_headers(admin_token))).json()
        assert h["open_streams"] == 0                       # the finished stream released its slot

    @pytest.mark.asyncio
    async def test_broken_bus_tells_the_client(self, client, admin_token, monkeypatch):
        async def broken(org_id):
            raise ConnectionError("redis down")
            yield  # pragma: no cover

        monkeypatch.setattr(obs_bus, "subscribe", broken)
        r = await client.get(O + "/stream", headers=auth_headers(admin_token))
        assert [n for n, _ in _sse(r.text)] == ["hello", "error"]
        assert (await client.get(O + "/stream", params={"event_types": "nope"},
                                 headers=auth_headers(admin_token))).status_code == 422


class TestWindowAndPaging:
    @pytest.mark.asyncio
    async def test_thirty_day_window_and_before(self, client, admin_token):
        agent = await _agent(client, admin_token)
        for tool in ("db.read", "stripe.charge", "db.read"):
            await _check(client, admin_token, agent, tool)
        assert (await client.get(O + "/summary", params={"minutes": 43200},
                                 headers=auth_headers(admin_token))).status_code == 200
        ts = (await client.get(O + "/timeseries", params={"minutes": 43200},
                               headers=auth_headers(admin_token))).json()
        assert ts["bucket_seconds"] == 28800 and 89 <= len(ts["buckets"]) <= 91

        params = {"agent_id": str(agent["id"]), "minutes": 43200, "limit": 2}
        first = (await client.get(O + "/events", params=params, headers=auth_headers(admin_token))).json()
        assert len(first) == 2
        older = (await client.get(O + "/events", params={**params, "before": first[-1]["ts"]},
                                  headers=auth_headers(admin_token))).json()
        assert all(e["ts"] < first[-1]["ts"] for e in older)
