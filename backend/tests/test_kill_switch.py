# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Kill switch: stops at agent, team, all-agents and organization-traffic
level, each lifted on its own, giving back exactly what it stopped.
"""

import secrets

import pytest
from sqlalchemy import select, update

from app.models.agent import Agent
from app.models.audit_log import AIAuditLog
from app.models.delegation import DelegationChain
from app.services import gateway_adapters
from tests.conftest import auth_headers
from tests.test_gateway import FakeProvider, _chat, _cleanup_route, _setup, msgs

pytestmark = pytest.mark.asyncio

K = "/api/v1/kill-switch"
A = "/api/v1/agents"
T = "/api/v1/teams"


@pytest.fixture
def fake(monkeypatch):
    f = FakeProvider()
    monkeypatch.setattr(gateway_adapters, "chat", f)
    return f


def _code(r):
    d = r.json().get("detail")
    return d["code"] if isinstance(d, dict) else d


async def _agent(client, token, name=None):
    r = await client.post(f"{A}/register", headers=auth_headers(token), json={
        "name": name or "ks-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
        "allowed_tools": [], "allowed_models": ["gpt-4o-mini"], "max_delegation_depth": 2})
    assert r.status_code == 200, r.text
    return r.json()


async def _team(client, token, name, **kw):
    r = await client.post(f"{T}/", json={"name": name, **kw}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _assign(client, token, agent_id, team_id):
    r = await client.put(f"{A}/{agent_id}/assignment", json={"team_id": team_id, "role_id": None},
                         headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _status(client, token, agent_id):
    return (await client.get(f"{A}/{agent_id}", headers=auth_headers(token))).json()["status"]


async def _stop(client, token, scope, target_id=None, reason="incident 42", **kw):
    body = {"scope": scope, "reason": reason, **kw}
    if target_id is not None:
        body["target_id"] = target_id
    if scope in ("all_agents", "org_traffic") and "confirm" not in kw:
        body["confirm"] = scope
    return await client.post(f"{K}/events", json=body, headers=auth_headers(token))


async def _lift(client, token, event_id, reason="resolved"):
    return await client.post(f"{K}/events/{event_id}/lift", json={"reason": reason}, headers=auth_headers(token))


async def test_agent_stop_and_undo(client, admin_token, approver_token, db_session):
    h = auth_headers(admin_token)
    a = await _agent(client, admin_token)
    other = await _agent(client, admin_token)
    chain = DelegationChain(org_id=(await db_session.get(Agent, a["id"])).org_id, root_agent_id=a["id"],
                            status="active")
    db_session.add(chain)
    await db_session.flush()

    # admin only; a reason is required
    assert (await _stop(client, approver_token, "agent", a["id"])).status_code == 403
    r = await _stop(client, admin_token, "agent", a["id"], reason="  ")
    assert r.status_code == 422
    r = await _stop(client, admin_token, "agent")
    assert r.status_code == 422 and _code(r) == "kill_switch.target_required"

    r = await _stop(client, admin_token, "agent", a["id"])
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["active"] and [x["id"] for x in ev["agents"]] == [a["id"]] and ev["chains"] == [chain.id]
    assert await _status(client, admin_token, a["id"]) == "suspended"
    assert await _status(client, admin_token, other["id"]) == "active"
    await db_session.refresh(chain)
    assert chain.status == "terminated"

    # the same stop twice is refused; switching the agent on by hand too
    r = await _stop(client, admin_token, "agent", a["id"])
    assert r.status_code == 409 and _code(r) == "kill_switch.already_active"
    r = await client.put(f"{A}/{a['id']}", headers=h, json={"status": "active"})
    assert r.status_code == 409 and _code(r) == "kill_switch.holds_agent"

    # reviewers see it
    ov = (await client.get(K, headers=auth_headers(approver_token))).json()
    assert [e["id"] for e in ov["active"]] == [ev["id"]] and not ov["traffic_stopped"]

    r = await _lift(client, admin_token, ev["id"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert not out["active"] and out["lift_result"]["restored"] == [{"id": a["id"], "name": a["name"]}]
    assert out["lift_result"]["chains_not_resumed"] == 1
    assert await _status(client, admin_token, a["id"]) == "active"
    await db_session.refresh(chain)
    assert chain.status == "terminated"  # chains are not resumed
    r = await _lift(client, admin_token, ev["id"])
    assert r.status_code == 409 and _code(r) == "kill_switch.already_lifted"

    actions = {x.action for x in (await db_session.execute(
        select(AIAuditLog).where(AIAuditLog.entity_type == "kill_switch", AIAuditLog.entity_id == ev["id"])
    )).scalars()}
    assert actions == {"engaged", "lifted"}


async def test_undo_gives_back_only_what_it_stopped(client, admin_token, db_session):
    h = auth_headers(admin_token)
    eng = await _team(client, admin_token, "Eng-" + secrets.token_hex(2))
    ml = await _team(client, admin_token, "ML-" + secrets.token_hex(2), parent_id=eng["id"])
    a = await _agent(client, admin_token)
    b = await _agent(client, admin_token)
    paused = await _agent(client, admin_token)
    outside = await _agent(client, admin_token)
    await _assign(client, admin_token, a["id"], eng["id"])
    await _assign(client, admin_token, b["id"], ml["id"])          # a sub-team is stopped with its team
    await _assign(client, admin_token, paused["id"], ml["id"])
    # suspended by hand before the stop: the stop does not give it back
    assert (await client.put(f"{A}/{paused['id']}", headers=h, json={"status": "suspended"})).status_code == 200

    r = await _stop(client, admin_token, "team", eng["id"])
    assert r.status_code == 201, r.text
    ev = r.json()
    assert sorted(x["id"] for x in ev["agents"]) == sorted([a["id"], b["id"]])
    assert sorted(ev["team_ids"]) == sorted([eng["id"], ml["id"]]) and ev["target_name"] == eng["name"]
    assert await _status(client, admin_token, outside["id"]) == "active"

    # an agent moved into the stopped team stops too, and comes back with it
    await _assign(client, admin_token, outside["id"], ml["id"])
    assert await _status(client, admin_token, outside["id"]) == "suspended"

    # retired meanwhile: skipped on undo
    assert (await client.put(f"{A}/{b['id']}", headers=h, json={"status": "retired"})).status_code == 200

    out = (await _lift(client, admin_token, ev["id"])).json()
    assert sorted(x["id"] for x in out["lift_result"]["restored"]) == sorted([a["id"], outside["id"]])
    assert [x["id"] for x in out["lift_result"]["skipped"]] == [b["id"]]
    assert await _status(client, admin_token, paused["id"]) == "suspended"
    assert await _status(client, admin_token, b["id"]) == "retired"


async def test_overlapping_stops_hand_over(client, admin_token):
    a = await _agent(client, admin_token)
    b = await _agent(client, admin_token)
    one = (await _stop(client, admin_token, "agent", a["id"])).json()
    r = await _stop(client, admin_token, "all_agents", confirm="yes")
    assert r.status_code == 422 and _code(r) == "kill_switch.confirm_required"
    every = (await _stop(client, admin_token, "all_agents")).json()
    assert [x["id"] for x in every["agents"]] == [b["id"]]  # a was already stopped by the first

    # agents created during an organization-wide stop start stopped
    c = await _agent(client, admin_token)
    assert c["status"] == "suspended"

    # lifting the agent stop first: the organization-wide one still holds a, and now gives it back
    out = (await _lift(client, admin_token, one["id"])).json()
    assert out["lift_result"]["restored"] == [] and out["lift_result"]["kept"][0]["id"] == a["id"]
    assert await _status(client, admin_token, a["id"]) == "suspended"
    out = (await _lift(client, admin_token, every["id"])).json()
    assert sorted(x["id"] for x in out["lift_result"]["restored"]) == sorted([a["id"], b["id"], c["id"]])
    for x in (a, b, c):
        assert await _status(client, admin_token, x["id"]) == "active"


async def test_quarantine_release_waits_for_the_stop(client, admin_token, db_session):
    a = await _agent(client, admin_token)
    await db_session.execute(update(Agent).where(Agent.id == a["id"]).values(status="quarantined"))
    await db_session.commit()
    ev = (await _stop(client, admin_token, "all_agents")).json()
    assert ev["agents"] == []  # already stopped by the behaviour monitor: not this stop's to give back
    r = await client.post(f"/api/v1/agent-behavior/agents/{a['id']}/release", headers=auth_headers(admin_token))
    assert r.status_code == 409 and _code(r) == "kill_switch.holds_agent"
    await _lift(client, admin_token, ev["id"])
    assert await _status(client, admin_token, a["id"]) == "quarantined"


async def test_org_traffic_stops_gateway_and_requests(client, admin_token, db_session, fake):
    a, pid, rid = await _setup(client, admin_token, db_session)
    try:
        assert (await _chat(client, a, msgs(("user", "hi")))).status_code == 200
        r = await _stop(client, admin_token, "org_traffic", confirm="all_agents")
        assert r.status_code == 422
        ev = (await _stop(client, admin_token, "org_traffic")).json()
        assert a["id"] in [x["id"] for x in ev["agents"]]
        ov = (await client.get(K, headers=auth_headers(admin_token))).json()
        assert ov["traffic_stopped"] and ov["all_agents_stopped"]

        r = await _chat(client, a, msgs(("user", "hi")))
        assert r.status_code == 503 and r.json()["error"]["code"] == "kill_switch"
        assert await _status(client, admin_token, a["id"]) == "suspended"
        r = await client.post("/api/v1/requests/", headers=auth_headers(admin_token), json={
            "use_case_id": 1, "provider_id": pid, "input_text": "hello", "purpose": "test"})
        assert r.status_code == 503 and _code(r) == "kill_switch.traffic_stopped"

        await _lift(client, admin_token, ev["id"])
        assert (await _chat(client, a, msgs(("user", "hi again")))).status_code == 200
    finally:
        await _cleanup_route(client, admin_token, rid)


async def test_gateway_refuses_while_traffic_stopped(client, admin_token, db_session, fake):
    """Even an agent that is somehow active gets no gateway call during a traffic stop."""
    a, pid, rid = await _setup(client, admin_token, db_session)
    try:
        ev = (await _stop(client, admin_token, "org_traffic")).json()
        await db_session.execute(update(Agent).where(Agent.id == a["id"]).values(status="active"))
        await db_session.commit()
        r = await _chat(client, a, msgs(("user", "hi")))
        assert r.status_code == 503 and r.json()["error"]["code"] == "kill_switch"
        assert fake.calls == []
        await _lift(client, admin_token, ev["id"])
    finally:
        await _cleanup_route(client, admin_token, rid)


async def test_agent_page_kill_is_a_stop(client, admin_token):
    a = await _agent(client, admin_token)
    r = await client.post(f"{A}/{a['id']}/kill", json={"reason": "leaked key", "cascade": True},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    event_id = r.json()["event_id"]
    events = (await client.get(f"{K}/events", headers=auth_headers(admin_token))).json()
    assert events[0]["id"] == event_id and events[0]["scope"] == "agent" and events[0]["reason"] == "leaked key"
    await _lift(client, admin_token, event_id)
    assert await _status(client, admin_token, a["id"]) == "active"


async def test_team_stop_follows_the_hierarchy(client, admin_token):
    h = auth_headers(admin_token)
    top = await _team(client, admin_token, "Top-" + secrets.token_hex(2))
    other = await _team(client, admin_token, "Other-" + secrets.token_hex(2))
    a = await _agent(client, admin_token)
    b = await _agent(client, admin_token)
    await _assign(client, admin_token, a["id"], top["id"])
    await _assign(client, admin_token, b["id"], other["id"])
    ev = (await _stop(client, admin_token, "team", top["id"])).json()

    # moved out of the stopped team: still held until the stop is lifted
    await _assign(client, admin_token, a["id"], None)
    r = await client.put(f"{A}/{a['id']}", headers=h, json={"status": "active"})
    assert r.status_code == 409 and _code(r) == "kill_switch.holds_agent"

    # a sub-team made after the stop is covered
    late = await _team(client, admin_token, "Late-" + secrets.token_hex(2), parent_id=top["id"])
    c = await _agent(client, admin_token)
    await _assign(client, admin_token, c["id"], late["id"])
    assert await _status(client, admin_token, c["id"]) == "suspended"

    # a running team moved under the stopped one stops with its agents
    r = await client.patch(f"{T}/{other['id']}", json={"parent_id": top["id"]}, headers=h)
    assert r.status_code == 200, r.text
    assert await _status(client, admin_token, b["id"]) == "suspended"

    out = (await _lift(client, admin_token, ev["id"])).json()
    assert sorted(x["id"] for x in out["lift_result"]["restored"]) == sorted([a["id"], b["id"], c["id"]])


async def test_killing_twice_is_not_an_error(client, admin_token):
    a = await _agent(client, admin_token)
    body = {"reason": "leaked key", "cascade": True}
    first = await client.post(f"{A}/{a['id']}/kill", json=body, headers=auth_headers(admin_token))
    again = await client.post(f"{A}/{a['id']}/kill", json=body, headers=auth_headers(admin_token))
    assert again.status_code == 200 and again.json()["event_id"] == first.json()["event_id"]
