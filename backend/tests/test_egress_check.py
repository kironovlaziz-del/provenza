# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress checks (app/services/egress_check.py) and the lockdown generator
(app/services/egress_lockdown.py): is the agent's host confined to the
egress proxy, and can acting depend on it.
"""

import secrets
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from sqlalchemy import select, update

from app.core.agent_signing import sign_payload
from app.models.agent_action import AgentIncident
from app.models.egress_check import AgentEgressCheck
from app.services import egress_check
from tests.conftest import auth_headers

CHECK = "/api/v1/agents/actions/check"


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register", json={
        "name": "egc-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
        "allowed_tools": ["db.read"], "allowed_models": [], "max_delegation_depth": 1,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _h(agent):
    return {"X-Agent-Key": agent["api_key"]}


async def _run(client, agent, reachable=(), beacon=False, hit_beacon=False, sign_as=None):
    r = await client.post("/api/v1/agents/egress-check", headers=_h(agent))
    assert r.status_code == 200, r.text
    started = r.json()
    if hit_beacon:
        path = "/egress-beacon/" + started["beacon_url"].rsplit("/", 1)[1]
        assert (await client.get(path)).status_code == 204
    results = [{"target": t, "reachable": t in reachable} for t in started["targets"]]
    payload = egress_check.signed_payload(agent["id"], started["check_id"], results, beacon)
    key = (sign_as or client.agent_keys[agent["id"]])[0]
    r = await client.post(f"/api/v1/agents/egress-check/{started['check_id']}/report", headers=_h(agent),
                          json={"results": results, "beacon_reached": beacon, "signature": sign_payload(payload, key)})
    return started, r


async def _require(client, token, on=True, hours=24):
    r = await client.put("/api/v1/agent-identity/settings", json={
        "require_agent_key": True, "rotation_grace_minutes": 60, "require_confined_egress": on,
        "egress_check_max_age_hours": hours}, headers=auth_headers(token))
    assert r.status_code == 200, r.text


async def _check_status(client, agent):
    r = await client.post(CHECK, json={"agent_id": agent["id"], "action_type": "tool_call", "tool_name": "db.read",
                                       "input": {}}, headers=_h(agent))
    return r.status_code, r.json()


@pytest.mark.asyncio
async def test_a_confined_host_and_the_requirement(client, admin_token):
    agent = await _agent(client, admin_token)
    await _require(client, admin_token)
    try:
        status_code, body = await _check_status(client, agent)
        assert status_code == 403 and body["detail"] == "agent.egress_unchecked"
        started, r = await _run(client, agent)
        assert started["targets"] == ["api.openai.com:443", "1.1.1.1:443"]
        assert "/egress-beacon/" in started["beacon_url"] and "/api/v1/" not in started["beacon_url"]
        assert r.status_code == 200 and r.json()["verdict"] == "confined", r.text
        assert (await _check_status(client, agent))[0] == 200
        ov = (await client.get("/api/v1/agent-identity/egress", headers=auth_headers(admin_token))).json()["checks"]
        assert any(c["agent_id"] == agent["id"] and c["verdict"] == "confined" for c in ov)
    finally:
        await _require(client, admin_token, on=False)


@pytest.mark.asyncio
async def test_open_hosts_are_refused_whatever_they_report(client, admin_token, db_session):
    await _require(client, admin_token)
    try:
        # it says so itself
        agent = await _agent(client, admin_token)
        _, r = await _run(client, agent, reachable=("1.1.1.1:443",))
        assert r.json()["verdict"] == "open"
        assert (await _check_status(client, agent))[1]["detail"] == "agent.egress_unconfined"
        # it says it reached nothing - but this server saw the beacon
        liar = await _agent(client, admin_token)
        _, r = await _run(client, liar, hit_beacon=True)
        assert r.json()["verdict"] == "open"
        # the beacon after a "confined" report still opens it
        late = await _agent(client, admin_token)
        started, r = await _run(client, late)
        assert r.json()["verdict"] == "confined"
        assert (await client.get("/egress-beacon/" + started["beacon_url"].rsplit("/", 1)[1])).status_code == 204
        assert (await _check_status(client, late))[1]["detail"] == "agent.egress_unconfined"
        incidents = (await db_session.execute(select(AgentIncident).where(
            AgentIncident.incident_type == "egress_unconfined",
            AgentIncident.agent_id.in_([agent["id"], liar["id"], late["id"]])))).scalars().all()
        assert {i.agent_id for i in incidents} == {agent["id"], liar["id"], late["id"]}
    finally:
        await _require(client, admin_token, on=False)


@pytest.mark.asyncio
async def test_reports_are_signed_complete_once_and_fresh(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    other = await _agent(client, admin_token)
    _, r = await _run(client, agent, sign_as=client.agent_keys[other["id"]])
    assert r.status_code == 401 and r.json()["detail"] == "egress_check.invalid_signature"

    started = (await client.post("/api/v1/agents/egress-check", headers=_h(agent))).json()
    partial = [{"target": started["targets"][0], "reachable": False}]
    payload = egress_check.signed_payload(agent["id"], started["check_id"], partial, False)
    r = await client.post(f"/api/v1/agents/egress-check/{started['check_id']}/report", headers=_h(agent), json={
        "results": partial, "beacon_reached": False,
        "signature": sign_payload(payload, client.agent_keys[agent["id"]][0])})
    assert r.status_code == 422 and r.json()["detail"] == "egress_check.targets_mismatch"
    # another agent cannot report on it
    r = await client.post(f"/api/v1/agents/egress-check/{started['check_id']}/report", headers=_h(other), json={
        "results": partial, "beacon_reached": False, "signature": "x"})
    assert r.status_code == 404

    started, r = await _run(client, agent)
    assert r.status_code == 200
    again = await client.post(f"/api/v1/agents/egress-check/{started['check_id']}/report", headers=_h(agent),
                              json={"results": [], "beacon_reached": False, "signature": "x"})
    assert again.status_code == 409

    # stale: an old confined verdict no longer counts
    await _require(client, admin_token, hours=1)
    try:
        await db_session.execute(update(AgentEgressCheck).where(AgentEgressCheck.agent_id == agent["id"],
                                                                AgentEgressCheck.reported_at.is_not(None)).values(
            reported_at=datetime.now(timezone.utc) - timedelta(hours=2)))
        await db_session.commit()
        assert (await _check_status(client, agent))[1]["detail"] == "agent.egress_check_stale"
    finally:
        await _require(client, admin_token, on=False)


@pytest.mark.asyncio
async def test_the_beacon_tells_nothing_and_ignores_unknown_tokens(client):
    for token in ("nope", "x" * 200):
        r = await client.get(f"/egress-beacon/{token}")
        assert r.status_code == 204 and r.content == b""


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["kubernetes", "docker", "nftables"])
async def test_lockdown_rules(client, admin_token, kind):
    body = {"kind": kind, "proxy_host": "10.0.0.5" if kind == "nftables" else "provenza-proxy"}
    r = await client.post("/api/v1/egress-lockdown/render", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    out = r.json()
    text = "\n".join(f["content"] for f in out["files"])
    assert out["agent_env"]["PROVENZA_URL"].endswith("/_provenza")
    assert '"relay_provenza": true' in text
    if kind == "kubernetes":
        docs = [d for d in yaml.safe_load_all(out["files"][0]["content"]) if d]
        policy = next(d for d in docs if d["kind"] == "NetworkPolicy" and d["metadata"]["namespace"] == "agents")
        assert policy["spec"]["podSelector"]["matchLabels"] == {"provenza/egress": "proxied"}
        assert len(policy["spec"]["egress"]) == 2   # the proxy and the cluster DNS - nothing else
    if kind == "docker":
        assert "internal: true" in text
    if kind == "nftables":
        assert 'meta skuid "agent" jump agent' in text and "ip daddr 10.0.0.5 tcp dport 8443 accept" in text


@pytest.mark.asyncio
async def test_lockdown_input_is_validated(client, admin_token):
    for bad in ({"kind": "nftables", "proxy_host": "proxy.corp"}, {"kind": "docker", "agent_service": "a b"},
                {"kind": "kubernetes", "agent_label": "x: y\nkind: Evil"}, {"kind": "iptables"}):
        r = await client.post("/api/v1/egress-lockdown/render", json=bad, headers=auth_headers(admin_token))
        assert r.status_code == 422, bad


@pytest.mark.asyncio
async def test_prune_keeps_each_agents_latest_verdict(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    await _run(client, agent)
    _, last = await _run(client, agent)
    await client.post("/api/v1/agents/egress-check", headers=_h(agent))     # never reported
    await db_session.execute(update(AgentEgressCheck).where(AgentEgressCheck.agent_id == agent["id"]).values(
        created_at=datetime.now(timezone.utc) - timedelta(days=40)))
    await db_session.commit()
    await egress_check.prune(db_session)
    left = (await db_session.execute(select(AgentEgressCheck.id).where(
        AgentEgressCheck.agent_id == agent["id"]))).scalars().all()
    assert left == [last.json()["check_id"]]
