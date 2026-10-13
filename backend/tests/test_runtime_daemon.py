# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Runtime daemon, server side (app/api/runtime.py, app/services/runtime_daemon.py):
governed workloads, the daemons' config and violations, and who may use them.
"""

import secrets

import pytest
from sqlalchemy import select

from app.core.security import generate_api_key, hash_api_key
from app.models.agent_action import AgentIncident
from app.models.ingestion_source import IngestionSource
from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers

R = "/api/v1/runtime"
D = "/api/v1/runtime-daemon"
PROXY = {"cidr": "127.0.0.1", "ports": [8443]}


async def _source(db, org_id, source_type="endpoint"):
    key = generate_api_key()
    db.add(IngestionSource(org_id=org_id, name=f"{source_type}-{secrets.token_hex(3)}", source_type=source_type,
                           api_key_hash=hash_api_key(key), enabled=True))
    await db.flush()
    return {"X-Ingestion-Key": key}


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register", json={
        "name": "rt-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["x"], "allowed_tools": [],
        "allowed_models": [], "max_delegation_depth": 2}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _workload(client, token, **over):
    body = {"name": "billing", "cgroup_patterns": ["system.slice/billing-agent.service"], "egress_allow": [PROXY],
            "mode": "enforce", **over}
    r = await client.post(f"{R}/workloads", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _event(workload_id, **over):
    return {"workload_id": workload_id, "action": "blocked", "protocol": "tcp", "dst_ip": "93.184.216.34",
            "dst_port": 443, "comm": "python3", "cgroup": "system.slice/billing-agent.service", **over}


@pytest.mark.asyncio
async def test_workload_admin(client, admin_token, approver_token):
    w = await _workload(client, admin_token, egress_allow=[{"cidr": "10.0.0.7/8", "ports": [443, 80]}])
    assert w["egress_allow"] == [{"cidr": "10.0.0.0/8", "ports": [80, 443]}]          # normalized
    assert (await client.get(f"{R}/workloads", headers=auth_headers(approver_token))).status_code == 403
    for bad in ({"cgroup_patterns": ["*"]}, {"cgroup_patterns": ["*/*"]}, {"cgroup_patterns": ["a/../b"]},
                {"cgroup_patterns": []}, {"cgroup_patterns": ["a b"]}, {"egress_allow": [{"cidr": "nope"}]},
                {"egress_allow": [{"cidr": "1.2.3.4", "ports": [0]}]}, {"mode": "kill"}):
        body = {"name": "x", "cgroup_patterns": ["user.slice/x.service"], **bad}
        assert (await client.post(f"{R}/workloads", json=body, headers=auth_headers(admin_token))).status_code \
            == 422, bad
    # names are unique; an unknown agent is refused
    assert (await client.post(f"{R}/workloads", json={"name": "billing", "cgroup_patterns": ["a.slice"]},
                              headers=auth_headers(admin_token))).status_code == 409
    assert (await client.post(f"{R}/workloads", json={"name": "y", "cgroup_patterns": ["a.slice"], "agent_id": 999999},
                              headers=auth_headers(admin_token))).status_code == 404
    other = await _workload(client, admin_token, name="other")
    assert (await client.patch(f"{R}/workloads/{other['id']}", json={"name": "billing"},
                               headers=auth_headers(admin_token))).status_code == 409
    r = await client.patch(f"{R}/workloads/{w['id']}", json={"mode": "observe"}, headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["mode"] == "observe"
    assert (await client.delete(f"{R}/workloads/{w['id']}", headers=auth_headers(admin_token))).json() == \
        {"deleted": True}


@pytest.mark.asyncio
async def test_daemon_config_needs_an_endpoint_key(client, admin_token, org_and_users, db_session):
    w = await _workload(client, admin_token)
    await _workload(client, admin_token, name="off", enabled=False)
    org_id = org_and_users["org"].id
    assert (await client.get(f"{D}/config")).status_code in (401, 422)
    ext = await _source(db_session, org_id, "browser_extension")
    assert (await client.get(f"{D}/config", headers=ext)).status_code == 403   # ships inside the extension
    cfg = (await client.get(f"{D}/config", headers=await _source(db_session, org_id))).json()
    assert cfg["workloads"] == [{"id": w["id"], "name": "billing",
                                 "cgroup_patterns": ["system.slice/billing-agent.service"],
                                 "egress_allow": [{"cidr": "127.0.0.1/32", "ports": [8443]}], "allow_dns": True,
                                 "mode": "enforce"}]


@pytest.mark.asyncio
async def test_violations_are_deduplicated_and_raise_one_incident(client, admin_token, org_and_users, db_session):
    agent = await _agent(client, admin_token)
    w = await _workload(client, admin_token, agent_id=agent["id"])
    key = await _source(db_session, org_and_users["org"].id)
    batch = {"host": "node-1", "events": [_event(w["id"]), _event(w["id"], count=4)]}
    r = await client.post(f"{D}/violations", json=batch, headers=key)
    assert r.status_code == 200 and r.json() == {"accepted": 2, "rejected": 0, "new": 1}, r.text
    r = await client.post(f"{D}/violations", json=batch, headers=key)
    assert r.json()["new"] == 0

    [v] = (await client.get(f"{R}/violations", headers=auth_headers(admin_token))).json()
    assert (v["count"], v["action"], v["dst_ip"], v["agent_id"], v["host"]) == (10, "blocked", "93.184.216.34",
                                                                               agent["id"], "node-1")
    incidents = (await db_session.execute(select(AgentIncident).where(
        AgentIncident.agent_id == agent["id"], AgentIncident.incident_type == "runtime_egress_violation"))
    ).scalars().all()
    assert len(incidents) == 1 and incidents[0].severity == "high"
    assert incidents[0].details["dst_port"] == 443


@pytest.mark.asyncio
async def test_observe_is_silent_and_input_is_checked(client, admin_token, org_and_users, db_session):
    agent = await _agent(client, admin_token)
    w = await _workload(client, admin_token, agent_id=agent["id"], mode="observe")
    key = await _source(db_session, org_and_users["org"].id)
    r = await client.post(f"{D}/violations", json={"host": "n\x00ode", "events": [
        _event(w["id"], action="observed", comm="evil\x1b[31m")]}, headers=key)
    assert r.json() == {"accepted": 1, "rejected": 0, "new": 0}
    [v] = (await client.get(f"{R}/violations", headers=auth_headers(admin_token))).json()
    assert v["comm"] == "evil?[31m" and v["host"] == "n?ode"                 # no control characters stored
    assert not (await db_session.execute(select(AgentIncident).where(
        AgentIncident.agent_id == agent["id"]))).scalars().all()
    for bad in ({"dst_ip": "example.com"}, {"protocol": "icmp"}, {"action": "killed"}, {"dst_port": 70000}):
        r = await client.post(f"{D}/violations", json={"host": "n", "events": [_event(w["id"], **bad)]}, headers=key)
        assert r.status_code == 422, bad


@pytest.mark.asyncio
async def test_a_daemon_cannot_report_for_another_organization(client, admin_token, db_session):
    w = await _workload(client, admin_token)
    await _create_org_with_admin_and_approver(db_session, org_slug="rt-other", admin_email="a@rt.example.com",
                                              approver_email="b@rt.example.com")
    await db_session.commit()
    other = await _login(client, "rt-other", "a@rt.example.com", "TestPass123!")
    other_org = (await client.get("/api/v1/users/me", headers=auth_headers(other))).json()["org_id"]
    key = await _source(db_session, other_org)
    assert (await client.get(f"{D}/config", headers=key)).json()["workloads"] == []
    r = await client.post(f"{D}/violations", json={"host": "n", "events": [_event(w["id"])]}, headers=key)
    assert r.json() == {"accepted": 0, "rejected": 1, "new": 0}
    assert (await client.get(f"{R}/violations", headers=auth_headers(admin_token))).json() == []
