"""
An agent's own network (app/services/agent_network.py): every new agent gets
a workload in observe mode, the agent's page lists where it went, and an
administrator allows those destinations and enforces in one step.
"""

import pytest
from sqlalchemy import select

from app.models.audit_log import AIAuditLog as AuditLog
from tests.conftest import auth_headers
from tests.enrollment_helpers import enroll

S = "/api/v1/egress-sensor"
A = "/api/v1/agents"


async def _agent(client, token, name="net-agent"):
    r = await client.post(f"{A}/register", json={"name": name, "agent_type": "custom", "capabilities": ["read"]},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _network(client, token, agent_id):
    r = await client.get(f"{A}/{agent_id}/network", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _sensor(client, token, name="net-sensor"):
    r = await client.post(f"{S}/sensors", json={"name": name}, headers=auth_headers(token))
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
async def test_a_new_agent_is_observed_by_default(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    net = await _network(client, admin_token, agent["id"])
    w = net["workload"]
    assert w["name"] == f"agent-{agent['id']}"
    assert (w["mode"], w["dns"], w["egress_allow"], w["enabled"]) == ("observe", "any", [], True)
    assert net["running"] == [] and net["destinations"] == []

    # the sensors get it, named for the agent: `provenza-sensor --agent N run` finds it
    sensor = await _sensor(client, admin_token)
    r = await client.get(f"{S}/config", headers={"X-Sensor-Key": sensor["api_key"]})
    pw = next(x for x in r.json()["workloads"] if x["id"] == w["id"])
    assert pw["agent_id"] == agent["id"] and pw["mode"] == "observe" and pw["dns"] == "any"
    assert pw["cgroup_patterns"] == [] and pw["egress_allow"] == []

    # the audit log says it came with the agent
    rows = (await db_session.execute(select(AuditLog).where(
        AuditLog.entity_type == "egress_workload", AuditLog.entity_id == w["id"]))).scalars().all()
    assert [r.action for r in rows] == ["created"] and rows[0].metadata_json["with_agent"] is True


@pytest.mark.asyncio
async def test_an_enrolled_agent_is_observed_too(client, admin_token):
    agent = await enroll(client, admin_token, name="enrolled-net")
    net = await _network(client, admin_token, agent["id"])
    assert net["workload"]["mode"] == "observe" and net["workload"]["name"] == f"agent-{agent['id']}"


@pytest.mark.asyncio
async def test_where_it_runs_and_where_it_went(client, admin_token):
    agent = await _agent(client, admin_token, name="net-dest")
    wid = (await _network(client, admin_token, agent["id"]))["workload"]["id"]
    sensor = await _sensor(client, admin_token, name="net-dest-sensor")
    key = {"X-Sensor-Key": sensor["api_key"]}

    r = await client.post(f"{S}/heartbeat", headers=key, json={
        "hostname": "build-1", "workloads": [{"id": wid, "cgroups": 1, "processes": 2, "privileged": []}]})
    assert r.status_code == 200, r.text
    ev = lambda **k: {"workload_id": wid, "action": "observed", "kind": "connect", "protocol": "tcp", "count": 1, **k}
    r = await client.post(f"{S}/violations", headers=key, json={"events": [
        ev(dst_ip="104.18.7.192", dst_port=443, dst_name="api.openai.com", count=3),
        ev(dst_ip="104.18.6.192", dst_port=443, dst_name="api.openai.com"),     # another address, the same name
        ev(dst_ip="140.82.112.3", dst_port=443),                                # no name learned
        ev(dst_ip="140.82.112.3", dst_port=22),
        ev(action="observed", kind="ingress", dst_ip="10.0.0.9", dst_port=8080),  # coming in: not where it went
        ev(action="observed", kind="family", count=1),                         # no address
    ]})
    assert r.status_code == 200, r.text

    net = await _network(client, admin_token, agent["id"])
    assert [(x["sensor"], x["hostname"], x["cgroups"], x["processes"]) for x in net["running"]] == \
        [("net-dest-sensor", "build-1", 1, 2)]
    got = {(d["dest"], d["port"], d["protocol"]): d for d in net["destinations"]}
    assert set(got) == {("api.openai.com", 443, "tcp"), ("140.82.112.3", 443, "tcp"), ("140.82.112.3", 22, "tcp")}
    assert got[("api.openai.com", 443, "tcp")]["count"] == 4 and got[("api.openai.com", 443, "tcp")]["named"]
    assert not got[("140.82.112.3", 443, "tcp")]["named"] and not got[("140.82.112.3", 443, "tcp")]["blocked"]

    # a sensor gone quiet no longer counts as running it
    r = await client.post(f"{S}/heartbeat", headers=key, json={"hostname": "build-1", "workloads": []})
    assert (await _network(client, admin_token, agent["id"]))["running"] == []


@pytest.mark.asyncio
async def test_allow_what_it_used_and_enforce(client, admin_token, db_session):
    agent = await _agent(client, admin_token, name="net-enforce")
    wid = (await _network(client, admin_token, agent["id"]))["workload"]["id"]
    r = await client.post(f"{A}/{agent['id']}/network/enforce", headers=auth_headers(admin_token), json={
        "destinations": [{"dest": "API.OpenAI.com.", "port": 443, "protocol": "tcp"},
                         {"dest": "api.openai.com", "port": 8443, "protocol": "tcp"},
                         {"dest": "140.82.112.3", "port": 22, "protocol": "tcp"},
                         {"dest": "10.1.0.0/16"}]})
    assert r.status_code == 200, r.text
    w = r.json()["workload"]
    assert (w["mode"], w["dns"]) == ("enforce", "listed")  # names resolve through the sensor, only these
    assert w["egress_allow"] == [
        {"dest": "10.1.0.0/16", "ports": [], "protocols": []},
        {"dest": "140.82.112.3/32", "ports": [22], "protocols": ["tcp"]},
        {"dest": "api.openai.com", "ports": [443, 8443], "protocols": ["tcp"]},
    ]
    # the sensors get exactly that
    sensor = await _sensor(client, admin_token, name="net-enforce-sensor")
    r = await client.get(f"{S}/config", headers={"X-Sensor-Key": sensor["api_key"]})
    pw = next(x for x in r.json()["workloads"] if x["id"] == wid)
    assert pw["mode"] == "enforce" and pw["dns"] == "listed" and len(pw["egress_allow"]) == 3

    row = (await db_session.execute(select(AuditLog).where(
        AuditLog.entity_type == "egress_workload", AuditLog.entity_id == wid, AuditLog.action == "updated"))
    ).scalars().one()
    assert row.metadata_json["via"] == "agent_network" and row.metadata_json["changes"]["mode"] == {"from": "observe",
                                                                                        "to": "enforce"}


@pytest.mark.asyncio
@pytest.mark.parametrize("dest", ["bad host", "a;b", "-x.com", "", "x" * 256, "http://api.openai.com"])
async def test_a_destination_must_be_a_name_an_address_or_a_network(client, admin_token, dest):
    agent = await _agent(client, admin_token, name="net-bad")
    r = await client.post(f"{A}/{agent['id']}/network/enforce", headers=auth_headers(admin_token),
                          json={"destinations": [{"dest": dest, "port": 443}]})
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_an_agent_made_before_is_observed_on_request(client, admin_token):
    agent = await _agent(client, admin_token, name="net-old")
    wid = (await _network(client, admin_token, agent["id"]))["workload"]["id"]
    r = await client.delete(f"{S}/workloads/{wid}", headers=auth_headers(admin_token))
    assert r.status_code == 204
    assert (await _network(client, admin_token, agent["id"]))["workload"] is None
    r = await client.post(f"{A}/{agent['id']}/network/enforce", headers=auth_headers(admin_token),
                          json={"destinations": []})
    assert r.status_code == 409 and r.json()["detail"] == "agent_network.not_observed"

    r = await client.post(f"{A}/{agent['id']}/network", headers=auth_headers(admin_token))
    assert r.status_code == 201, r.text
    w = r.json()["workload"]
    # the deleted workload keeps its name: the new one takes the next
    assert w["mode"] == "observe" and w["name"] == f"agent-{agent['id']}-2" and w["id"] != wid
    r = await client.post(f"{A}/{agent['id']}/network", headers=auth_headers(admin_token))
    assert r.json()["workload"]["id"] == w["id"]  # once


@pytest.mark.asyncio
async def test_administrators_only_and_own_organization(client, admin_token, approver_token):
    agent = await _agent(client, admin_token, name="net-rbac")
    for method, path in (("get", ""), ("post", ""), ("post", "/enforce")):
        r = await getattr(client, method)(f"{A}/{agent['id']}/network{path}", headers=auth_headers(approver_token),
                                          **({"json": {"destinations": []}} if path else {}))
        assert r.status_code == 403, (method, path, r.text)
    r = await client.get(f"{A}/999999/network", headers=auth_headers(admin_token))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_not_past_what_a_sensor_holds(client, admin_token, monkeypatch):
    """Every workload goes to every sensor: past the limit a new agent gets
    none by default, and its page still offers one."""
    from app.services import agent_network

    monkeypatch.setattr(agent_network, "AUTO_WORKLOADS_MAX", 1)
    first = await _agent(client, admin_token, name="net-cap-1")
    second = await _agent(client, admin_token, name="net-cap-2")
    assert (await _network(client, admin_token, first["id"]))["workload"] is not None
    assert (await _network(client, admin_token, second["id"]))["workload"] is None
    r = await client.post(f"{A}/{second['id']}/network", headers=auth_headers(admin_token))
    assert r.status_code == 201 and r.json()["workload"]["mode"] == "observe"
