"""
Protection coverage (app/services/coverage.py), in GET /api/v1/system/setup:
whether each part of the protection works now - not only whether it was
configured. ok / attention / missing, with the facts it was judged on.
"""

import secrets
from datetime import datetime, timedelta, timezone

import pytest

from app.models.agent import Agent
from app.models.egress_check import AgentEgressCheck
from app.models.egress_proxy import EgressProxy
from app.models.egress_sensor import EgressSensor
from app.models.endpoint_device import EndpointDevice
from app.models.ingestion_source import IngestionSource
from app.pvp import signed_policy
from tests.conftest import auth_headers
from tests.test_policy_release import _prepare, _release

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


async def _coverage(client, token):
    r = await client.get("/api/v1/system/setup", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    cov = r.json()["coverage"]
    return {i["key"]: i for i in cov["items"]}, cov["summary"]


def _agent(org_id, key=True):
    return Agent(org_id=org_id, name="cov-" + secrets.token_hex(3), status="active", api_key_hash=secrets.token_hex(32),
                 capabilities=[], allowed_tools=[], allowed_models=[],
                 public_key=("A" * 44) if key else None)


def _check(org_id, agent_id, verdict, age=timedelta(0)):
    return AgentEgressCheck(org_id=org_id, agent_id=agent_id, token=secrets.token_hex(16), targets=[],
                            created_at=NOW() - age, expires_at=NOW() - age + timedelta(minutes=10), verdict=verdict)


@pytest.mark.asyncio
async def test_a_new_installation_has_nothing_working(client, admin_token, approver_token):
    assert (await client.get("/api/v1/system/setup", headers=auth_headers(approver_token))).status_code == 403
    items, summary = await _coverage(client, admin_token)
    assert list(items) == ["signed_policy", "proxy", "agents_signing", "agents_confined", "sensors",
                           "endpoint_agents", "browsers"]
    assert {k: i["state"] for k, i in items.items()} == dict.fromkeys(items, "missing")
    assert {k for k, i in items.items() if i["optional"]} == {"sensors", "endpoint_agents", "browsers"}
    # what needs a person: the four required parts, none of the optional ones
    assert summary == {"ok": 0, "attention": 0, "missing": 7, "needs_action": 4}


@pytest.mark.asyncio
async def test_a_proxy_without_a_signed_policy_protects_nothing(client, db_session, org_and_users, admin_token):
    org_id = org_and_users["org"].id
    db_session.add(EgressProxy(org_id=org_id, name="edge", key_hash=secrets.token_hex(32), key_prefix="pxy_x",
                               last_seen_at=NOW()))
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["proxy"]["state"] == "attention"
    assert items["proxy"]["facts"] == {"total": 1, "online": 1, "policy": False}

    await _release(client, admin_token)
    items, _ = await _coverage(client, admin_token)
    assert items["signed_policy"]["state"] == "ok" and items["signed_policy"]["facts"]["number"] == 1
    assert items["proxy"]["state"] == "ok"

    # not heard from for a while: it may be down, so the agents behind it may be cut off - or going around it
    proxy = (await db_session.execute(EgressProxy.__table__.select())).first()
    await db_session.execute(EgressProxy.__table__.update().where(EgressProxy.id == proxy.id)
                             .values(last_seen_at=NOW() - timedelta(hours=1)))
    await db_session.flush()
    items, summary = await _coverage(client, admin_token)
    assert items["proxy"]["state"] == "attention" and items["proxy"]["facts"]["online"] == 0
    assert summary["attention"] == 1


@pytest.mark.asyncio
async def test_a_release_waiting_for_signatures_needs_attention(client, admin_token):
    await _release(client, admin_token)
    await _prepare(client, admin_token)
    items, _ = await _coverage(client, admin_token)
    assert items["signed_policy"]["state"] == "attention"
    assert items["signed_policy"]["facts"]["draft"] == 2


@pytest.mark.asyncio
async def test_agents_are_covered_when_they_sign_and_are_shown_confined(client, db_session, org_and_users, admin_token):
    org_id = org_and_users["org"].id
    a, b = _agent(org_id), _agent(org_id, key=False)
    retired = _agent(org_id)
    retired.status = "retired"
    db_session.add_all([a, b, retired])
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["agents_signing"]["state"] == "attention"
    assert items["agents_signing"]["facts"] == {"agents": 2, "signing": 1}
    assert items["agents_confined"]["state"] == "missing"           # never checked

    db_session.add_all([_check(org_id, a.id, "confined"), _check(org_id, b.id, "pending")])
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["agents_confined"]["state"] == "attention"
    assert items["agents_confined"]["facts"] == {"agents": 2, "confined": 1, "open": 0, "unchecked": 1}

    # the latest finished check counts: confined once, open now
    db_session.add(_check(org_id, b.id, "confined", age=timedelta(days=2)))
    db_session.add(_check(org_id, b.id, "open", age=timedelta(days=1)))
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["agents_confined"]["facts"] == {"agents": 2, "confined": 1, "open": 1, "unchecked": 0}

    db_session.add(_check(org_id, b.id, "confined"))
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["agents_confined"]["state"] == "ok"

    # a check older than the validity window proves little about today
    db_session.add(_check(org_id, retired.id, "confined"))
    c = _agent(org_id)
    db_session.add(c)
    await db_session.flush()
    db_session.add(_check(org_id, c.id, "confined", age=timedelta(days=45)))
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["agents_confined"]["facts"]["unchecked"] == 1 and items["agents_confined"]["state"] == "attention"


@pytest.mark.asyncio
async def test_a_sensor_counts_when_it_is_online_and_enforcing(client, db_session, org_and_users, admin_token):
    org_id = org_and_users["org"].id
    s = EgressSensor(org_id=org_id, name="host", key_hash=secrets.token_hex(32), key_prefix="sns_x",
                     last_seen_at=NOW(), enforcing=False)
    db_session.add(s)
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["sensors"]["state"] == "attention" and items["sensors"]["facts"]["enforcing"] == 0
    s.enforcing = True
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["sensors"]["state"] == "ok"
    s.errors = ["bpf: lsm hook unavailable"]
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["sensors"]["state"] == "attention" and items["sensors"]["facts"]["problems"] == 1


@pytest.mark.asyncio
async def test_collectors_count_when_something_reports(client, db_session, org_and_users, admin_token):
    org_id = org_and_users["org"].id
    ep = IngestionSource(org_id=org_id, name="fleet", source_type="endpoint", api_key_hash=secrets.token_hex(32))
    br = IngestionSource(org_id=org_id, name="browsers", source_type="browser_extension",
                         api_key_hash=secrets.token_hex(32))
    db_session.add_all([ep, br])
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    # a key was made, but nothing reports with it
    assert items["endpoint_agents"]["state"] == "attention" and items["browsers"]["state"] == "attention"

    db_session.add_all([
        EndpointDevice(org_id=org_id, ingestion_source_id=ep.id, host_id="laptop-1", last_seen_at=NOW()),
        EndpointDevice(org_id=org_id, ingestion_source_id=ep.id, host_id="laptop-2",
                       last_seen_at=NOW() - timedelta(days=3)),
        EndpointDevice(org_id=org_id, ingestion_source_id=br.id, host_id="browser-1",
                       last_seen_at=NOW() - timedelta(days=3))])
    await db_session.flush()
    items, _ = await _coverage(client, admin_token)
    assert items["endpoint_agents"]["state"] == "ok"
    assert items["endpoint_agents"]["facts"] == {"sources": 1, "devices": 2, "reporting": 1}
    # the extension has no heartbeat: a browser that reported this week counts
    assert items["browsers"]["state"] == "ok"
