# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress sensor API: registration, keys, workload CRUD, policy assembly,
ETag, heartbeat, violations, and org isolation.
"""

import pytest

from app.core.security import get_password_hash
from app.models.organization import Organization
from app.models.user import User, UserRole
from tests.conftest import auth_headers


BASE = "/api/v1/egress-sensor"


async def _register_sensor(client, admin_token, name="test-sensor"):
    r = await client.post(f"{BASE}/sensors", json={"name": name}, headers=auth_headers(admin_token))
    assert r.status_code == 201, r.text
    return r.json()


async def _make_workload(client, admin_token, **overrides):
    body = {
        "name": overrides.pop("name", "wl-1"),
        "cgroup_patterns": ["system.slice/app.service"],
        "egress_allow": [],
        "ingress_allow": [],
        "dns": "off",
        "mode": "enforce",
    }
    body.update(overrides)
    r = await client.post(f"{BASE}/workloads", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
async def test_register_sensor_returns_key_once(client, admin_token):
    created = await _register_sensor(client, admin_token, name="host-a")
    assert created["name"] == "host-a"
    assert created["api_key"].startswith("pvz_sensor_")
    assert len(created["api_key"]) == 11 + 32
    assert created["key_prefix"].startswith("pvz_sensor_")
    assert created["enabled"] is True

    r = await client.get(f"{BASE}/sensors", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    sensors = r.json()
    assert len(sensors) == 1
    assert "api_key" not in sensors[0]


@pytest.mark.asyncio
async def test_register_sensor_name_unique_per_org(client, admin_token):
    await _register_sensor(client, admin_token, name="dup")
    r = await client.post(f"{BASE}/sensors", json={"name": "dup"}, headers=auth_headers(admin_token))
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "egress_sensor.name_taken"


@pytest.mark.asyncio
async def test_sensor_key_required_and_checked(client, admin_token):
    created = await _register_sensor(client, admin_token, name="host-b")
    key = created["api_key"]

    r = await client.get(f"{BASE}/config")
    assert r.status_code == 401, r.text

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": "pvz_sensor_deadbeef"})
    assert r.status_code == 401, r.text

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["schema"] == 1
    assert body["workloads"] == []


@pytest.mark.asyncio
async def test_revoked_sensor_loses_access(client, admin_token):
    created = await _register_sensor(client, admin_token, name="host-c")
    key = created["api_key"]

    r = await client.delete(f"{BASE}/sensors/{created['id']}", headers=auth_headers(admin_token))
    assert r.status_code == 204, r.text

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    assert r.status_code == 401, r.text


@pytest.mark.asyncio
async def test_create_workload_bumps_revision(client, admin_token):
    w = await _make_workload(client, admin_token, name="wl-1")
    assert w["name"] == "wl-1"
    assert w["dns"] == "off"
    assert w["mode"] == "enforce"

    created = await _register_sensor(client, admin_token, name="host-d")
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": created["api_key"]})
    assert r.status_code == 200
    assert r.json()["version"] == "1"

    await _make_workload(client, admin_token, name="wl-2")
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": created["api_key"]})
    assert r.json()["version"] == "2"


@pytest.mark.asyncio
async def test_workload_name_unique_per_org(client, admin_token):
    await _make_workload(client, admin_token, name="dup")
    r = await client.post(
        f"{BASE}/workloads",
        json={"name": "dup", "mode": "enforce"},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["code"] == "egress_workload.name_taken"


@pytest.mark.asyncio
async def test_workload_validation_rejects_bad_port(client, admin_token):
    r = await client.post(
        f"{BASE}/workloads",
        json={
            "name": "wl-bad",
            "egress_allow": [{"dest": "10.0.0.0/8", "ports": [99999], "protocols": ["tcp"]}],
        },
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_disabled_workload_excluded_from_policy(client, admin_token):
    w = await _make_workload(client, admin_token, name="wl-enabled")
    await _make_workload(client, admin_token, name="wl-disabled", enabled=False)
    created = await _register_sensor(client, admin_token, name="host-e")
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": created["api_key"]})
    ids = [x["id"] for x in r.json()["workloads"]]
    assert ids == [w["id"]]


@pytest.mark.asyncio
async def test_soft_delete_removes_from_policy(client, admin_token):
    w = await _make_workload(client, admin_token, name="wl-soft")
    created = await _register_sensor(client, admin_token, name="host-f")
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": created["api_key"]})
    assert len(r.json()["workloads"]) == 1

    r = await client.delete(f"{BASE}/workloads/{w['id']}", headers=auth_headers(admin_token))
    assert r.status_code == 204, r.text

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": created["api_key"]})
    assert r.json()["workloads"] == []

    r = await client.get(f"{BASE}/workloads?include_deleted=true", headers=auth_headers(admin_token))
    assert any(x["id"] == w["id"] for x in r.json())


@pytest.mark.asyncio
async def test_policy_allow_rules_passed_through(client, admin_token):
    await _make_workload(
        client, admin_token, name="wl-allow",
        egress_allow=[
            {"dest": "1.2.3.0/24", "ports": [443], "protocols": ["tcp"]},
            {"dest": "*.corp.internal", "ports": [53], "protocols": ["udp"]},
        ],
        dns="listed",
    )
    created = await _register_sensor(client, admin_token, name="host-g")
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": created["api_key"]})
    wl = r.json()["workloads"][0]
    assert wl["dns"] == "listed"
    assert len(wl["egress_allow"]) == 2
    assert wl["egress_allow"][0]["dest"] == "1.2.3.0/24"
    assert wl["egress_allow"][1]["dest"] == "*.corp.internal"


@pytest.mark.asyncio
async def test_config_etag_304_when_version_matches(client, admin_token):
    await _make_workload(client, admin_token, name="wl-etag")
    created = await _register_sensor(client, admin_token, name="host-h")
    key = created["api_key"]

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    assert r.status_code == 200
    etag = r.headers["ETag"]
    assert etag == '"1"'

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key, "If-None-Match": etag})
    assert r.status_code == 304, r.text

    await _make_workload(client, admin_token, name="wl-etag-2")
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key, "If-None-Match": etag})
    assert r.status_code == 200, r.text
    assert r.headers["ETag"] == '"2"'


@pytest.mark.asyncio
async def test_heartbeat_updates_sensor_state(client, admin_token):
    created = await _register_sensor(client, admin_token, name="host-i")
    key = created["api_key"]

    r = await client.post(
        f"{BASE}/heartbeat",
        json={
            "hostname": "prod-01",
            "version": "v0.1.0",
            "kernel": "linux/amd64",
            "enforcing": True,
            "hooks": ["connect4", "connect6", "sendmsg4"],
            "warnings": ["BPF LSM not available"],
            "errors": [],
            "dropped_events": 3,
            "config_version": "7",
        },
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 204, r.text

    r = await client.get(f"{BASE}/sensors/{created['id']}", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["hostname"] == "prod-01"
    assert got["version"] == "v0.1.0"
    assert got["enforcing"] is True
    assert got["hooks"] == ["connect4", "connect6", "sendmsg4"]
    assert got["warnings"] == ["BPF LSM not available"]
    assert got["dropped_events"] == 3
    assert got["config_version"] == "7"
    assert got["last_seen_at"] is not None


@pytest.mark.asyncio
async def test_violations_batch_inserted(client, admin_token):
    w = await _make_workload(client, admin_token, name="wl-v")
    created = await _register_sensor(client, admin_token, name="host-j")
    key = created["api_key"]

    r = await client.post(
        f"{BASE}/violations",
        json={
            "events": [
                {"workload_id": w["id"], "action": "blocked", "kind": "connect",
                 "protocol": "tcp", "dst_ip": "1.1.1.1", "dst_port": 443,
                 "comm": "curl", "count": 2},
                {"workload_id": w["id"], "action": "alerted", "kind": "dns",
                 "protocol": "udp", "dst_name": "evil.example.com", "count": 1},
            ]
        },
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 204, r.text

    r = await client.get(f"{BASE}/sensors/{created['id']}/violations", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    events = r.json()
    assert len(events) == 2
    assert {e["kind"] for e in events} == {"connect", "dns"}
    dns_event = next(e for e in events if e["kind"] == "dns")
    assert dns_event["dst_name"] == "evil.example.com"


@pytest.mark.asyncio
async def test_violations_reject_unknown_action(client, admin_token):
    created = await _register_sensor(client, admin_token, name="host-k")
    r = await client.post(
        f"{BASE}/violations",
        json={"events": [{"workload_id": 1, "action": "wrong", "kind": "connect"}]},
        headers={"X-Sensor-Key": created["api_key"]},
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_sensor_cannot_see_other_org(client, admin_token, db_session):
    await _make_workload(client, admin_token, name="org-a-wl")
    created = await _register_sensor(client, admin_token, name="org-a-sensor")

    other = Organization(name="Other Org", slug="other-org")
    db_session.add(other)
    await db_session.flush()
    db_session.add(User(
        org_id=other.id,
        email="admin@other.example.com",
        name="Other Admin",
        hashed_password=get_password_hash("TestPass123!"),
        role=UserRole.admin.value,
        status="active",
    ))
    await db_session.flush()

    r = await client.post(
        "/api/v1/auth/login",
        json={"org_slug": "other-org", "email": "admin@other.example.com", "password": "TestPass123!"},
    )
    assert r.status_code == 200, r.text
    other_token = r.json()["access_token"]

    r = await client.get(f"{BASE}/sensors", headers=auth_headers(other_token))
    assert r.status_code == 200
    assert r.json() == []

    r = await client.get(f"{BASE}/sensors/{created['id']}", headers=auth_headers(other_token))
    assert r.status_code == 404, r.text

    r = await client.get(f"{BASE}/workloads", headers=auth_headers(other_token))
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_list_all_violations_filters(client, admin_token):
    w1 = await _make_workload(client, admin_token, name="wl-a")
    w2 = await _make_workload(client, admin_token, name="wl-b")
    created = await _register_sensor(client, admin_token, name="host-all-v")
    key = created["api_key"]

    r = await client.post(
        f"{BASE}/violations",
        json={"events": [
            {"workload_id": w1["id"], "action": "blocked", "kind": "connect",
             "protocol": "tcp", "dst_ip": "1.1.1.1", "dst_port": 443, "count": 1},
            {"workload_id": w1["id"], "action": "alerted", "kind": "dns",
             "protocol": "udp", "dst_name": "evil.example", "count": 1},
            {"workload_id": w2["id"], "action": "blocked", "kind": "connect",
             "protocol": "tcp", "dst_ip": "2.2.2.2", "dst_port": 80, "count": 1},
        ]},
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 204, r.text

    r = await client.get(f"{BASE}/violations", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert len(r.json()) == 3

    r = await client.get(f"{BASE}/violations?workload_id={w1['id']}", headers=auth_headers(admin_token))
    assert r.status_code == 200
    assert len(r.json()) == 2

    r = await client.get(f"{BASE}/violations?action=blocked", headers=auth_headers(admin_token))
    assert r.status_code == 200
    assert len(r.json()) == 2

    r = await client.get(f"{BASE}/violations?sensor_id={created['id']}", headers=auth_headers(admin_token))
    assert r.status_code == 200
    assert len(r.json()) == 3
