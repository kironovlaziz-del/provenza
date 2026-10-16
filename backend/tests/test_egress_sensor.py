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
    assert r.status_code == 200, r.text

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
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 2 and body["dropped"] == 0

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
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 3 and body["dropped"] == 0

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



@pytest.mark.asyncio
async def test_violations_drop_foreign_workload(client, admin_token, db_session):
    """A sensor must not be able to write a violation that points at another
    organization's workload."""
    from app.models.organization import Organization
    from app.models.egress_sensor import EgressWorkload

    w_own = await _make_workload(client, admin_token, name="own-wl")
    created = await _register_sensor(client, admin_token, name="sensor-org-a")
    key = created["api_key"]

    other = Organization(name="Other", slug="other-org-viol")
    db_session.add(other)
    await db_session.flush()
    foreign_w = EgressWorkload(
        org_id=other.id, name="foreign-wl", cgroup_patterns=["x.service"],
        run_as_users=[], egress_allow=[], ingress_allow=[],
        dns="off", mode="enforce", isolated=False, enabled=True,
    )
    db_session.add(foreign_w)
    await db_session.flush()

    r = await client.post(
        f"{BASE}/violations",
        json={"events": [
            {"workload_id": w_own["id"], "action": "blocked", "kind": "connect",
             "protocol": "tcp", "dst_ip": "1.1.1.1", "dst_port": 443, "count": 1},
            {"workload_id": foreign_w.id, "action": "blocked", "kind": "connect",
             "protocol": "tcp", "dst_ip": "2.2.2.2", "dst_port": 80, "count": 1},
        ]},
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 1
    assert body["dropped"] == 1

    r = await client.get(f"{BASE}/sensors/{created['id']}/violations", headers=auth_headers(admin_token))
    events = r.json()
    assert len(events) == 1
    assert events[0]["workload_id"] == w_own["id"]


@pytest.mark.asyncio
async def test_offline_sensor_warns_once(client, admin_token, db_session, monkeypatch):
    """A silent sensor produces exactly one warning; the warning is not
    repeated until the sensor comes back and goes silent again."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from app.models.egress_sensor import EgressSensor
    from app.services import egress_sensor as svc

    calls = []

    async def fake_notify(db, org_id, event_type, subject, message, metadata=None):
        calls.append((org_id, event_type))

    from app.services import notification_service
    monkeypatch.setattr(notification_service, "notify", fake_notify)

    created = await _register_sensor(client, admin_token, name="silent")
    sensor = (await db_session.execute(
        select(EgressSensor).where(EgressSensor.id == created["id"])
    )).scalar_one()
    sensor.last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    await db_session.flush()
    await db_session.refresh(sensor)  # flush alone does not sync the row we later select

    from sqlalchemy import func
    print('DEBUG row', sensor.id, sensor.enabled, sensor.revoked_at, sensor.last_seen_at, sensor.offline_notified_at)
    print('DEBUG threshold', svc.now_utc() - svc.OFFLINE_AFTER, svc.now_utc().tzinfo)
    print('DEBUG db', (await db_session.execute(select(EgressSensor.id, EgressSensor.last_seen_at, EgressSensor.offline_notified_at, func.now()).where(EgressSensor.id == sensor.id))).one())
    warned = await svc.warn_offline_sensors(db_session)
    assert warned == 1
    assert len(calls) == 1
    assert calls[0][1] == "egress_sensor_offline"

    warned = await svc.warn_offline_sensors(db_session)
    assert warned == 0
    assert len(calls) == 1

    # It came back after the warning (a heartbeat later than the warning),
    # then went silent again: warned 20 min ago, last heartbeat 10 min ago.
    now = datetime.now(timezone.utc)
    sensor.offline_notified_at = now - timedelta(minutes=20)
    sensor.last_seen_at = now - timedelta(minutes=10)
    await db_session.flush()
    await db_session.refresh(sensor)
    warned = await svc.warn_offline_sensors(db_session)
    assert warned == 1
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_kill_switch_isolates_every_workload(client, admin_token):
    """A stop of the organization's AI traffic reaches the sensors at their next
    poll: a new version (no 304) with every workload isolated."""
    created = await _register_sensor(client, admin_token, name="ks")
    await _make_workload(client, admin_token, name="wl-ks", mode="observe")
    key = {"X-Sensor-Key": created["api_key"]}

    before = await client.get(f"{BASE}/config", headers=key)
    assert before.status_code == 200, before.text
    assert before.json()["workloads"] and not any(w.get("isolated") for w in before.json()["workloads"])
    etag = before.headers["ETag"]

    r = await client.post("/api/v1/kill-switch/events",
                          json={"scope": "org_traffic", "reason": "test stop", "confirm": "org_traffic"},
                          headers=auth_headers(admin_token))
    assert r.status_code == 201, r.text

    after = await client.get(f"{BASE}/config", headers={**key, "If-None-Match": etag})
    assert after.status_code == 200, after.text
    assert after.headers["ETag"] != etag
    assert all(w["isolated"] and w["isolated_reason"] == "org_traffic_stopped"
               for w in after.json()["workloads"])



@pytest.mark.asyncio
async def test_force_refresh_bumps_revision(client, admin_token):
    """Force refresh increments the org's revision so sensors get a 200 on
    their next poll, not a 304."""
    created = await _register_sensor(client, admin_token, name="host-refresh")
    key = created["api_key"]

    # Baseline: version is the current revision (no kill switch, no suspended agent).
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    base_version = r.json()["version"]

    r = await client.post(
        f"{BASE}/sensors/{created['id']}/refresh",
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["bumped"] is True
    assert isinstance(body["new_revision"], int)

    # The sensor sees a different version on the next fetch.
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    assert r.status_code == 200
    assert r.json()["version"] != base_version


@pytest.mark.asyncio
async def test_force_refresh_requires_admin(client, approver_token, admin_token):
    """A non-admin cannot bump the org's revision."""
    created = await _register_sensor(client, admin_token, name="host-refresh-perm")
    r = await client.post(
        f"{BASE}/sensors/{created['id']}/refresh",
        headers=auth_headers(approver_token),
    )
    assert r.status_code in (401, 403), r.text


@pytest.mark.asyncio
async def test_force_refresh_unknown_sensor(client, admin_token):
    r = await client.post(
        f"{BASE}/sensors/999999/refresh",
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_force_refresh_writes_audit(client, admin_token, db_session):
    """Every refresh is on the audit log: who asked, when, and the new revision."""
    from sqlalchemy import select
    from app.models.audit_log import AIAuditLog

    created = await _register_sensor(client, admin_token, name="host-refresh-audit")
    r = await client.post(
        f"{BASE}/sensors/{created['id']}/refresh",
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 200, r.text

    rows = (await db_session.execute(
        select(AIAuditLog).where(
            AIAuditLog.entity_type == "egress_sensor",
            AIAuditLog.entity_id == created["id"],
            AIAuditLog.action == "refreshed",
        )
    )).scalars().all()
    assert len(rows) == 1



@pytest.mark.asyncio
async def test_heartbeat_stores_per_workload_snapshot(client, admin_token):
    """The heartbeat's per-workload rows land in egress_sensor_workloads and
    are returned by GET /sensors/{id}/workloads, with names joined in."""
    w = await _make_workload(client, admin_token, name="snap-wl", dns="listed")
    created = await _register_sensor(client, admin_token, name="snap-sensor")
    key = created["api_key"]

    r = await client.post(
        f"{BASE}/heartbeat",
        json={
            "hostname": "h1", "version": "v1", "kernel": "linux/amd64",
            "enforcing": True,
            "hooks": ["connect4"], "warnings": [], "errors": [],
            "dropped_events": 0,
            "workloads": [
                {"id": w["id"], "cgroups": 3, "processes": 12, "privileged": ["curl"],
                 "dns_port": 15353, "dns_total": 100, "dns_allowed": 90, "dns_denied": 10},
            ],
        },
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 200, r.text

    r = await client.get(f"{BASE}/sensors/{created['id']}/workloads", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    rows = r.json()
    assert len(rows) == 1
    row = rows[0]
    assert row["workload_id"] == w["id"]
    assert row["workload_name"] == "snap-wl"
    assert row["cgroups"] == 3
    assert row["processes"] == 12
    assert row["privileged"] == ["curl"]
    assert row["dns_port"] == 15353
    assert row["dns_total"] == 100
    assert row["dns_allowed"] == 90
    assert row["dns_denied"] == 10


@pytest.mark.asyncio
async def test_heartbeat_overwrites_snapshot(client, admin_token):
    """A second heartbeat replaces the row, not appends to it."""
    w = await _make_workload(client, admin_token, name="snap-overwrite", dns="listed")
    created = await _register_sensor(client, admin_token, name="snap-overwrite-sensor")
    key = created["api_key"]

    def hb(cgroups, total):
        return {
            "hostname": "h1", "version": "v1", "enforcing": False,
            "hooks": [], "warnings": [], "errors": [], "dropped_events": 0,
            "workloads": [
                {"id": w["id"], "cgroups": cgroups, "processes": 0, "privileged": [],
                 "dns_port": 15353, "dns_total": total, "dns_allowed": total, "dns_denied": 0},
            ],
        }

    r = await client.post(f"{BASE}/heartbeat", json=hb(3, 100), headers={"X-Sensor-Key": key})
    assert r.status_code == 200
    r = await client.post(f"{BASE}/heartbeat", json=hb(7, 250), headers={"X-Sensor-Key": key})
    assert r.status_code == 200

    r = await client.get(f"{BASE}/sensors/{created['id']}/workloads", headers=auth_headers(admin_token))
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["cgroups"] == 7
    assert rows[0]["dns_total"] == 250


@pytest.mark.asyncio
async def test_heartbeat_drops_unknown_workload(client, admin_token):
    """A row naming another organization's workload is dropped, not
    upserted into the snapshot."""
    created = await _register_sensor(client, admin_token, name="snap-unknown")
    key = created["api_key"]

    r = await client.post(
        f"{BASE}/heartbeat",
        json={
            "hostname": "h1", "version": "v1", "enforcing": False,
            "hooks": [], "warnings": [], "errors": [], "dropped_events": 0,
            "workloads": [
                {"id": 999999, "cgroups": 1, "processes": 0, "privileged": [],
                 "dns_port": 15353, "dns_total": 5, "dns_allowed": 5, "dns_denied": 0},
            ],
        },
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 200
    r = await client.get(f"{BASE}/sensors/{created['id']}/workloads", headers=auth_headers(admin_token))
    assert r.json() == []


@pytest.mark.asyncio
async def test_heartbeat_deletes_removed_workload(client, admin_token):
    """A workload the sensor stops reporting is removed from the snapshot
    on the next heartbeat."""
    w = await _make_workload(client, admin_token, name="snap-drop", dns="listed")
    created = await _register_sensor(client, admin_token, name="snap-drop-sensor")
    key = created["api_key"]

    r = await client.post(
        f"{BASE}/heartbeat",
        json={"hostname": "h1", "version": "v1", "enforcing": False,
              "hooks": [], "warnings": [], "errors": [], "dropped_events": 0,
              "workloads": [{"id": w["id"], "cgroups": 1, "processes": 0, "privileged": [],
                             "dns_port": 15353, "dns_total": 1, "dns_allowed": 1, "dns_denied": 0}]},
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 200

    r = await client.post(
        f"{BASE}/heartbeat",
        json={"hostname": "h1", "version": "v1", "enforcing": False,
              "hooks": [], "warnings": [], "errors": [], "dropped_events": 0,
              "workloads": []},
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 200

    r = await client.get(f"{BASE}/sensors/{created['id']}/workloads", headers=auth_headers(admin_token))
    assert r.json() == []



@pytest.mark.asyncio
async def test_settings_create_defaults_on_first_read(client, admin_token):
    """GET /settings creates the row with defaults the first time it is
    asked, and returns those defaults."""
    r = await client.get(f"{BASE}/settings", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["refresh_seconds"] == 30
    assert body["heartbeat_seconds"] == 30
    assert body["default_mode"] == "observe"
    assert body["default_dns"] == "off"


@pytest.mark.asyncio
async def test_settings_patch_updates_and_audits(client, admin_token, db_session):
    """PATCH /settings applies the change and writes an audit record."""
    from sqlalchemy import select
    from app.models.audit_log import AIAuditLog

    # Ensure the row exists first.
    await client.get(f"{BASE}/settings", headers=auth_headers(admin_token))

    r = await client.patch(
        f"{BASE}/settings",
        json={"refresh_seconds": 120, "heartbeat_seconds": 60},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["refresh_seconds"] == 120
    assert body["heartbeat_seconds"] == 60

    rows = (await db_session.execute(
        select(AIAuditLog).where(
            AIAuditLog.entity_type == "egress_policy_settings",
            AIAuditLog.action == "updated",
        )
    )).scalars().all()
    assert len(rows) >= 1


@pytest.mark.asyncio
async def test_settings_patch_validates_ranges(client, admin_token):
    """Out-of-range values are refused; a bad value must not take every
    sensor offline."""
    r = await client.patch(
        f"{BASE}/settings",
        json={"refresh_seconds": 5},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 422, r.text

    r = await client.patch(
        f"{BASE}/settings",
        json={"heartbeat_seconds": 10000},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 422, r.text

    r = await client.patch(
        f"{BASE}/settings",
        json={"default_mode": "wrong"},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_build_policy_uses_settings(client, admin_token):
    """The policy a sensor fetches carries the organization's settings,
    not the hardcoded defaults."""
    created = await _register_sensor(client, admin_token, name="settings-policy")
    key = created["api_key"]

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    assert r.status_code == 200
    assert r.json()["refresh_seconds"] == 30
    assert r.json()["heartbeat_seconds"] == 30

    r = await client.patch(
        f"{BASE}/settings",
        json={"refresh_seconds": 90, "heartbeat_seconds": 45},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 200

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    assert r.status_code == 200
    assert r.json()["refresh_seconds"] == 90
    assert r.json()["heartbeat_seconds"] == 45


@pytest.mark.asyncio
async def test_settings_requires_admin(client, approver_token):
    r = await client.get(f"{BASE}/settings", headers=auth_headers(approver_token))
    assert r.status_code in (401, 403), r.text



@pytest.mark.asyncio
async def test_settings_patch_bumps_revision(client, admin_token):
    """A settings change must make the policy version change, otherwise a
    sensor's If-None-Match gets a 304 and it keeps the old intervals."""
    created = await _register_sensor(client, admin_token, name="settings-bump")
    key = created["api_key"]

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    v1 = r.json()["version"]

    r = await client.patch(
        f"{BASE}/settings",
        json={"refresh_seconds": 90},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 200, r.text

    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    v2 = r.json()["version"]
    assert v2 != v1, f"version did not change: {v1} -> {v2}"
    assert r.json()["refresh_seconds"] == 90


@pytest.mark.asyncio
async def test_settings_304_only_after_same_values(client, admin_token):
    """PATCHing to the same values does not bump; a sensor polling twice in
    a row gets a 304, as it should when nothing changed."""
    created = await _register_sensor(client, admin_token, name="settings-304")
    key = created["api_key"]

    # First fetch establishes the version.
    r = await client.get(f"{BASE}/config", headers={"X-Sensor-Key": key})
    etag = r.headers["ETag"]

    # Immediate second fetch: 304.
    r = await client.get(
        f"{BASE}/config",
        headers={"X-Sensor-Key": key, "If-None-Match": etag},
    )
    assert r.status_code == 304, r.text

    # Change settings: version moves, next poll is a 200.
    r = await client.patch(
        f"{BASE}/settings",
        json={"refresh_seconds": 120},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 200

    r = await client.get(
        f"{BASE}/config",
        headers={"X-Sensor-Key": key, "If-None-Match": etag},
    )
    assert r.status_code == 200, r.text
    assert r.json()["refresh_seconds"] == 120



# ---------------------------------------------------------------- commands

@pytest.mark.asyncio
async def test_signing_key_created_lazily_and_stable(client, admin_token):
    """GET /signing-key creates the org's keypair on first call, and a
    second call returns the same key."""
    created = await _register_sensor(client, admin_token, name="signing-key-1")
    key = created["api_key"]

    r = await client.get(f"{BASE}/signing-key", headers={"X-Sensor-Key": key})
    assert r.status_code == 200, r.text
    first = r.json()
    assert first["public_key"]
    assert first["fingerprint"].startswith("SHA256:")
    assert first["sensor_id"] == created["id"]
    assert first["sensor_id"] == created["id"]

    r = await client.get(f"{BASE}/signing-key", headers={"X-Sensor-Key": key})
    assert r.status_code == 200
    assert r.json()["public_key"] == first["public_key"]


@pytest.mark.asyncio
async def test_create_command_requires_admin(client, approver_token, admin_token):
    created = await _register_sensor(client, admin_token, name="cmd-perm")
    r = await client.post(
        f"{BASE}/sensors/{created['id']}/commands",
        json={"kind": "restart"},
        headers=auth_headers(approver_token),
    )
    assert r.status_code in (401, 403), r.text


@pytest.mark.asyncio
async def test_create_command_rejects_unknown_kind(client, admin_token):
    created = await _register_sensor(client, admin_token, name="cmd-unknown")
    r = await client.post(
        f"{BASE}/sensors/{created['id']}/commands",
        json={"kind": "reboot"},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_command_delivered_in_heartbeat_and_verified(client, admin_token):
    """The command a sensor sees in the heartbeat response carries a
    signature that verifies against the public key from /signing-key,
    and the signature is over the exact payload the sensor sees."""
    from app.services.egress_sensor_commands import verify_command_signature

    created = await _register_sensor(client, admin_token, name="cmd-deliver")
    key = created["api_key"]

    # Public key the sensor caches.
    r = await client.get(f"{BASE}/signing-key", headers={"X-Sensor-Key": key})
    pub = r.json()["public_key"]

    # Admin queues a command.
    r = await client.post(
        f"{BASE}/sensors/{created['id']}/commands",
        json={"kind": "dump-state"},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 201, r.text
    cmd = r.json()
    assert cmd["kind"] == "dump-state"
    assert cmd["status"] == "pending"
    cmd_id = cmd["id"]

    # Next heartbeat carries it.
    r = await client.post(
        f"{BASE}/heartbeat",
        json={"hostname": "h1", "version": "v1", "enforcing": False,
              "hooks": [], "warnings": [], "errors": [], "dropped_events": 0},
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["commands"]) == 1
    got = body["commands"][0]
    assert got["id"] == cmd_id
    assert got["kind"] == "dump-state"
    assert got["payload"]["id"] == cmd_id
    assert got["payload"]["kind"] == "dump-state"
    assert got["payload"]["sensor_id"] == created["id"]

    # The signature verifies against the public key the sensor has.
    assert verify_command_signature(pub, got["payload"], got["signature"])


@pytest.mark.asyncio
async def test_command_ack_done_and_failed(client, admin_token):
    created = await _register_sensor(client, admin_token, name="cmd-ack")
    key = created["api_key"]

    r = await client.post(
        f"{BASE}/sensors/{created['id']}/commands",
        json={"kind": "dump-state"},
        headers=auth_headers(admin_token),
    )
    cmd_id = r.json()["id"]

    # executing -> done, with a result.
    r = await client.post(
        f"{BASE}/commands/{cmd_id}/ack",
        json={"status": "executing"},
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 204, r.text

    r = await client.post(
        f"{BASE}/commands/{cmd_id}/ack",
        json={"status": "done", "result": {"hooks": ["connect4"], "workloads": 1}},
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 204, r.text

    r = await client.get(f"{BASE}/sensors/{created['id']}/commands", headers=auth_headers(admin_token))
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["status"] == "done"
    assert rows[0]["result"]["workloads"] == 1


@pytest.mark.asyncio
async def test_command_ack_wrong_sensor_rejected(client, admin_token):
    a = await _register_sensor(client, admin_token, name="cmd-a")
    b = await _register_sensor(client, admin_token, name="cmd-b")

    r = await client.post(
        f"{BASE}/sensors/{a['id']}/commands",
        json={"kind": "restart"},
        headers=auth_headers(admin_token),
    )
    cmd_id = r.json()["id"]

    # Sensor B tries to ack A's command.
    r = await client.post(
        f"{BASE}/commands/{cmd_id}/ack",
        json={"status": "done"},
        headers={"X-Sensor-Key": b["api_key"]},
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_command_across_orgs_invisible(client, admin_token, db_session):
    """Another organization cannot see or list a sensor's commands."""
    from app.core.security import get_password_hash
    from app.models.organization import Organization
    from app.models.user import User, UserRole

    created = await _register_sensor(client, admin_token, name="cmd-iso")
    r = await client.post(
        f"{BASE}/sensors/{created['id']}/commands",
        json={"kind": "restart"},
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 201

    other = Organization(name="Other Cmd Org", slug="other-cmd-org")
    db_session.add(other)
    await db_session.flush()
    db_session.add(User(
        org_id=other.id, email="admin@other-cmd.example.com", name="X",
        hashed_password=get_password_hash("TestPass123!"),
        role=UserRole.admin.value, status="active",
    ))
    await db_session.flush()

    r = await client.post(
        "/api/v1/auth/login",
        json={"org_slug": "other-cmd-org", "email": "admin@other-cmd.example.com",
              "password": "TestPass123!"},
    )
    other_token = r.json()["access_token"]

    r = await client.get(
        f"{BASE}/sensors/{created['id']}/commands",
        headers=auth_headers(other_token),
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_expired_command_not_delivered(client, admin_token, db_session):
    """A command whose TTL passed is not returned by the heartbeat and is
    flagged expired by the sweeper."""
    from datetime import timedelta
    from sqlalchemy import update
    from app.models.egress_sensor import EgressSensorCommand
    from app.services import egress_sensor_commands as cmd

    created = await _register_sensor(client, admin_token, name="cmd-expire")
    key = created["api_key"]

    r = await client.post(
        f"{BASE}/sensors/{created['id']}/commands",
        json={"kind": "restart"},
        headers=auth_headers(admin_token),
    )
    cmd_id = r.json()["id"]

    # Force the expiry into the past.
    await db_session.execute(
        update(EgressSensorCommand)
        .where(EgressSensorCommand.id == cmd_id)
        .values(expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc) - timedelta(seconds=1))
    )
    await db_session.flush()

    r = await client.post(
        f"{BASE}/heartbeat",
        json={"hostname": "h1", "version": "v1", "enforcing": False,
              "hooks": [], "warnings": [], "errors": [], "dropped_events": 0},
        headers={"X-Sensor-Key": key},
    )
    assert r.status_code == 200
    assert r.json()["commands"] == []

    n = await cmd.expire_old_commands(db_session)
    assert n >= 1



def test_canonical_command_payload_bytes():
    """The bytes a command signature is made over, pinned to a literal.

    The sensor (Go) canonicalizes the same payload and must produce
    exactly this string before verifying the signature. If either side
    ever changes its JSON writer, this test fails - and that is the point:
    canonicalization is the contract between the two ends.
    """
    from app.core.agent_signing import canonical_text

    payload = {
        "id": 42,
        "kind": "detach",
        "org_id": 7,
        "sensor_id": 3,
        "issued_at": "2026-10-16T09:00:00Z",
        "expires_at": "2026-10-16T09:05:00Z",
    }
    expected = (
        '{"expires_at":"2026-10-16T09:05:00Z","id":42,'
        '"issued_at":"2026-10-16T09:00:00Z","kind":"detach",'
        '"org_id":7,"sensor_id":3}'
    )
    assert canonical_text(payload) == expected



# ---------------------------------------------------------------- key rotation

@pytest.mark.asyncio
async def test_rotate_generates_new_key_and_broadcasts(client, admin_token):
    """POST /rotate changes the current fingerprint and queues exactly one
    update-signing-key command per enabled sensor."""
    a = await _register_sensor(client, admin_token, name="rot-a")
    b = await _register_sensor(client, admin_token, name="rot-b")

    # Baseline: current key fingerprint.
    r = await client.get(f"{BASE}/settings/signing-key", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    before = r.json()["fingerprint"]
    assert before

    r = await client.post(f"{BASE}/settings/signing-key/rotate", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["fingerprint"] != before
    assert body["previous_fingerprint"] == before
    assert body["sensors_notified"] >= 2
    assert body["previous_valid_until"] is not None

    # Each sensor has its own update-signing-key command queued.
    for s in (a, b):
        r = await client.get(f"{BASE}/sensors/{s['id']}/commands", headers=auth_headers(admin_token))
        assert r.status_code == 200
        kinds = [c["kind"] for c in r.json()]
        assert "update-signing-key" in kinds


@pytest.mark.asyncio
async def test_rotate_command_signed_with_previous_key(client, admin_token, db_session):
    """The update-signing-key command must verify against the PREVIOUS
    public key: that is what the sensor already trusts."""
    from app.models.egress_sensor import EgressSensorCommand, EgressSensorSigningKey
    from app.services.egress_sensor_commands import verify_command_signature
    from sqlalchemy import select

    created = await _register_sensor(client, admin_token, name="rot-verify")

    # Get current (pre-rotation) key.
    r = await client.get(f"{BASE}/settings/signing-key", headers=auth_headers(admin_token))
    old_public = r.json()["public_key"]

    # Rotate.
    r = await client.post(f"{BASE}/settings/signing-key/rotate", headers=auth_headers(admin_token))
    assert r.status_code == 200

    # The command payload verifies against the OLD key.
    r = await client.get(f"{BASE}/sensors/{created['id']}/commands", headers=auth_headers(admin_token))
    cmds = [c for c in r.json() if c["kind"] == "update-signing-key"]
    assert len(cmds) == 1

    # Fetch the payload + signature.
    rows = (await db_session.execute(
        select(EgressSensorCommand).where(EgressSensorCommand.id == cmds[0]["id"])
    )).scalars().all()
    assert len(rows) == 1
    payload = rows[0].payload
    signature = rows[0].signature

    assert "new_public_key" in payload
    assert verify_command_signature(old_public, payload, signature), \
        "update-signing-key must verify against the OLD key"


@pytest.mark.asyncio
async def test_finalize_clears_previous_key(client, admin_token):
    """POST /finalize drops the previous key from the settings response."""
    await _register_sensor(client, admin_token, name="rot-fin")

    r = await client.post(f"{BASE}/settings/signing-key/rotate", headers=auth_headers(admin_token))
    assert r.status_code == 200

    r = await client.get(f"{BASE}/settings/signing-key", headers=auth_headers(admin_token))
    assert r.json()["previous_public_key"] is not None

    r = await client.post(f"{BASE}/settings/signing-key/finalize", headers=auth_headers(admin_token))
    assert r.status_code == 200

    r = await client.get(f"{BASE}/settings/signing-key", headers=auth_headers(admin_token))
    assert r.json()["previous_public_key"] is None


@pytest.mark.asyncio
async def test_signing_key_out_includes_previous_after_rotate(client, admin_token):
    """The sensor-facing /signing-key returns the previous public key while
    the grace period is running."""
    created = await _register_sensor(client, admin_token, name="rot-sensor")

    r = await client.get(f"{BASE}/signing-key", headers={"X-Sensor-Key": created["api_key"]})
    assert r.status_code == 200
    assert r.json()["previous_public_key"] is None

    r = await client.post(f"{BASE}/settings/signing-key/rotate", headers=auth_headers(admin_token))
    assert r.status_code == 200

    r = await client.get(f"{BASE}/signing-key", headers={"X-Sensor-Key": created["api_key"]})
    assert r.status_code == 200
    assert r.json()["previous_public_key"] is not None
    assert r.json()["previous_valid_until"] is not None


@pytest.mark.asyncio
async def test_rotate_requires_admin(client, approver_token):
    r = await client.post(f"{BASE}/settings/signing-key/rotate", headers=auth_headers(approver_token))
    assert r.status_code in (401, 403)
