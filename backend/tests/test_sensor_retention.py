"""Tests for event timestamp preservation and per-org retention.

Two things are exercised end to end:
  * ts_ns: BPF stamps each event with the kernel clock and the backend
    stores that as created_at, not now(). Without it, a batch of 500
    events landed in the DB with identical timestamps.
  * retention: hourly Celery tasks delete rows past each org's retention.
    Zero means keep forever. Independent per table (activity vs violations).

Schema bounds (0..365) are checked at the Pydantic layer so a bad PATCH
never reaches the DB.
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from tests.conftest import auth_headers
from app.models.egress_sensor import (
    EgressPolicySettings,
    EgressViolation,
    SensorActivity,
)
from app.schemas.egress_sensor import (
    ActivityIn,
    PolicySettingsUpdate,
    ViolationIn,
)
from app.services.egress_sensor import prune_sensor_activity, prune_violations

BASE = "/api/v1/egress-sensor"


async def _register_sensor(client, token, name: str) -> dict:
    r = await client.post(f"{BASE}/sensors", json={"name": name}, headers=auth_headers(token))
    assert r.status_code == 201, r.text
    return r.json()


async def _make_workload(client, token, name: str) -> dict:
    r = await client.post(
        f"{BASE}/workloads",
        json={"name": name, "mode": "observe", "dns": "off", "cgroup_patterns": []},
        headers=auth_headers(token),
    )
    assert r.status_code == 201, r.text
    return r.json()


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def test_violation_in_accepts_optional_ts():
    base = dict(workload_id=1, action="blocked", kind="connect")
    v_no_ts = ViolationIn(**base)
    assert v_no_ts.ts is None

    when = datetime(2026, 10, 17, 3, 15, 51, 189642, tzinfo=timezone.utc)
    v_with_ts = ViolationIn(**base, ts=when)
    assert v_with_ts.ts == when


def test_activity_in_accepts_optional_ts():
    base = dict(workload_id=1, kind="connect")
    a_no_ts = ActivityIn(**base)
    assert a_no_ts.ts is None

    when = datetime(2026, 10, 17, 3, 15, 51, tzinfo=timezone.utc)
    a_with_ts = ActivityIn(**base, ts=when)
    assert a_with_ts.ts == when


def test_policy_settings_update_rejects_out_of_range_retention():
    PolicySettingsUpdate(violation_retention_days=0)
    PolicySettingsUpdate(violation_retention_days=365)
    PolicySettingsUpdate(activity_retention_days=0)
    PolicySettingsUpdate(activity_retention_days=365)

    with pytest.raises(ValidationError):
        PolicySettingsUpdate(violation_retention_days=-1)
    with pytest.raises(ValidationError):
        PolicySettingsUpdate(violation_retention_days=366)
    with pytest.raises(ValidationError):
        PolicySettingsUpdate(activity_retention_days=-1)


async def test_ingest_violations_honours_ts(client, admin_token):
    w = await _make_workload(client, admin_token, "wl-ts-v")
    sensor = await _register_sensor(client, admin_token, "host-ts-v")
    # within the accepted window (services/egress_sensor.event_time)
    when = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    r = await client.post(
        f"{BASE}/violations",
        json={"events": [{
            "workload_id": w["id"], "action": "blocked", "kind": "connect",
            "protocol": "tcp", "dst_ip": "1.1.1.1", "dst_port": 443,
            "comm": "curl", "count": 1, "ts": when,
        }]},
        headers={"X-Sensor-Key": sensor["api_key"]},
    )
    assert r.status_code == 200, r.text

    r = await client.get(
        f"{BASE}/sensors/{sensor['id']}/violations",
        headers=auth_headers(admin_token),
    )
    events = r.json()
    assert len(events) == 1
    assert _parse_iso(events[0]["created_at"]) == _parse_iso(when)


async def test_ingest_activities_honours_ts(client, admin_token):
    w = await _make_workload(client, admin_token, "wl-ts-a")
    sensor = await _register_sensor(client, admin_token, "host-ts-a")
    # within the accepted window (services/egress_sensor.event_time)
    when = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    r = await client.post(
        f"{BASE}/activity",
        json={"events": [{
            "workload_id": w["id"], "action": "allowed", "kind": "connect",
            "protocol": "tcp", "dst_ip": "1.1.1.1", "dst_port": 443,
            "comm": "curl", "count": 1, "ts": when,
        }]},
        headers={"X-Sensor-Key": sensor["api_key"]},
    )
    assert r.status_code == 200, r.text

    r = await client.get(
        f"{BASE}/sensors/{sensor['id']}/activity",
        headers=auth_headers(admin_token),
    )
    events = r.json()
    assert len(events) == 1
    assert _parse_iso(events[0]["created_at"]) == _parse_iso(when)


async def test_ingest_violations_falls_back_to_now_when_ts_missing(client, admin_token):
    w = await _make_workload(client, admin_token, "wl-nots-v")
    sensor = await _register_sensor(client, admin_token, "host-nots-v")

    # Postgres now() inside a transaction returns the transaction start
    # time, not wall-clock. The test fixture holds one transaction for the
    # whole test, so created_at can be slightly before we captured the
    # "before" timestamp here. What matters is that the fallback produces
    # a recent, non-null timestamp (not the epoch, not "far in the past").
    r = await client.post(
        f"{BASE}/violations",
        json={"events": [{
            "workload_id": w["id"], "action": "blocked", "kind": "connect",
        }]},
        headers={"X-Sensor-Key": sensor["api_key"]},
    )
    assert r.status_code == 200, r.text

    r = await client.get(
        f"{BASE}/sensors/{sensor['id']}/violations",
        headers=auth_headers(admin_token),
    )
    created_at = _parse_iso(r.json()[0]["created_at"])
    now = datetime.now(timezone.utc)
    assert created_at is not None
    assert abs((now - created_at).total_seconds()) < 300, (
        f"fallback timestamp should be recent, got {created_at} (now={now})"
    )


async def test_ingest_ignores_event_times_far_from_the_server_clock(client, admin_token):
    """A sensor cannot date events into the past (retention would delete them
    at once) or the future (they would never age out): outside the window the
    server's time is stored instead."""
    w = await _make_workload(client, admin_token, "wl-ts-bad")
    sensor = await _register_sensor(client, admin_token, "host-ts-bad")
    now = datetime.now(timezone.utc)
    for path, action in (("violations", "blocked"), ("activity", "allowed")):
        r = await client.post(
            f"{BASE}/{path}",
            json={"events": [
                {"workload_id": w["id"], "action": action, "kind": "connect",
                 "comm": "past", "ts": (now - timedelta(days=400)).isoformat()},
                {"workload_id": w["id"], "action": action, "kind": "connect",
                 "comm": "future", "ts": (now + timedelta(days=30)).isoformat()},
            ]},
            headers={"X-Sensor-Key": sensor["api_key"]},
        )
        assert r.status_code == 200, r.text
        r = await client.get(f"{BASE}/sensors/{sensor['id']}/{path}", headers=auth_headers(admin_token))
        rows = r.json()
        assert {e["comm"] for e in rows} == {"past", "future"}
        for e in rows:
            assert abs((_parse_iso(e["created_at"]) - now).total_seconds()) < 300, e


def test_event_time_window():
    from app.services.egress_sensor import EVENT_TIME_FUTURE, EVENT_TIME_PAST, event_time

    now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
    assert event_time(None, now) is None
    assert event_time(now - timedelta(hours=3), now) == now - timedelta(hours=3)
    assert event_time(now - EVENT_TIME_PAST, now) == now - EVENT_TIME_PAST
    assert event_time(now - EVENT_TIME_PAST - timedelta(seconds=1), now) is None
    assert event_time(now + EVENT_TIME_FUTURE, now) == now + EVENT_TIME_FUTURE
    assert event_time(now + EVENT_TIME_FUTURE + timedelta(seconds=1), now) is None
    # no zone: taken as UTC
    assert event_time(datetime(2026, 10, 18, 11, 0), now) == datetime(2026, 10, 18, 11, 0, tzinfo=timezone.utc)


async def test_prune_violations_removes_rows_past_retention(db_session, org_and_users):
    org = org_and_users["org"]
    now = datetime.now(timezone.utc)
    db_session.add_all([
        EgressViolation(
            org_id=org.id, action="observed", kind="connect",
            created_at=now - timedelta(days=40),
        ),
        EgressViolation(
            org_id=org.id, action="observed", kind="connect",
            created_at=now - timedelta(days=2),
        ),
    ])
    await db_session.flush()

    deleted = await prune_violations(db_session, default_days=30)
    assert deleted == 1

    remaining = (await db_session.execute(
        select(func.count()).select_from(EgressViolation)
    )).scalar()
    assert remaining == 1


async def test_prune_violations_skips_orgs_with_zero_retention(db_session, org_and_users):
    org = org_and_users["org"]
    db_session.add(EgressPolicySettings(
        org_id=org.id,
        activity_retention_days=30,
        violation_retention_days=0,
    ))
    db_session.add(EgressViolation(
        org_id=org.id, action="observed", kind="connect",
        created_at=datetime.now(timezone.utc) - timedelta(days=400),
    ))
    await db_session.flush()

    deleted = await prune_violations(db_session, default_days=30)
    assert deleted == 0

    remaining = (await db_session.execute(
        select(func.count()).select_from(EgressViolation)
    )).scalar()
    assert remaining == 1


async def test_prune_activity_uses_activity_retention_independently(db_session, org_and_users):
    org = org_and_users["org"]
    db_session.add(EgressPolicySettings(
        org_id=org.id,
        activity_retention_days=7,
        violation_retention_days=30,
    ))
    now = datetime.now(timezone.utc)
    db_session.add_all([
        SensorActivity(
            org_id=org.id, action="allowed", kind="connect",
            created_at=now - timedelta(days=10),
        ),
        EgressViolation(
            org_id=org.id, action="observed", kind="connect",
            created_at=now - timedelta(days=40),
        ),
    ])
    await db_session.flush()

    deleted_activity = await prune_sensor_activity(db_session, default_days=7)
    assert deleted_activity == 1

    remaining_violations = (await db_session.execute(
        select(func.count()).select_from(EgressViolation)
    )).scalar()
    assert remaining_violations == 1

    deleted_violations = await prune_violations(db_session, default_days=30)
    assert deleted_violations == 1


async def test_prune_records_each_organizations_own_rows(db_session, org_and_users):
    """The status row of an organization says what was deleted for it, not the
    total of the run; an organization with settings but no rows gets a status
    too. chunk=2 makes the 3 rows of the first organization take two chunks."""
    from app.models.organization import Organization

    org = org_and_users["org"]
    other = Organization(name="Other", slug="other-org-prune")
    quiet = Organization(name="Quiet", slug="quiet-org-prune")
    db_session.add_all([other, quiet])
    await db_session.flush()
    db_session.add(EgressPolicySettings(org_id=quiet.id))
    old = datetime.now(timezone.utc) - timedelta(days=40)
    db_session.add_all(
        [SensorActivity(org_id=org.id, action="allowed", kind="connect", created_at=old) for _ in range(3)]
        + [SensorActivity(org_id=other.id, action="allowed", kind="connect", created_at=old)]
    )
    await db_session.flush()

    assert await prune_sensor_activity(db_session, default_days=30, chunk=2) == 4

    status = {
        s.org_id: s for s in (await db_session.execute(select(EgressPolicySettings))).scalars()
    }
    assert status[org.id].activity_last_prune_rows == 3
    assert status[other.id].activity_last_prune_rows == 1
    assert status[quiet.id].activity_last_prune_rows == 0
    for s in status.values():
        assert s.activity_last_pruned_at is not None
        assert s.activity_last_prune_error is None
        assert s.violation_last_pruned_at is None  # the other table is its own


async def test_prune_failure_is_recorded_and_does_not_stop_other_orgs(db_session, org_and_users, monkeypatch):
    """A failed prune sets the organization's error (the alert's input) and
    keeps last_pruned_at at the last success; the other organizations are
    still pruned, and the next good run clears the error."""
    from app.models.organization import Organization

    org = org_and_users["org"]
    other = Organization(name="Other", slug="other-org-prune-fail")
    db_session.add(other)
    await db_session.flush()
    last_ok = datetime.now(timezone.utc) - timedelta(hours=3)
    db_session.add(EgressPolicySettings(org_id=org.id, violation_last_pruned_at=last_ok))
    old = datetime.now(timezone.utc) - timedelta(days=40)
    db_session.add_all([
        EgressViolation(org_id=org.id, action="observed", kind="connect", created_at=old),
        EgressViolation(org_id=other.id, action="observed", kind="connect", created_at=old),
    ])
    await db_session.flush()

    real_execute = db_session.execute

    async def failing_for_org(stmt, *args, **kwargs):
        if getattr(stmt, "is_select", False) and "egress_violations.created_at <" in str(stmt) \
                and org.id in stmt.compile().params.values():
            raise RuntimeError("disk full")
        return await real_execute(stmt, *args, **kwargs)

    async def no_rollback():  # the injected error never reached the database
        return None

    monkeypatch.setattr(db_session, "execute", failing_for_org)
    monkeypatch.setattr(db_session, "rollback", no_rollback)
    assert await prune_violations(db_session, default_days=30) == 1
    monkeypatch.setattr(db_session, "execute", real_execute)

    status = {
        s.org_id: s for s in (await db_session.execute(select(EgressPolicySettings))).scalars()
    }
    assert status[org.id].violation_last_prune_error == "RuntimeError: disk full"
    assert status[org.id].violation_last_pruned_at == last_ok
    assert status[org.id].violation_last_prune_rows == 0
    assert status[other.id].violation_last_prune_error is None
    assert status[other.id].violation_last_prune_rows == 1

    assert await prune_violations(db_session, default_days=30) == 1
    await db_session.refresh(status[org.id])
    assert status[org.id].violation_last_prune_error is None
    assert status[org.id].violation_last_prune_rows == 1
    assert status[org.id].violation_last_pruned_at > last_ok


def test_metrics_module_exports_expected_metrics():
    from app.core import metrics as m

    for attr in (
        "http_requests_total",
        "http_request_duration_seconds",
        "sensor_violations_inserted_total",
        "sensor_violations_dropped_total",
        "sensor_activity_inserted_total",
        "sensor_activity_dropped_total",
        "sensor_activity_rows",
        "sensor_violations_rows",
        "sensor_last_heartbeat_age_seconds",
        "sensors_offline",
    ):
        assert hasattr(m, attr), f"metric {attr} missing from app.core.metrics"
