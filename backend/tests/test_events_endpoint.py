"""Tests for the unified /events endpoint (SIEM/SOAR feed).

The endpoint merges egress_violations and sensor_activity into one
chronological stream. What matters here:
  * both tables are merged, not concatenated
  * event_type filter narrows to one table
  * sensor_id / since / until filters compose correctly
  * cursor pagination does not skip or duplicate rows
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from tests.conftest import auth_headers
from app.models.egress_sensor import EgressViolation, SensorActivity

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


async def _seed(client, token, sensor, wl, *, tag: str, n_vio: int, n_act: int) -> None:
    """Create n_vio violations and n_act activity rows, all tagged with comm=tag."""
    if n_vio:
        r = await client.post(
            f"{BASE}/violations",
            json={"events": [
                {
                    "workload_id": wl["id"], "action": "blocked", "kind": "connect",
                    "protocol": "tcp", "dst_ip": "1.1.1.1", "dst_port": 443,
                    "comm": tag, "count": i + 1,
                } for i in range(n_vio)
            ]},
            headers={"X-Sensor-Key": sensor["api_key"]},
        )
        assert r.status_code == 200, r.text
    if n_act:
        r = await client.post(
            f"{BASE}/activity",
            json={"events": [
                {
                    "workload_id": wl["id"], "action": "allowed", "kind": "connect",
                    "protocol": "tcp", "dst_ip": "8.8.8.8", "dst_port": 443,
                    "comm": tag, "count": i + 1,
                } for i in range(n_act)
            ]},
            headers={"X-Sensor-Key": sensor["api_key"]},
        )
        assert r.status_code == 200, r.text


def _filter_tag(events: list[dict], tag: str) -> list[dict]:
    return [e for e in events if e.get("comm") == tag]


# ------------------------------------------------------------------ tests

async def test_events_merges_both_tables(client, admin_token):
    sensor = await _register_sensor(client, admin_token, "s-merge")
    wl = await _make_workload(client, admin_token, "wl-merge")
    await _seed(client, admin_token, sensor, wl, tag="ev-merge", n_vio=5, n_act=3)

    r = await client.get(f"{BASE}/events?limit=200", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    body = r.json()
    tag_events = _filter_tag(body["events"], "ev-merge")

    assert len(tag_events) == 8
    by_type = {}
    for e in tag_events:
        by_type[e["event_type"]] = by_type.get(e["event_type"], 0) + 1
    assert by_type == {"violation": 5, "activity": 3}

    # Sorted newest-first.
    ts = [e["created_at"] for e in body["events"]]
    assert ts == sorted(ts, reverse=True)


async def test_events_filters_by_type(client, admin_token):
    sensor = await _register_sensor(client, admin_token, "s-type")
    wl = await _make_workload(client, admin_token, "wl-type")
    await _seed(client, admin_token, sensor, wl, tag="ev-type", n_vio=4, n_act=2)

    r = await client.get(
        f"{BASE}/events?event_type=violation&limit=200",
        headers=auth_headers(admin_token),
    )
    evs = _filter_tag(r.json()["events"], "ev-type")
    assert len(evs) == 4
    assert all(e["event_type"] == "violation" for e in evs)

    r = await client.get(
        f"{BASE}/events?event_type=activity&limit=200",
        headers=auth_headers(admin_token),
    )
    evs = _filter_tag(r.json()["events"], "ev-type")
    assert len(evs) == 2
    assert all(e["event_type"] == "activity" for e in evs)


async def test_events_filters_by_sensor(client, admin_token):
    s1 = await _register_sensor(client, admin_token, "s-s1")
    s2 = await _register_sensor(client, admin_token, "s-s2")
    wl = await _make_workload(client, admin_token, "wl-by-sensor")
    await _seed(client, admin_token, s1, wl, tag="ev-s1", n_vio=2, n_act=2)
    await _seed(client, admin_token, s2, wl, tag="ev-s2", n_vio=3, n_act=1)

    r = await client.get(
        f"{BASE}/events?sensor_id={s1['id']}&limit=200",
        headers=auth_headers(admin_token),
    )
    events = r.json()["events"]
    assert len(_filter_tag(events, "ev-s1")) == 4
    assert len(_filter_tag(events, "ev-s2")) == 0

    r = await client.get(
        f"{BASE}/events?sensor_id={s2['id']}&limit=200",
        headers=auth_headers(admin_token),
    )
    events = r.json()["events"]
    assert len(_filter_tag(events, "ev-s1")) == 0
    assert len(_filter_tag(events, "ev-s2")) == 4


async def test_events_filters_by_since_until(client, admin_token):
    """Use explicit ts: Postgres now() in the same transaction returns
    the same value for both seeds, so we cannot distinguish them by
    insertion time alone."""
    sensor = await _register_sensor(client, admin_token, "s-time")
    wl = await _make_workload(client, admin_token, "wl-time")

    now = datetime.now(timezone.utc)
    # isoformat() emits "+00:00" for UTC; the "+" turns into a space in a
    # query string, so the server never sees a valid datetime. Use Z.
    def _z(dt: datetime) -> str:
        return dt.isoformat().replace("+00:00", "Z")

    old_ts = _z(now - timedelta(hours=2))
    new_ts = _z(now)

    r = await client.post(
        f"{BASE}/violations",
        json={"events": [
            {"workload_id": wl["id"], "action": "blocked", "kind": "connect",
             "comm": "ev-old", "ts": old_ts},
            {"workload_id": wl["id"], "action": "blocked", "kind": "connect",
             "comm": "ev-new", "ts": new_ts},
        ]},
        headers={"X-Sensor-Key": sensor["api_key"]},
    )
    assert r.status_code == 200, r.text

    # since=now-1h should return only the new one
    since = _z(now - timedelta(hours=1))
    r = await client.get(
        f"{BASE}/events?since={since}&limit=200",
        headers=auth_headers(admin_token),
    )
    events = r.json()["events"]
    assert len(_filter_tag(events, "ev-new")) == 1
    assert len(_filter_tag(events, "ev-old")) == 0

    # until=now-1h should return only the old one
    until = _z(now - timedelta(hours=1))
    r = await client.get(
        f"{BASE}/events?until={until}&limit=200",
        headers=auth_headers(admin_token),
    )
    events = r.json()["events"]
    assert len(_filter_tag(events, "ev-new")) == 0
    assert len(_filter_tag(events, "ev-old")) == 1


async def test_events_paginates_by_cursor(client, admin_token):
    """Walk 25 events with limit=10; three pages, no skips, no duplicates."""
    sensor = await _register_sensor(client, admin_token, "s-page")
    wl = await _make_workload(client, admin_token, "wl-page")
    await _seed(client, admin_token, sensor, wl, tag="ev-page", n_vio=25, n_act=0)

    seen: set[tuple[str, int]] = set()
    cursor: str | None = None
    pages = 0
    for _ in range(10):  # safety bound
        url = f"{BASE}/events?event_type=violation&limit=10"
        if cursor:
            url += f"&cursor={cursor}"
        r = await client.get(url, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        body = r.json()
        pages += 1
        for e in body["events"]:
            key = (e["event_type"], e["id"])
            assert key not in seen, f"duplicate {key} across pages"
            seen.add(key)
        cursor = body["next_cursor"]
        if not cursor:
            break

    # Exactly 25 tagged rows in the DB at this point (other tests in this
    # module use their own sensor/workload, and the fixture rolls back).
    # If they ever leak into this test, len(seen) will exceed 25; we want
    # at least the 25 we created.
    assert len(seen) >= 25
    # The cursor should have been returned on page 1 and 2, and cleared
    # on page 3.
    assert pages == 3


async def test_events_rejects_bad_event_type(client, admin_token):
    r = await client.get(
        f"{BASE}/events?event_type=bogus",
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 422


async def test_events_requires_admin(client, approver_token):
    r = await client.get(f"{BASE}/events", headers=auth_headers(approver_token))
    assert r.status_code == 403


async def test_events_cursor_across_both_tables_at_one_time(client, admin_token):
    """Rows of one test share created_at (the transaction's now()), as a batch
    a sensor sent without event times does. Paging both tables through such
    a tie must still return every row once."""
    sensor = await _register_sensor(client, admin_token, "s-tie")
    wl = await _make_workload(client, admin_token, "wl-tie")
    await _seed(client, admin_token, sensor, wl, tag="ev-tie", n_vio=7, n_act=8)

    seen: list[tuple[str, int]] = []
    cursor: str | None = None
    for _ in range(20):
        url = f"{BASE}/events?limit=4" + (f"&cursor={cursor}" if cursor else "")
        r = await client.get(url, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        body = r.json()
        seen += [(e["event_type"], e["id"]) for e in _filter_tag(body["events"], "ev-tie")]
        cursor = body["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)), "an event came twice"
    assert sum(1 for et, _ in seen if et == "violation") == 7
    assert sum(1 for et, _ in seen if et == "activity") == 8


async def test_events_rejects_a_forged_cursor_type(client, admin_token):
    import base64, json
    bad = base64.urlsafe_b64encode(json.dumps({"t": "x", "i": 1, "c": "2026-01-01T00:00:00+00:00"}).encode()).decode()
    r = await client.get(f"{BASE}/events?cursor={bad}", headers=auth_headers(admin_token))
    assert r.status_code == 400
