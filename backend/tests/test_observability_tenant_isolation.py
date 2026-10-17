"""Access control on the Prometheus proxy.

/metrics/query{,_range} is admin-only. Admins see the whole
installation (a self-hosted install is typically one organization), so
there is no per-org filtering. Approvers and users are refused at the
dependency level. label_replace / label_join are refused: they rewrite
labels and can quietly turn a series into a different one.
"""

import pytest

from tests.conftest import auth_headers

BASE = "/api/v1/metrics"


async def test_query_requires_admin(client, approver_token):
    """Approvers cannot reach the proxy at all."""
    r = await client.get(
        f"{BASE}/query?query=sensors_offline",
        headers=auth_headers(approver_token),
    )
    assert r.status_code == 403


async def test_query_range_requires_admin(client, approver_token):
    r = await client.get(
        f"{BASE}/query_range?query=sensors_offline&start=0&end=100&step=15s",
        headers=auth_headers(approver_token),
    )
    assert r.status_code == 403


async def test_admin_accepts_global_query(client, admin_token):
    """An admin query without org_id is forwarded (all-org view)."""
    r = await client.get(
        f"{BASE}/query?query=sensors_offline",
        headers=auth_headers(admin_token),
    )
    # 200 from Prometheus or 503 if Prometheus is unavailable in the test
    # environment; either is fine — the proxy accepted the request.
    assert r.status_code in (200, 503), r.text


async def test_admin_accepts_ops_metrics(client, admin_token):
    """HTTP counters are operator metrics; an admin must be able to graph them."""
    r = await client.get(
        f"{BASE}/query?query=rate(http_requests_total[5m])",
        headers=auth_headers(admin_token),
    )
    assert r.status_code in (200, 503), r.text


async def test_admin_rejects_label_replace(client, admin_token):
    """label_replace can forge a metric; still refused."""
    r = await client.get(
        f'{BASE}/query?query=label_replace(sensors_offline, "x", "y", "", "")',
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 400
    assert "label_replace" in r.json()["detail"]


async def test_admin_rejects_label_join(client, admin_token):
    r = await client.get(
        f'{BASE}/query?query=label_join(sensors_offline, "x", ",", "")',
        headers=auth_headers(admin_token),
    )
    assert r.status_code == 400


async def test_unauthenticated_rejected(client):
    r = await client.get(f"{BASE}/query?query=sensors_offline")
    assert r.status_code in (401, 403)
