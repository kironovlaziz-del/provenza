"""Access control on the Prometheus proxy.

/metrics/query{,_range} answers the installation's operator only: an
administrator of the first organization. The metrics cover the whole
installation (every organization's sensors and tables), so administrators
of organizations created later by public sign-up are refused, as are
approvers and users. label_replace / label_join are refused: they rewrite
labels and can quietly turn a series into a different one.
"""

import pytest

from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers

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


async def _tenant_admin_token(client, db_session) -> str:
    """An administrator of a second organization, as public sign-up makes."""
    other = await _create_org_with_admin_and_approver(
        db_session, org_slug="tenant-org",
        admin_email="admin@tenant.example.com", approver_email="approver@tenant.example.com",
    )
    return await _login(client, "tenant-org", other["admin"].email, other["password"])


async def test_tenant_admin_cannot_query(client, admin_token, db_session):
    """Another organization's administrator would see every organization's
    sensors and tables through the proxy: refused."""
    token = await _tenant_admin_token(client, db_session)
    for path in ("query?query=sensors_offline", "query_range?query=sensors_offline&start=0&end=100&step=15s"):
        r = await client.get(f"{BASE}/{path}", headers=auth_headers(token))
        assert r.status_code == 403, r.text
        assert r.json()["detail"] == "rbac.operator_only"


async def test_me_says_who_is_the_operator(client, admin_token, approver_token, db_session):
    """The UI shows the monitoring page to the operator only."""
    r = await client.get("/api/v1/users/me", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["is_operator"] is True
    r = await client.get("/api/v1/users/me", headers=auth_headers(approver_token))
    assert r.json()["is_operator"] is False
    token = await _tenant_admin_token(client, db_session)
    r = await client.get("/api/v1/users/me", headers=auth_headers(token))
    assert r.json()["is_operator"] is False
