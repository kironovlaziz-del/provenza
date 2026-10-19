"""Audit log: every write in the system should leave a trail here."""

import pytest

from tests.conftest import auth_headers


pytestmark = pytest.mark.asyncio


async def test_changing_the_policy_writes_an_audit_entry(client, org_and_users, admin_token):
    resp = await client.put(
        "/api/v1/policy-layers",
        json={"scope": "org", "yaml": "limits:\n  max_tokens: 100\n"},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200, resp.text

    logs_resp = await client.get(
        "/api/v1/audit-logs/",
        params={"entity_type": "policy_layer_org"},
        headers=auth_headers(admin_token),
    )
    assert logs_resp.status_code == 200
    items = logs_resp.json()["items"]
    assert len(items) == 1
    assert items[0]["action"] == "created"
    assert items[0]["entity_type"] == "policy_layer_org"


async def test_list_audit_logs_with_pagination_does_not_error(client, org_and_users, admin_token):
    """
    Regression test: list_logs() previously referenced an undeclared `skip`
    variable, and the API layer called it with skip=... as a keyword
    argument the method didn't accept - GET /audit-logs/ raised a 500 (or
    TypeError) on every single call. This just has to succeed at all.
    """
    for i in range(3):
        await client.post(
            "/api/v1/use-cases/",
            json={"name": f"Use Case {i}"},
            headers=auth_headers(admin_token),
        )

    resp = await client.get(
        "/api/v1/audit-logs/",
        params={"skip": 1, "limit": 2},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["skip"] == 1
    assert body["limit"] == 2
    assert len(body["items"]) <= 2


async def test_skip_actually_skips_the_most_recent_entry(client, org_and_users, admin_token):
    await client.post(
        "/api/v1/use-cases/", json={"name": "First"}, headers=auth_headers(admin_token)
    )
    await client.post(
        "/api/v1/use-cases/", json={"name": "Second"}, headers=auth_headers(admin_token)
    )

    no_skip = await client.get(
        "/api/v1/audit-logs/",
        params={"entity_type": "use_case", "limit": 10},
        headers=auth_headers(admin_token),
    )
    with_skip = await client.get(
        "/api/v1/audit-logs/",
        params={"entity_type": "use_case", "skip": 1, "limit": 10},
        headers=auth_headers(admin_token),
    )
    no_skip_ids = [item["id"] for item in no_skip.json()["items"]]
    with_skip_ids = [item["id"] for item in with_skip.json()["items"]]
    assert no_skip_ids[1:] == with_skip_ids
    assert no_skip_ids[0] not in with_skip_ids


async def test_audit_logs_are_scoped_to_organization(client, org_and_users, admin_token):
    await client.post(
        "/api/v1/use-cases/", json={"name": "Org A Only"}, headers=auth_headers(admin_token)
    )

    await client.post(
        "/api/v1/users/register",
        json={
            "email": "other-admin@test.example.com",
            "password": "TestPass123!",
            "name": "Other Admin",
            "org_name": "Other Org",
            "org_slug": "other-org-audit",
        },
    )
    login = await client.post(
        "/api/v1/auth/login",
        json={
            "org_slug": "other-org-audit",
            "email": "other-admin@test.example.com",
            "password": "TestPass123!",
        },
    )
    other_token = login.json()["access_token"]

    # The new org's own registration legitimately logs entries against
    # itself (org created, admin registered) - what must NOT leak across
    # is org A's "use_case" entry.
    resp = await client.get(
        "/api/v1/audit-logs/",
        params={"entity_type": "use_case"},
        headers=auth_headers(other_token),
    )
    assert resp.status_code == 200
    assert resp.json()["items"] == []
