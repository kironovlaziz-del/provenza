"""The dashboard's setup checklist (GET /api/v1/system/setup)."""

import pytest

from tests.conftest import auth_headers


@pytest.mark.asyncio
async def test_a_new_installation_shows_what_is_left(client, admin_token, approver_token):
    assert (await client.get("/api/v1/system/setup", headers=auth_headers(approver_token))).status_code == 403
    r = (await client.get("/api/v1/system/setup", headers=auth_headers(admin_token))).json()
    assert r["complete"] is False
    assert {i["key"]: i["done"] for i in r["items"]} == {
        "provider": False, "policy": False, "agent": False, "notifications": False, "mfa": False, "discovery": False}

    # requiring a second factor the admin does not have yet would lock them out of everything but enrolling
    r = await client.put("/api/v1/users/mfa-policy", json={"mfa_required": "reviewers"}, headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"] == "mfa.enroll_first"
