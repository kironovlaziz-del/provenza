"""Use Case registry: creation, partial updates, and org isolation."""

import pytest

from tests.conftest import auth_headers


pytestmark = pytest.mark.asyncio


async def test_create_use_case_defaults_to_active_and_low_risk(
    client, org_and_users, admin_token
):
    resp = await client.post(
        "/api/v1/use-cases/",
        json={"name": "Customer Support Bot"},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "active"
    assert body["risk_level"] == "low"


async def test_create_use_case_with_explicit_risk_level(client, org_and_users, admin_token):
    resp = await client.post(
        "/api/v1/use-cases/",
        json={"name": "Medical Triage Assistant", "risk_level": "critical"},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["risk_level"] == "critical"


async def test_update_use_case_is_partial(client, org_and_users, admin_token):
    create_resp = await client.post(
        "/api/v1/use-cases/",
        json={"name": "Original Name", "risk_level": "medium"},
        headers=auth_headers(admin_token),
    )
    use_case_id = create_resp.json()["id"]

    # Only touch the status - name and risk_level must be left alone.
    update_resp = await client.put(
        f"/api/v1/use-cases/{use_case_id}",
        json={"status": "retired"},
        headers=auth_headers(admin_token),
    )
    assert update_resp.status_code == 200
    body = update_resp.json()
    assert body["status"] == "retired"
    assert body["name"] == "Original Name"
    assert body["risk_level"] == "medium"


async def test_use_case_not_found_returns_404(client, org_and_users, admin_token):
    resp = await client.get(
        "/api/v1/use-cases/999999", headers=auth_headers(admin_token)
    )
    assert resp.status_code == 404


async def test_use_case_update_not_found_returns_404(client, org_and_users, admin_token):
    resp = await client.put(
        "/api/v1/use-cases/999999",
        json={"name": "Nope"},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 404


async def test_use_case_list_is_scoped_to_organization(client, org_and_users, admin_token):
    await client.post(
        "/api/v1/use-cases/",
        json={"name": "Org A Use Case"},
        headers=auth_headers(admin_token),
    )

    await client.post(
        "/api/v1/users/register",
        json={
            "email": "other-admin@test.example.com",
            "password": "TestPass123!",
            "name": "Other Admin",
            "org_name": "Other Org",
            "org_slug": "other-org-usecases",
        },
    )
    login = await client.post(
        "/api/v1/auth/login",
        json={
            "org_slug": "other-org-usecases",
            "email": "other-admin@test.example.com",
            "password": "TestPass123!",
        },
    )
    other_token = login.json()["access_token"]

    resp = await client.get(
        "/api/v1/use-cases/", headers=auth_headers(other_token)
    )
    assert resp.status_code == 200
    assert resp.json()["items"] == []


# ---------------------------------------------------------------------------
# Governance of the use case itself: who may change it, and who may own it.
# ---------------------------------------------------------------------------

from tests.conftest import _create_org_with_admin_and_approver  # noqa: E402


async def test_only_admin_can_create_or_change_use_cases(client, org_and_users, admin_token, approver_token):
    resp = await client.post("/api/v1/use-cases/", json={"name": "X"}, headers=auth_headers(approver_token))
    assert resp.status_code == 403
    uc = await client.post("/api/v1/use-cases/", json={"name": "X"}, headers=auth_headers(admin_token))
    resp = await client.put(f"/api/v1/use-cases/{uc.json()['id']}", json={"risk_level": "low"},
                            headers=auth_headers(approver_token))
    assert resp.status_code == 403


async def test_owner_must_belong_to_the_organization(client, db_session, org_and_users, admin_token):
    other = await _create_org_with_admin_and_approver(
        db_session, org_slug="uc-owner", admin_email="a@uc-owner.test", approver_email="p@uc-owner.test")
    resp = await client.post("/api/v1/use-cases/", json={"name": "X", "owner_user_id": other["admin"].id},
                             headers=auth_headers(admin_token))
    assert resp.status_code == 422
    assert resp.json()["detail"] == "use_case.owner_not_found"

    resp = await client.post("/api/v1/use-cases/", json={"name": "X", "owner_user_id": org_and_users["approver"].id},
                             headers=auth_headers(admin_token))
    assert resp.status_code == 200
    assert "approved_policy_version_id" not in resp.json()
