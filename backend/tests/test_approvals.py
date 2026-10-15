"""Approval workflow - approver assignment and decision permissions."""

import pytest

from tests.conftest import auth_headers


pytestmark = pytest.mark.asyncio


async def _make_use_case_with_approval_policy(
    client, admin_token
) -> tuple[int, int, int]:
    """Returns (use_case_id, provider_id, policy_version_id)."""
    # Policy + version with require_approval
    policy_resp = await client.post(
        "/api/v1/policies/",
        json={"name": "Require Approval"},
        headers=auth_headers(admin_token),
    )
    policy_id = policy_resp.json()["id"]

    version_resp = await client.post(
        f"/api/v1/policies/{policy_id}/versions",
        json={"rules_json": {"effect": "require_approval"}},
        headers=auth_headers(admin_token),
    )
    version_id = version_resp.json()["id"]

    await client.post(
        f"/api/v1/policies/{policy_id}/versions/{version_id}/approve",
        headers=auth_headers(admin_token),
    )

    use_case_resp = await client.post(
        "/api/v1/use-cases/",
        json={"name": "UC", "risk_level": "low"},
        headers=auth_headers(admin_token),
    )
    use_case_id = use_case_resp.json()["id"]

    await client.put(
        f"/api/v1/use-cases/{use_case_id}",
        json={"approved_policy_version_id": version_id},
        headers=auth_headers(admin_token),
    )

    provider_resp = await client.post(
        "/api/v1/providers/",
        json={"name": "Test", "type": "openai"},
        headers=auth_headers(admin_token),
    )
    provider_id = provider_resp.json()["id"]

    return use_case_id, provider_id, version_id


async def test_approver_auto_assigned_server_side(
    client, org_and_users, admin_token
):
    use_case_id, provider_id, _ = await _make_use_case_with_approval_policy(
        client, admin_token
    )

    req_resp = await client.post(
        "/api/v1/requests/",
        json={
            "use_case_id": use_case_id,
            "provider_id": provider_id,
            "input_text": "test",
            "purpose": "test",
        },
        headers=auth_headers(admin_token),
    )
    assert req_resp.status_code == 200
    request_id = req_resp.json()["id"]

    approval_resp = await client.post(
        "/api/v1/approvals/",
        json={"request_id": request_id},
        headers=auth_headers(admin_token),
    )
    assert approval_resp.status_code == 200
    # The approver must be the approver user, not the admin who called.
    assert approval_resp.json()["approver_user_id"] == org_and_users["approver"].id


async def test_client_cannot_specify_approver(client, org_and_users, admin_token):
    """extra='forbid' makes a rogue approver_user_id fail with 422."""
    resp = await client.post(
        "/api/v1/approvals/",
        json={"request_id": 1, "approver_user_id": 999},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 422


async def test_only_assigned_approver_can_decide(
    client, org_and_users, admin_token, approver_token
):
    use_case_id, provider_id, _ = await _make_use_case_with_approval_policy(
        client, admin_token
    )

    req = await client.post(
        "/api/v1/requests/",
        json={
            "use_case_id": use_case_id,
            "provider_id": provider_id,
            "input_text": "x",
            "purpose": "x",
        },
        headers=auth_headers(admin_token),
    )
    request_id = req.json()["id"]

    approval = await client.post(
        "/api/v1/approvals/",
        json={"request_id": request_id},
        headers=auth_headers(admin_token),
    )
    approval_id = approval.json()["id"]

    # Create a second approver that was NOT assigned
    await client.post(
        "/api/v1/users/invite",
        json={
            "email": "approver2@test.example.com",
            "name": "A2",
            "password": "TestPass123!",
            "role": "approver",
        },
        headers=auth_headers(admin_token),
    )
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "org_slug": org_and_users["org"].slug,
            "email": "approver2@test.example.com",
            "password": "TestPass123!",
        },
    )
    approver2_token = login_resp.json()["access_token"]

    # Non-assigned approver is rejected
    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        json={"decision": "approved"},
        headers=auth_headers(approver2_token),
    )
    assert resp.status_code == 403

    # Assigned approver can decide
    resp = await client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        json={"decision": "approved"},
        headers=auth_headers(approver_token),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "approved"


async def test_duplicate_pending_approval_rejected(
    client, org_and_users, admin_token
):
    use_case_id, provider_id, _ = await _make_use_case_with_approval_policy(
        client, admin_token
    )
    req = await client.post(
        "/api/v1/requests/",
        json={
            "use_case_id": use_case_id,
            "provider_id": provider_id,
            "input_text": "x",
            "purpose": "x",
        },
        headers=auth_headers(admin_token),
    )
    request_id = req.json()["id"]

    r1 = await client.post(
        "/api/v1/approvals/",
        json={"request_id": request_id},
        headers=auth_headers(admin_token),
    )
    assert r1.status_code == 200

    r2 = await client.post(
        "/api/v1/approvals/",
        json={"request_id": request_id},
        headers=auth_headers(admin_token),
    )
    assert r2.status_code == 400
    assert "pending approval" in r2.json()["detail"]


async def _pending_request(client, token, use_case_id, provider_id) -> int:
    r = await client.post(
        "/api/v1/requests/",
        json={"use_case_id": use_case_id, "provider_id": provider_id, "input_text": "x", "purpose": "x"},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def test_an_approver_is_never_assigned_their_own_request(
    client, org_and_users, admin_token, approver_token
):
    use_case_id, provider_id, _ = await _make_use_case_with_approval_policy(client, admin_token)
    request_id = await _pending_request(client, approver_token, use_case_id, provider_id)
    r = await client.post("/api/v1/approvals/", json={"request_id": request_id},
                          headers=auth_headers(approver_token))
    assert r.status_code == 200, r.text
    assert r.json()["approver_user_id"] != org_and_users["approver"].id
    assert r.json()["approver_user_id"] == org_and_users["admin"].id


async def test_an_admin_cannot_decide_their_own_request(
    client, org_and_users, admin_token
):
    use_case_id, provider_id, _ = await _make_use_case_with_approval_policy(client, admin_token)
    request_id = await _pending_request(client, admin_token, use_case_id, provider_id)
    approval = await client.post("/api/v1/approvals/", json={"request_id": request_id},
                                 headers=auth_headers(admin_token))
    assert approval.status_code == 200, approval.text
    r = await client.post(f"/api/v1/approvals/{approval.json()['id']}/decision",
                          json={"decision": "approved"}, headers=auth_headers(admin_token))
    assert r.status_code == 403
    assert "own request" in r.json()["detail"]


async def test_only_a_request_waiting_for_approval_can_be_routed(
    client, org_and_users, admin_token
):
    provider = await client.post("/api/v1/providers/", json={"name": "P", "type": "openai"},
                                 headers=auth_headers(admin_token))
    use_case = await client.post("/api/v1/use-cases/", json={"name": "Plain", "risk_level": "low"},
                                 headers=auth_headers(admin_token))
    request_id = await _pending_request(client, admin_token, use_case.json()["id"], provider.json()["id"])
    r = await client.post("/api/v1/approvals/", json={"request_id": request_id},
                          headers=auth_headers(admin_token))
    assert r.status_code == 400
    assert "waiting for approval" in r.json()["detail"]
