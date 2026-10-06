"""Request creation, encryption, firewall integration."""

import pytest

from tests.conftest import auth_headers


pytestmark = pytest.mark.asyncio


async def _create_provider(client, admin_token) -> int:
    resp = await client.post(
        "/api/v1/providers/",
        json={"name": "Test", "type": "openai"},
        headers=auth_headers(admin_token),
    )
    return resp.json()["id"]


async def _create_use_case(client, admin_token) -> int:
    resp = await client.post(
        "/api/v1/use-cases/",
        json={"name": "UC", "risk_level": "low"},
        headers=auth_headers(admin_token),
    )
    return resp.json()["id"]


async def test_request_masks_email_before_provider(
    client, org_and_users, admin_token
):
    provider_id = await _create_provider(client, admin_token)
    uc_id = await _create_use_case(client, admin_token)

    resp = await client.post(
        "/api/v1/requests/",
        json={
            "use_case_id": uc_id,
            "provider_id": provider_id,
            "input_text": "Email me at secret@example.com",
            "purpose": "test",
        },
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    # input_text is never returned, only the masked version
    assert "input_text" not in body
    assert "[MASKED:EMAIL]" in body["masked_input_text"]
    assert "secret@example.com" not in body["masked_input_text"]


async def test_request_raw_text_encrypted_at_rest(
    client, org_and_users, admin_token, db_session
):
    provider_id = await _create_provider(client, admin_token)
    uc_id = await _create_use_case(client, admin_token)

    await client.post(
        "/api/v1/requests/",
        json={
            "use_case_id": uc_id,
            "provider_id": provider_id,
            "input_text": "TopSecretValue123",
            "purpose": "test",
        },
        headers=auth_headers(admin_token),
    )

    from sqlalchemy import select
    from app.models.ai_request import AIRequest

    result = await db_session.execute(
        select(AIRequest).order_by(AIRequest.id.desc()).limit(1)
    )
    req = result.scalar_one()
    # Raw prompt must not appear in plaintext in the DB
    assert req.input_text_encrypted is not None
    assert "TopSecretValue123" not in req.input_text_encrypted
    # Fernet tokens start with "gAAAAA"
    assert req.input_text_encrypted.startswith("gAAAAA")


async def test_blocked_term_short_circuits(client, org_and_users, admin_token):
    """A prompt containing a blocked term is rejected and never sent."""
    # A policy with a policy-scoped blocked term, attached to a use case
    policy = await client.post(
        "/api/v1/policies/",
        json={"name": "Firewall"},
        headers=auth_headers(admin_token),
    )
    pid = policy.json()["id"]
    # terms in a policy version are refused now: they live on the Blocked terms page
    bad = await client.post(
        f"/api/v1/policies/{pid}/versions",
        json={"rules_json": {"blocked_terms": ["forbidden"]}},
        headers=auth_headers(admin_token),
    )
    assert bad.status_code == 422
    ver = await client.post(
        f"/api/v1/policies/{pid}/versions",
        json={"rules_json": {}},
        headers=auth_headers(admin_token),
    )
    t = await client.post("/api/v1/blocked-terms", json={"term": "forbidden", "scope": "policy", "target_id": pid},
                          headers=auth_headers(admin_token))
    assert t.status_code == 201, t.text
    vid = ver.json()["id"]
    await client.post(
        f"/api/v1/policies/{pid}/versions/{vid}/approve",
        headers=auth_headers(admin_token),
    )
    uc = await client.post(
        "/api/v1/use-cases/",
        json={"name": "UC", "risk_level": "low"},
        headers=auth_headers(admin_token),
    )
    ucid = uc.json()["id"]
    await client.put(
        f"/api/v1/use-cases/{ucid}",
        json={"approved_policy_version_id": vid},
        headers=auth_headers(admin_token),
    )
    provider_id = await _create_provider(client, admin_token)

    resp = await client.post(
        "/api/v1/requests/",
        json={
            "use_case_id": ucid,
            "provider_id": provider_id,
            "input_text": "This contains forbidden content",
            "purpose": "test",
        },
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "blocked"
    assert any("blocked_term" in f for f in resp.json()["firewall_flags"])


async def test_request_other_org_not_visible(
    client, org_and_users, admin_token, db_session
):
    """Sanity check that org_id filtering works."""
    from app.models.organization import Organization
    from app.models.user import User, UserRole
    from app.core.security import get_password_hash

    # Create a second org with its own admin directly in the DB
    other_org = Organization(name="Other", slug="other-org")
    db_session.add(other_org)
    await db_session.flush()
    other_admin = User(
        org_id=other_org.id,
        email="other@test.example.com",
        name="Other Admin",
        hashed_password=get_password_hash("TestPass123!"),
        role=UserRole.admin.value,
        status="active",
    )
    db_session.add(other_admin)
    await db_session.flush()

    login = await client.post(
        "/api/v1/auth/login",
        json={
            "org_slug": "other-org",
            "email": "other@test.example.com",
            "password": "TestPass123!",
        },
    )
    other_token = login.json()["access_token"]

    # Other admin sees an empty list, not the first org's requests
    resp = await client.get(
        "/api/v1/requests/", headers=auth_headers(other_token)
    )
    assert resp.status_code == 200
    assert resp.json()["items"] == []
