"""AI Providers: credential handling and admin-only writes."""

import pytest

from tests.conftest import auth_headers


pytestmark = pytest.mark.asyncio


async def test_create_provider_requires_admin(client, org_and_users, approver_token):
    resp = await client.post(
        "/api/v1/providers/",
        json={"name": "OpenAI", "type": "openai", "api_key": "sk-test123"},
        headers=auth_headers(approver_token),
    )
    assert resp.status_code == 403


async def test_api_key_is_never_returned(client, org_and_users, admin_token):
    resp = await client.post(
        "/api/v1/providers/",
        json={"name": "Anthropic", "type": "anthropic", "api_key": "sk-ant-secret"},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "api_key" not in body
    assert "api_key_encrypted" not in body
    assert body["has_credentials"] is True


async def test_provider_without_key_has_no_credentials_flag(client, org_and_users, admin_token):
    resp = await client.post(
        "/api/v1/providers/",
        json={"name": "No Key Provider", "type": "custom"},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    assert resp.json()["has_credentials"] is False


async def test_changing_provider_type_clears_stored_credential(client, org_and_users, admin_token):
    create_resp = await client.post(
        "/api/v1/providers/",
        json={"name": "Switchable", "type": "openai", "api_key": "sk-openai-key"},
        headers=auth_headers(admin_token),
    )
    provider_id = create_resp.json()["id"]
    assert create_resp.json()["has_credentials"] is True

    update_resp = await client.put(
        f"/api/v1/providers/{provider_id}",
        json={"type": "anthropic"},
        headers=auth_headers(admin_token),
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["has_credentials"] is False
    assert update_resp.json()["type"] == "anthropic"


async def test_updating_without_type_change_keeps_credential(client, org_and_users, admin_token):
    create_resp = await client.post(
        "/api/v1/providers/",
        json={"name": "Stable Type", "type": "openai", "api_key": "sk-openai-key"},
        headers=auth_headers(admin_token),
    )
    provider_id = create_resp.json()["id"]

    update_resp = await client.put(
        f"/api/v1/providers/{provider_id}",
        json={"sla": "99.9%"},
        headers=auth_headers(admin_token),
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["has_credentials"] is True
    assert update_resp.json()["sla"] == "99.9%"


async def test_empty_string_api_key_clears_credential(client, org_and_users, admin_token):
    create_resp = await client.post(
        "/api/v1/providers/",
        json={"name": "Clearable", "type": "openai", "api_key": "sk-openai-key"},
        headers=auth_headers(admin_token),
    )
    provider_id = create_resp.json()["id"]

    update_resp = await client.put(
        f"/api/v1/providers/{provider_id}",
        json={"api_key": ""},
        headers=auth_headers(admin_token),
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["has_credentials"] is False


async def test_provider_not_found_returns_404(client, org_and_users, admin_token):
    resp = await client.get(
        "/api/v1/providers/999999", headers=auth_headers(admin_token)
    )
    assert resp.status_code == 404


async def test_non_admin_can_still_read_providers(client, org_and_users, admin_token, approver_token):
    await client.post(
        "/api/v1/providers/",
        json={"name": "Readable", "type": "custom"},
        headers=auth_headers(admin_token),
    )
    resp = await client.get(
        "/api/v1/providers/", headers=auth_headers(approver_token)
    )
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 1


async def test_a_changed_key_is_not_written_to_the_audit_log(client, org_and_users, admin_token):
    created = await client.post("/api/v1/providers/", json={"name": "Keyed", "type": "openai"},
                                headers=auth_headers(admin_token))
    pid = created.json()["id"]
    r = await client.put(f"/api/v1/providers/{pid}", json={"api_key": "sk-audit-leak-check"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    logs = await client.get("/api/v1/audit-logs/", params={"entity_type": "provider", "entity_id": pid},
                            headers=auth_headers(admin_token))
    assert logs.status_code == 200
    assert "sk-audit-leak-check" not in logs.text
    updated = [e for e in logs.json()["items"] if e["action"] == "updated"]
    assert updated and updated[0]["metadata_json"]["api_key"] == "set"
