"""Incident tracking: creation, resolution timestamps, and notifications."""

import pytest

from tests.conftest import auth_headers


pytestmark = pytest.mark.asyncio


async def test_create_incident_starts_open_with_no_resolution(client, org_and_users, admin_token):
    resp = await client.post(
        "/api/v1/incidents/",
        json={
            "severity": "high",
            "category": "data_leak",
            "summary": "PII sent to an unapproved provider",
        },
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "open"
    assert body["resolved_at"] is None
    assert body["severity"] == "high"


async def test_resolving_incident_sets_resolved_at(client, org_and_users, admin_token):
    create_resp = await client.post(
        "/api/v1/incidents/",
        json={"severity": "low", "category": "policy_violation", "summary": "test"},
        headers=auth_headers(admin_token),
    )
    incident_id = create_resp.json()["id"]
    assert create_resp.json()["resolved_at"] is None

    update_resp = await client.put(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved", "root_cause": "Misconfigured policy"},
        headers=auth_headers(admin_token),
    )
    assert update_resp.status_code == 200
    body = update_resp.json()
    assert body["status"] == "resolved"
    assert body["resolved_at"] is not None
    assert body["root_cause"] == "Misconfigured policy"


async def test_updating_non_status_fields_does_not_set_resolved_at(
    client, org_and_users, admin_token
):
    create_resp = await client.post(
        "/api/v1/incidents/",
        json={"severity": "low", "category": "other", "summary": "test"},
        headers=auth_headers(admin_token),
    )
    incident_id = create_resp.json()["id"]

    update_resp = await client.put(
        f"/api/v1/incidents/{incident_id}",
        json={"impact": "Minor - one user affected"},
        headers=auth_headers(admin_token),
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["resolved_at"] is None
    assert update_resp.json()["status"] == "open"


async def test_incident_creation_dispatches_notification(
    client, org_and_users, admin_token, monkeypatch
):
    calls = []

    async def _fake_notify(db, org_id, event_type, subject, message, metadata=None):
        calls.append(event_type)

    monkeypatch.setattr(
        "app.api.incidents.notification_service.notify", _fake_notify
    )

    resp = await client.post(
        "/api/v1/incidents/",
        json={"severity": "critical", "category": "outage", "summary": "test"},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 200
    assert calls == ["incident_created"]


async def test_incident_not_found_returns_404(client, org_and_users, admin_token):
    resp = await client.get(
        "/api/v1/incidents/999999", headers=auth_headers(admin_token)
    )
    assert resp.status_code == 404


async def test_incident_cannot_reference_another_organizations_request(client, org_and_users, admin_token):
    resp = await client.post(
        "/api/v1/incidents/",
        json={"severity": "low", "category": "policy_violation", "summary": "x", "request_id": 987654},
        headers=auth_headers(admin_token),
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == "incident.request_not_found"
