"""Alertmanager webhook receiver.

Two things to protect: the shared-secret gate (a self-hosted install
must not expose the endpoint to the internet), and the fan-out path
(each firing alert with an org_id must produce a notify() call for that
organization).
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.config import settings


BASE = "/api/v1/metrics/alerts"
SECRET = "test-alertmanager-secret"


def _payload(alerts):
    return {
        "version": "4",
        "status": "firing",
        "groupLabels": {},
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": "http://localhost:9093",
        "alerts": alerts,
    }


def _firing(org_id: int, alertname: str = "TestAlert", severity: str = "warning"):
    return {
        "status": "firing",
        "labels": {
            "alertname": alertname,
            "severity": severity,
            "org_id": str(org_id),
        },
        "annotations": {
            "summary": f"{alertname} summary",
            "description": f"{alertname} description",
        },
        "startsAt": "2026-10-17T05:00:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
    }


@pytest.fixture
def with_secret(monkeypatch):
    monkeypatch.setattr(settings, "ALERTMANAGER_SECRET", SECRET)
    yield


async def test_alerts_503_when_secret_unset(client, monkeypatch):
    """No secret in settings means the endpoint refuses to ingest —
    better than accidentally exposing it."""
    monkeypatch.setattr(settings, "ALERTMANAGER_SECRET", "")
    r = await client.post(BASE, json=_payload([_firing(7)]), headers={"Authorization": "Bearer x"})
    assert r.status_code == 503


async def test_alerts_401_missing_token(client, with_secret):
    r = await client.post(BASE, json=_payload([_firing(7)]))
    assert r.status_code == 401


async def test_alerts_401_wrong_token(client, with_secret):
    r = await client.post(
        BASE,
        json=_payload([_firing(7)]),
        headers={"Authorization": "Bearer wrong"},
    )
    assert r.status_code == 401


async def test_alerts_firing_calls_notify(client, with_secret):
    with patch("app.api.prometheus.notification_service.notify", new_callable=AsyncMock) as notify:
        r = await client.post(
            BASE,
            json=_payload([_firing(7, "TestAlert", "critical")]),
            headers={"Authorization": f"Bearer {SECRET}"},
        )
    assert r.status_code == 200, r.text
    assert r.json() == {"processed": 1, "skipped": 0}
    assert notify.await_count == 1
    _, kwargs = notify.call_args
    assert kwargs["org_id"] == 7
    assert kwargs["event_type"] == "alert"
    assert "CRITICAL" in kwargs["subject"]
    assert "TestAlert" in kwargs["subject"]


async def test_alerts_skips_without_org_id(client, with_secret):
    no_org = _firing(7)
    del no_org["labels"]["org_id"]
    with patch("app.api.prometheus.notification_service.notify", new_callable=AsyncMock) as notify:
        r = await client.post(
            BASE,
            json=_payload([no_org]),
            headers={"Authorization": f"Bearer {SECRET}"},
        )
    assert r.status_code == 200
    assert r.json() == {"processed": 0, "skipped": 1}
    assert notify.await_count == 0


async def test_alerts_resolved_is_acknowledged_not_fanned(client, with_secret):
    resolved = _firing(7)
    resolved["status"] = "resolved"
    with patch("app.api.prometheus.notification_service.notify", new_callable=AsyncMock) as notify:
        r = await client.post(
            BASE,
            json=_payload([resolved]),
            headers={"Authorization": f"Bearer {SECRET}"},
        )
    assert r.status_code == 200
    assert r.json() == {"processed": 0, "skipped": 0}
    assert notify.await_count == 0


async def test_alerts_multiple_in_one_payload(client, with_secret):
    payload = _payload([
        _firing(7, "A"),
        _firing(7, "B"),
        _firing(11, "C"),
    ])
    with patch("app.api.prometheus.notification_service.notify", new_callable=AsyncMock) as notify:
        r = await client.post(
            BASE,
            json=payload,
            headers={"Authorization": f"Bearer {SECRET}"},
        )
    assert r.status_code == 200
    assert r.json() == {"processed": 3, "skipped": 0}
    assert notify.await_count == 3
    orgs = sorted(call.kwargs["org_id"] for call in notify.call_args_list)
    assert orgs == [7, 7, 11]


async def test_alert_reaches_a_subscribed_channel(client, org_and_users, admin_token, with_secret, monkeypatch):
    """End to end: "alert" is an event a channel can subscribe to, and a
    firing alert for the organization reaches that channel (and not one
    subscribed to something else)."""
    from tests.conftest import auth_headers

    types = (await client.get("/api/v1/notification-channels/event-types")).json()["event_types"]
    assert "alert" in types

    sent = []
    monkeypatch.setattr(
        "app.services.notification_service._dispatch",
        lambda channel, subject, message, metadata: sent.append((channel.target, subject)),
    )
    for target, events in (("https://example.com/alerts", ["alert"]),
                           ("https://example.com/incidents", ["incident_created"])):
        r = await client.post("/api/v1/notification-channels/",
                              json={"channel_type": "webhook", "target": target, "events": events},
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text

    org_id = org_and_users["org"].id
    r = await client.post(BASE, json=_payload([_firing(org_id, "AuditUnsealedRecords")]),
                          headers={"Authorization": f"Bearer {SECRET}"})
    assert r.status_code == 200, r.text
    assert sent == [("https://example.com/alerts", "[WARNING] AuditUnsealedRecords")]


async def test_channel_rejects_unknown_event_types(client, org_and_users, admin_token):
    from tests.conftest import auth_headers

    r = await client.post("/api/v1/notification-channels/",
                          json={"channel_type": "email", "target": "ops@example.com",
                                "events": ["alert", "no_such_event"]},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422
    assert "no_such_event" in r.text
