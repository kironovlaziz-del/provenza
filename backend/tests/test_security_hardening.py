"""
Security fixes from the 2026-10 audit: who may triage incidents and Shadow AI
sightings, what a (public) browser extension key may send, notifications that
a batch cannot flood or inject into, ending sessions, security headers, and
the attestation fetch going through the outbound guard.
"""

import httpx
import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.security import generate_api_key, get_password_hash, hash_api_key
from app.models.ingestion_source import IngestionSource
from app.models.user import User, UserRole
from app.schemas.telemetry import TelemetryEventIn
from app.services import telemetry_service
from app.services.telemetry_service import TelemetryService
from tests.conftest import _login, auth_headers


async def _plain_user(db, client, org_and_users) -> str:
    org = org_and_users["org"]
    db.add(User(org_id=org.id, email="user@test.example.com", name="User", role=UserRole.user.value,
                hashed_password=get_password_hash("TestPass123!"), status="active"))
    await db.flush()
    return await _login(client, org.slug, "user@test.example.com", "TestPass123!")


async def _source(db, org_id, source_type):
    key = generate_api_key()
    db.add(IngestionSource(org_id=org_id, name=f"{source_type}-src", source_type=source_type,
                           api_key_hash=hash_api_key(key), enabled=True))
    await db.flush()
    return {"X-Ingestion-Key": key}


# ---------------------------------------------------------------- who may triage

@pytest.mark.asyncio
async def test_only_reviewers_triage_incidents_and_sightings(client, db_session, org_and_users, admin_token,
                                                             approver_token):
    user = await _plain_user(db_session, client, org_and_users)
    inc = await client.post("/api/v1/incidents/", json={"severity": "high", "category": "data_leak",
                                                         "summary": "x"}, headers=auth_headers(user))
    assert inc.status_code == 200, inc.text          # anyone may report
    iid = inc.json()["id"]
    assert (await client.put(f"/api/v1/incidents/{iid}", json={"status": "resolved"},
                             headers=auth_headers(user))).status_code == 403
    assert (await client.put(f"/api/v1/incidents/{iid}", json={"severity": "low"},
                             headers=auth_headers(user))).status_code == 403
    assert (await client.put(f"/api/v1/incidents/{iid}", json={"status": "whatever"},
                             headers=auth_headers(approver_token))).status_code == 422
    r = await client.put(f"/api/v1/incidents/{iid}", json={"status": "resolved"}, headers=auth_headers(approver_token))
    assert r.status_code == 200 and r.json()["status"] == "resolved"

    s = await client.post("/api/v1/shadow-ai/", json={"tool_name": "SomeAI", "domain": "some.ai"},
                          headers=auth_headers(user))
    sid = s.json()["id"]
    assert (await client.put(f"/api/v1/shadow-ai/{sid}", json={"status": "dismissed"},
                             headers=auth_headers(user))).status_code == 403
    assert (await client.put(f"/api/v1/shadow-ai/{sid}", json={"status": "registered"},
                             headers=auth_headers(admin_token))).status_code == 422     # only via /register
    assert (await client.put(f"/api/v1/shadow-ai/{sid}", json={"status": "dismissed"},
                             headers=auth_headers(approver_token))).status_code == 200


@pytest.mark.asyncio
async def test_notification_channels_are_admin_only(client, approver_token, admin_token):
    r = await client.post("/api/v1/notification-channels/", json={
        "channel_type": "webhook", "target": "https://hooks.example.com/T000/secret", "events": ["incident_created"]},
        headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert (await client.get("/api/v1/notification-channels/", headers=auth_headers(approver_token))).status_code == 403
    assert (await client.post(f"/api/v1/notification-channels/{r.json()['id']}/test",
                              headers=auth_headers(approver_token))).status_code == 403


# ---------------------------------------------------------------- ingestion keys

def _visit(domain="chat.example-ai.com", **over):
    return {"event_type": "domain_visit", "domain": domain, **over}


@pytest.mark.asyncio
async def test_an_extension_key_reports_domain_visits_only(client, db_session, org_and_users, mock_celery_send_task):
    ext = await _source(db_session, org_and_users["org"].id, "browser_extension")
    assert (await client.post("/api/v1/shadow-ai/ingest", json={"events": [_visit()]}, headers=ext)).status_code == 202
    r = await client.post("/api/v1/shadow-ai/ingest", json={"events": [
        _visit(), {"event_type": "agent_detected", "domain": "localhost", "payload": {"product": "claude-code"}}]},
        headers=ext)
    assert r.status_code == 403 and r.json()["detail"] == "ingestion.event_type_not_allowed"
    endpoint = await _source(db_session, org_and_users["org"].id, "endpoint")
    assert (await client.post("/api/v1/shadow-ai/ingest", json={"events": [
        {"event_type": "agent_detected", "domain": "localhost", "payload": {"product": "claude-code"}}]},
        headers=endpoint)).status_code == 202


@pytest.mark.asyncio
async def test_ingestion_is_rate_limited_per_key(client, db_session, org_and_users, mock_celery_send_task,
                                                 monkeypatch):
    monkeypatch.setattr(settings, "INGEST_EXTENSION_BATCHES_PER_MINUTE", 2)
    ext = await _source(db_session, org_and_users["org"].id, "browser_extension")
    other = await _source(db_session, org_and_users["org"].id, "browser_extension")
    for _ in range(2):
        assert (await client.post("/api/v1/shadow-ai/ingest", json={"events": [_visit()]}, headers=ext)).status_code == 202
    r = await client.post("/api/v1/shadow-ai/ingest", json={"events": [_visit()]}, headers=ext)
    assert r.status_code == 429 and r.headers.get("Retry-After")
    # per key, not per address
    assert (await client.post("/api/v1/shadow-ai/ingest", json={"events": [_visit()]}, headers=other)).status_code == 202


@pytest.mark.asyncio
async def test_a_batch_cannot_flood_or_write_into_the_channels(db_session, org_and_users, monkeypatch):
    sent = []

    async def capture(db, org_id, event_type, subject, message, metadata=None):
        sent.append((event_type, subject, message))

    monkeypatch.setattr(telemetry_service.notification_service, "notify", capture)
    org_id = org_and_users["org"].id
    src = IngestionSource(org_id=org_id, name="ext", source_type="browser_extension", api_key_hash="x" * 64)
    db_session.add(src)
    await db_session.flush()
    svc = TelemetryService(db_session)

    forged = "Evil\r\nSubject: reset your password at evil.example\x1b[0m"
    await svc.ingest_events(org_id, src.id, [TelemetryEventIn(**_visit("one.example-ai.com",
                                                                        payload={"tool_name": forged}))])
    [(kind, subject, _)] = sent
    assert kind == "shadow_ai_reported" and "\n" not in subject and "\r" not in subject and "\x1b" not in subject
    assert len(subject) < 120

    sent.clear()
    await svc.ingest_events(org_id, src.id, [TelemetryEventIn(**_visit(f"d{i}.example-ai.com")) for i in range(40)])
    assert len(sent) == 1 and sent[0][1] == "40 new Shadow AI sightings"


# ---------------------------------------------------------------- sessions

@pytest.mark.asyncio
async def test_logout_ends_the_session(client, admin_token):
    assert (await client.get("/api/v1/users/me", headers=auth_headers(admin_token))).status_code == 200
    assert (await client.post("/api/v1/auth/logout", headers=auth_headers(admin_token))).status_code == 204
    assert (await client.get("/api/v1/users/me", headers=auth_headers(admin_token))).status_code == 401
    assert (await client.post("/api/v1/auth/logout")).status_code == 204          # nothing to end: fine


@pytest.mark.asyncio
async def test_a_password_change_ends_the_other_sessions(client, db_session, org_and_users):
    org, admin = org_and_users["org"], org_and_users["admin"]
    phone = await _login(client, org.slug, admin.email, "TestPass123!")
    laptop = await _login(client, org.slug, admin.email, "TestPass123!")
    r = await client.post("/api/v1/users/me/password", json={"current_password": "TestPass123!",
                                                             "new_password": "NewPass456!x"},
                          headers=auth_headers(laptop))
    assert r.status_code == 200, r.text
    fresh = r.json()["access_token"]
    assert (await client.get("/api/v1/users/me", headers=auth_headers(phone))).status_code == 401
    assert (await client.get("/api/v1/users/me", headers=auth_headers(laptop))).status_code == 401
    assert (await client.get("/api/v1/users/me", headers=auth_headers(fresh))).status_code == 200


@pytest.mark.asyncio
async def test_password_change_attempts_are_limited(client, admin_token):
    for _ in range(5):
        r = await client.post("/api/v1/users/me/password", json={"current_password": "wrong-guess",
                                                                 "new_password": "NewPass456!x"},
                              headers=auth_headers(admin_token))
        assert r.status_code == 400
    r = await client.post("/api/v1/users/me/password", json={"current_password": "wrong-guess",
                                                             "new_password": "NewPass456!x"},
                          headers=auth_headers(admin_token))
    assert r.status_code == 429


# ---------------------------------------------------------------- headers, outbound

@pytest.mark.asyncio
async def test_security_headers(client, admin_token):
    r = await client.get("/api/v1/users/me", headers=auth_headers(admin_token))
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert (await client.get("/health")).headers["x-frame-options"] == "DENY"


@pytest.mark.asyncio
async def test_attestation_keys_are_fetched_through_the_outbound_guard():
    from app.services import attestation
    with pytest.raises(httpx.HTTPError):
        await attestation._fetch_json("https://169.254.169.254/latest/meta-data/jwks")
    with pytest.raises(httpx.HTTPError):
        await attestation._fetch_json("https://127.0.0.1:6443/openid/v1/jwks")
