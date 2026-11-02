"""Who used an AI service (browser extension 2.1, userEmail from the
organization's policy): people per domain sighting, names for reviewers only,
and nothing but an address kept from a browser's public key."""

import pytest

from app.models.user import UserRole
from app.schemas.telemetry import TelemetryEventIn
from app.services.telemetry_service import TelemetryService
from tests.conftest import auth_headers
from tests.test_extension_catalog import _source
from tests.test_oversight_roles import _token_for


def _visit(domain, user=None, browser="browser-ext-1", action="monitored"):
    return TelemetryEventIn(event_type="domain_visit", domain=domain, user_id=user, agent_id=browser,
                            action_taken=action, payload={"tool_name": "DeepSeek Chat"})


async def _ingest(db, org_and_users, events):
    from app.models.ingestion_source import IngestionSource
    from sqlalchemy import select

    src = (await db.execute(select(IngestionSource).where(IngestionSource.org_id == org_and_users["org"].id))).scalars().first()
    await TelemetryService(db).ingest_events(org_and_users["org"].id, src.id, events)
    await db.flush()


@pytest.mark.asyncio
async def test_a_sighting_shows_who_visited(client, db_session, org_and_users, admin_token):
    await _source(db_session, org_and_users["org"].id)
    await _ingest(db_session, org_and_users, [
        _visit("chat.deepseek.com", "anna@corp.example"),
        _visit("chat.deepseek.com", "anna@corp.example"),
        _visit("chat.deepseek.com", "bob@corp.example", browser="browser-ext-2", action="blocked"),
        _visit("chat.deepseek.com", None, browser="browser-ext-3"),
        _visit("chat.deepseek.com", None, browser="browser-ext-3"),
        _visit("chat.deepseek.com", None, browser="browser-ext-4"),
        _visit("grok.com", "anna@corp.example"),
    ])
    h = auth_headers(admin_token)
    rows = (await client.get("/api/v1/shadow-ai/", headers=h)).json()["items"]
    deepseek = next(r for r in rows if r["domain"] == "chat.deepseek.com")
    assert deepseek["people"] == 2 and deepseek["unidentified_browsers"] == 2
    assert deepseek["user_hint"] == "anna@corp.example"

    r = await client.get(f"/api/v1/shadow-ai/{deepseek['id']}/people", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    people = {p["user"]: p for p in body["people"]}
    assert people["anna@corp.example"]["visits"] == 2 and people["anna@corp.example"]["blocked"] == 0
    assert people["bob@corp.example"]["blocked"] == 1
    assert body["unidentified_browsers"] == 2 and body["unidentified_visits"] == 3


@pytest.mark.asyncio
async def test_names_are_for_reviewers_and_oversight_only(client, db_session, org_and_users):
    await _source(db_session, org_and_users["org"].id)
    await _ingest(db_session, org_and_users, [_visit("chat.deepseek.com", "anna@corp.example")])

    user = auth_headers(await _token_for(client, db_session, org_and_users, UserRole.user))
    row = (await client.get("/api/v1/shadow-ai/", headers=user)).json()["items"][0]
    assert row["user_hint"] is None and row["people"] == 1  # how many, not who
    assert (await client.get(f"/api/v1/shadow-ai/{row['id']}/people", headers=user)).status_code == 403

    auditor = auth_headers(await _token_for(client, db_session, org_and_users, UserRole.auditor))
    assert (await client.get("/api/v1/shadow-ai/", headers=auditor)).json()["items"][0]["user_hint"] == "anna@corp.example"
    assert (await client.get(f"/api/v1/shadow-ai/{row['id']}/people", headers=auditor)).status_code == 200


@pytest.mark.asyncio
async def test_a_browser_reports_an_address_or_nobody(client, db_session, org_and_users, monkeypatch):
    sent = []
    from app.api import shadow_ai

    monkeypatch.setattr(shadow_ai.process_telemetry_batch, "delay",
                        lambda org, src, events: sent.extend(events) or type("R", (), {"id": "t"})())
    ext = await _source(db_session, org_and_users["org"].id)
    r = await client.post("/api/v1/shadow-ai/ingest", headers=ext, json={"events": [
        {"event_type": "domain_visit", "domain": "grok.com", "user_id": "Anna@Corp.Example"},
        {"event_type": "domain_visit", "domain": "grok.com", "user_id": "<b>not an address</b>"},
        {"event_type": "domain_visit", "domain": "grok.com"},
    ]})
    assert r.status_code == 202, r.text
    assert [e["user_id"] for e in sent] == ["anna@corp.example", None, None]
