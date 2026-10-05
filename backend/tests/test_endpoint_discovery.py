# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Discovery without manual entry: every telemetry batch refreshes the device
that sent it, and "agent_detected" events become AI agents found on that
device - reviewed in Agents Found (link to a governed agent, or ignore).
A process command line is never stored.
"""

import secrets

import pytest
from sqlalchemy import select

from app.core.security import generate_api_key, hash_api_key
from app.models.ai_telemetry_event import AITelemetryEvent
from app.models.endpoint_device import DiscoveredAgent, EndpointDevice
from app.models.ingestion_source import IngestionSource
from app.models.organization import Organization
from app.schemas.telemetry import TelemetryEventIn
from app.services import notification_service
from app.services.telemetry_service import TelemetryService
from tests.conftest import auth_headers

D = "/api/v1/devices"
F = "/api/v1/agents-found"


@pytest.fixture
def notes(monkeypatch):
    sent = []

    async def fake_notify(db, org_id, event_type, subject, message, metadata=None):
        sent.append((event_type, subject))

    monkeypatch.setattr(notification_service, "notify", fake_notify)
    return sent


async def _source(db, org_id, name="laptops"):
    src = IngestionSource(org_id=org_id, name=name, source_type="endpoint",
                          api_key_hash=hash_api_key(generate_api_key()), enabled=True)
    db.add(src)
    await db.flush()
    return src


def _agent_event(host="dev-1", product="claude_code", user="alice", **payload):
    return TelemetryEventIn(event_type="agent_detected", agent_id=host, domain="localhost", user_id=user,
                            risk_score=0.7, payload={"product": product, "process_name": "claude",
                                                     "matched_by": "executable", "os": "linux",
                                                     "agent_version": "1.2.0", **payload})


async def _ingest(db, src, events):
    return await TelemetryService(db).ingest_events(src.org_id, src.id, events)


class TestIngestion:
    async def test_agent_detected_creates_device_and_finding(self, db_session, org_and_users, notes):
        src = await _source(db_session, org_and_users["org"].id)
        r = await _ingest(db_session, src, [_agent_event()])
        assert r.agents_found == 1 and r.devices_seen == 1

        dev = (await db_session.execute(select(EndpointDevice).where(EndpointDevice.ingestion_source_id == src.id))).scalar_one()
        assert (dev.host_id, dev.last_user, dev.os, dev.agent_version, dev.event_count) == \
            ("dev-1", "alice", "linux", "1.2.0", 1)
        found = (await db_session.execute(select(DiscoveredAgent).where(DiscoveredAgent.device_id == dev.id))).scalar_one()
        assert (found.product, found.status, found.seen_count) == ("claude_code", "new", 1)
        assert found.evidence == {"process_name": "claude", "matched_by": "executable"}
        assert [n[0] for n in notes] == ["agent_discovered"]

    async def test_seen_again_updates_instead_of_duplicating(self, db_session, org_and_users, notes):
        src = await _source(db_session, org_and_users["org"].id)
        await _ingest(db_session, src, [_agent_event()])
        r = await _ingest(db_session, src, [_agent_event(), _agent_event(product="cursor")])
        assert r.agents_found == 1  # only cursor is new
        rows = (await db_session.execute(select(DiscoveredAgent).order_by(DiscoveredAgent.product))).scalars().all()
        rows = [x for x in rows if x.org_id == src.org_id]
        await db_session.refresh(rows[0])
        assert [(x.product, x.seen_count) for x in rows] == [("claude_code", 2), ("cursor", 1)]
        dev = (await db_session.execute(select(EndpointDevice).where(EndpointDevice.ingestion_source_id == src.id))).scalar_one()
        await db_session.refresh(dev)
        assert dev.event_count == 3
        assert [n[0] for n in notes].count("agent_discovered") == 2

    async def test_same_host_name_under_another_source_is_another_device(self, db_session, org_and_users, notes):
        org_id = org_and_users["org"].id
        a, b = await _source(db_session, org_id, "a"), await _source(db_session, org_id, "b")
        await _ingest(db_session, a, [_agent_event()])
        await _ingest(db_session, b, [_agent_event()])
        n = (await db_session.execute(select(EndpointDevice).where(EndpointDevice.org_id == org_id))).scalars().all()
        assert len(n) == 2

    async def test_unknown_product_is_kept_but_does_not_notify(self, db_session, org_and_users, notes):
        src = await _source(db_session, org_and_users["org"].id)
        r = await _ingest(db_session, src, [_agent_event(product="brand_new_agent")])
        assert r.agents_found == 1 and notes == []

    async def test_a_fleet_rollout_sends_one_summary(self, db_session, org_and_users, notes):
        src = await _source(db_session, org_and_users["org"].id)
        events = [_agent_event(host=f"pc-{i}") for i in range(8)]
        r = await _ingest(db_session, src, events)
        assert r.agents_found == 8 and r.devices_seen == 8
        assert len(notes) == 1 and notes[0][1] == "8 AI agents found on 8 devices"

    async def test_device_name_cannot_inject_mail_headers(self, db_session, org_and_users, notes):
        src = await _source(db_session, org_and_users["org"].id)
        await _ingest(db_session, src, [_agent_event(host="pc\r\nBcc: x@evil.example")])
        assert "\n" not in notes[0][1] and "\r" not in notes[0][1]

    async def test_unrecognized_agent_found_by_behavior(self, db_session, org_and_users, notes):
        src = await _source(db_session, org_and_users["org"].id)
        ev = _agent_event(product="custom.sales_bot", matched_by="behavior", confidence="high",
                          api_hosts=["api.openai.com", "<script>"], env_keys=["OPENAI_API_KEY", "sk-live-123"],
                          sdks=["openai-or-anthropic-python"], process_name="python3")
        r = await _ingest(db_session, src, [ev])
        assert r.agents_found == 1
        found = (await db_session.execute(select(DiscoveredAgent).where(DiscoveredAgent.org_id == src.org_id))).scalar_one()
        assert found.evidence == {
            "process_name": "python3", "matched_by": "behavior", "confidence": "high",
            "api_hosts": ["api.openai.com"],          # junk dropped
            "env_keys": ["OPENAI_API_KEY"],           # a value-looking entry dropped
            "sdks": ["openai-or-anthropic-python"],
        }
        assert notes == [("agent_discovered", "Unrecognized AI agent found: sales_bot on dev-1")]

    @pytest.mark.parametrize("product", ["", "../etc", "A" * 80, "rm -rf"])
    async def test_malformed_product_is_not_recorded(self, db_session, org_and_users, notes, product):
        src = await _source(db_session, org_and_users["org"].id)
        r = await _ingest(db_session, src, [_agent_event(product=product)])
        assert r.agents_found == 0
        n = (await db_session.execute(select(DiscoveredAgent).where(DiscoveredAgent.org_id == src.org_id))).scalars().all()
        assert n == []

    async def test_command_line_is_never_stored(self, db_session, org_and_users, notes):
        src = await _source(db_session, org_and_users["org"].id)
        old_agent = TelemetryEventIn(event_type="process_detected", agent_id="dev-2", domain="localhost",
                                     payload={"process_name": "ollama", "ai_tool": "ollama",
                                              "cmdline": "ollama serve --key sk-secret"})
        await _ingest(db_session, src, [old_agent])
        raw = (await db_session.execute(select(AITelemetryEvent).where(
            AITelemetryEvent.ingestion_source_id == src.id))).scalar_one()
        assert "cmdline" not in raw.metadata_json and raw.metadata_json["process_name"] == "ollama"


async def _seed(db, org_id, host="dev-1", products=("claude_code",)):
    src = await _source(db, org_id, "src-" + secrets.token_hex(3))
    await _ingest(db, src, [_agent_event(host=host, product=p) for p in products])
    return src


class TestApi:
    async def test_devices_and_findings_are_listed(self, client, db_session, org_and_users, admin_token, notes):
        await _seed(db_session, org_and_users["org"].id, products=("claude_code", "crewai"))
        r = await client.get(D + "/", headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        dev = r.json()["items"][0]
        assert (dev["host_id"], dev["agents_found"], dev["agents_new"]) == ("dev-1", 2, 2)
        assert dev["source"]["source_type"] == "endpoint"

        detail = (await client.get(f"{D}/{dev['id']}", headers=auth_headers(admin_token))).json()
        assert sorted(a["product"] for a in detail["agents"]) == ["claude_code", "crewai"]

        found = (await client.get(F + "/", headers=auth_headers(admin_token))).json()["items"]
        cc = next(f for f in found if f["product"] == "claude_code")
        assert (cc["name"], cc["vendor"], cc["category"], cc["device_host"]) == \
            ("Claude Code", "Anthropic", "coding_agent", "dev-1")
        crew = next(f for f in found if f["product"] == "crewai")
        assert crew["category"] == "agent_framework"

    async def test_custom_agent_is_described_by_its_name(self, client, db_session, org_and_users, admin_token, notes):
        await _seed(db_session, org_and_users["org"].id, products=("custom.ticket-triage",))
        f = (await client.get(F + "/", headers=auth_headers(admin_token))).json()["items"][0]
        assert (f["name"], f["category"], f["vendor"]) == ("ticket-triage", "custom_agent", "")

    async def test_plain_users_cannot_see_devices(self, client, db_session, org_and_users, notes):
        from tests.conftest import _login
        await _seed(db_session, org_and_users["org"].id)
        from app.core.security import get_password_hash
        from app.models.user import User
        db_session.add(User(org_id=org_and_users["org"].id, email="plain@test.example.com", name="P",
                            hashed_password=get_password_hash("TestPass123!"), role="user", status="active"))
        await db_session.flush()
        token = await _login(client, org_and_users["org"].slug, "plain@test.example.com", "TestPass123!")
        assert (await client.get(D + "/", headers=auth_headers(token))).status_code == 403
        assert (await client.get(F + "/", headers=auth_headers(token))).status_code == 403

    async def test_review_link_ignore_restore(self, client, db_session, org_and_users, admin_token, notes):
        await _seed(db_session, org_and_users["org"].id)
        fid = (await client.get(F + "/", headers=auth_headers(admin_token))).json()["items"][0]["id"]

        r = await client.post(f"{F}/{fid}/ignore", headers=auth_headers(admin_token))
        assert r.status_code == 200 and r.json()["after"] == "ignored"
        assert (await client.get(F + "/", params={"status": "ignored"},
                                 headers=auth_headers(admin_token))).json()["total"] == 1

        reg = await client.post("/api/v1/agents/register", json={
            "name": "claude-on-dev-1", "agent_type": "custom", "capabilities": ["read"], "allowed_tools": [],
            "allowed_models": [], "max_delegation_depth": 1}, headers=auth_headers(admin_token))
        assert reg.status_code == 200, reg.text
        r = await client.post(f"{F}/{fid}/link", json={"agent_id": reg.json()["id"]}, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        item = (await client.get(F + "/", params={"status": "registered"},
                                 headers=auth_headers(admin_token))).json()["items"][0]
        assert item["registered_agent"] == {"id": reg.json()["id"], "name": "claude-on-dev-1"}

        # restoring a registered finding keeps the link
        await client.post(f"{F}/{fid}/ignore", headers=auth_headers(admin_token))
        r = await client.post(f"{F}/{fid}/restore", headers=auth_headers(admin_token))
        assert r.json()["after"] == "registered"

        s = (await client.get(F + "/summary", headers=auth_headers(admin_token))).json()
        assert s == {"new": 0, "registered": 1, "ignored": 0, "devices": 1}

    async def test_only_admins_review(self, client, db_session, org_and_users, approver_token, notes):
        await _seed(db_session, org_and_users["org"].id)
        items = (await client.get(F + "/", headers=auth_headers(approver_token))).json()["items"]
        r = await client.post(f"{F}/{items[0]['id']}/ignore", headers=auth_headers(approver_token))
        assert r.status_code == 403

    async def test_other_organizations_are_invisible(self, client, db_session, org_and_users, admin_token, notes):
        other = Organization(name="Other", slug="other-" + secrets.token_hex(3))
        db_session.add(other)
        await db_session.flush()
        await _seed(db_session, other.id, host="their-laptop")
        assert (await client.get(D + "/", headers=auth_headers(admin_token))).json()["total"] == 0
        dev = (await db_session.execute(select(EndpointDevice).where(EndpointDevice.org_id == other.id))).scalar_one()
        found = (await db_session.execute(select(DiscoveredAgent).where(DiscoveredAgent.org_id == other.id))).scalar_one()
        assert (await client.get(f"{D}/{dev.id}", headers=auth_headers(admin_token))).status_code == 404
        assert (await client.post(f"{F}/{found.id}/ignore", headers=auth_headers(admin_token))).status_code == 404

    async def test_link_needs_an_agent_of_this_organization(self, client, db_session, org_and_users, admin_token, notes):
        await _seed(db_session, org_and_users["org"].id)
        fid = (await client.get(F + "/", headers=auth_headers(admin_token))).json()["items"][0]["id"]
        r = await client.post(f"{F}/{fid}/link", json={"agent_id": 999999}, headers=auth_headers(admin_token))
        assert r.status_code == 404
        r = await client.post(f"{F}/{fid}/link", json={"agent_id": 1, "extra": 1}, headers=auth_headers(admin_token))
        assert r.status_code == 422
