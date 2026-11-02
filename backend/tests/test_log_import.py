"""DNS and proxy logs as a Shadow AI collector (app/services/log_import.py):
the formats it reads, that only AI services are kept, and the upload / log
forwarder endpoints that turn them into sightings and people."""

import gzip

import pytest
from sqlalchemy import func, select

from app.models.ai_telemetry_event import AITelemetryEvent
from app.models.endpoint_device import EndpointDevice
from app.schemas.telemetry import TelemetryEventIn
from app.services.domain_catalog_service import AIDomainSet
from app.services.log_import import LogParser, decode_lines, host_of, import_lines, maybe_gunzip, to_events
from app.services.telemetry_service import TelemetryService
from tests.conftest import auth_headers
from tests.test_extension_catalog import _source

AI = AIDomainSet(["chatgpt.com", "claude.ai", "openai.com", "deepseek.com", "poe.com", "perplexity.ai",
                  "gemini.google.com", "copilot.microsoft.com", "huggingface.co"])

FORMATS = [
    ("squid", "1730512345.123    150 10.0.0.5 TCP_TUNNEL/200 3456 CONNECT chatgpt.com:443 alice HIER_DIRECT/1.2.3.4 -",
     ("chatgpt.com", "alice", "10.0.0.5", False)),
    ("squid", "1730512346.000     12 10.0.0.6 TCP_DENIED/403 0 GET http://claude.ai/new?q=secret bob HIER_NONE/- text/html",
     ("claude.ai", "bob", "10.0.0.6", True)),
    ("bind", "02-Nov-2026 10:00:00.123 queries: info: client @0x7f12 10.0.0.7#53211 (gemini.google.com): "
             "query: gemini.google.com IN A +E(0)K (10.0.0.1)", ("gemini.google.com", None, "10.0.0.7", False)),
    ("dnsmasq", "Nov  2 10:00:00 dnsmasq[123]: query[A] chat.deepseek.com from 10.0.0.8",
     ("chat.deepseek.com", None, "10.0.0.8", False)),
    ("unbound", "[1730512345] unbound[1:0] info: 10.0.0.9 perplexity.ai. A IN", ("perplexity.ai", None, "10.0.0.9", False)),
    ("windows_dns", "11/2/2026 10:00:00 AM 0E5C PACKET  000000D2 UDP Rcv 10.0.0.10   1234   Q [0001   D   NOERROR] A      "
                    "(7)chatgpt(3)com(0)", ("chatgpt.com", None, "10.0.0.10", False)),
    ("json", '{"ts": 1730512345.5, "query": "claude.ai", "id.orig_h": "10.0.0.11"}', ("claude.ai", None, "10.0.0.11", False)),
    ("json", '{"timestamp":"2026-11-02T10:00:00Z","user":{"name":"carol@corp.example"},"url":"https://chatgpt.com/c/1",'
             '"action":"block"}', ("chatgpt.com", "carol@corp.example", None, True)),
    ("key_value", 'date=2026-11-02 time=10:00:00 srcip=10.0.0.12 user="dave" hostname="copilot.microsoft.com" action="blocked"',
     ("copilot.microsoft.com", "dave", "10.0.0.12", True)),
    ("key_value", "CEF:0|Vendor|Proxy|1.0|100|access|3|src=10.0.0.13 suser=eve dhost=poe.com request=https://poe.com/chat",
     ("poe.com", "eve", "10.0.0.13", False)),
]


@pytest.mark.parametrize("fmt,line,want", FORMATS)
def test_reads_each_format(fmt, line, want):
    p = LogParser()
    hits = p.feed(line)
    assert [(h.host, h.user, h.client, h.blocked) for h in hits] == [want]
    assert p.formats == {fmt: 1}


def test_csv_export_with_a_header():
    # Cisco Umbrella's DNS export; the identity names a person, the address wins
    lines = [
        '"Timestamp","Most Granular Identity","Identities","Internal IP","External IP","Action","QueryType",'
        '"ResponseCode","Domain","Categories"',
        '"2026-11-02 10:00:00","frank (frank@corp.example)","frank (frank@corp.example),HQ","10.0.0.14","1.2.3.4",'
        '"Blocked","1 (A)","NOERROR","chatgpt.com.","Generative AI"',
        '"2026-11-02 10:01:00","HQ","HQ","10.0.0.15","1.2.3.4","Allowed","1 (A)","NOERROR","example.org.","Business"',
    ]
    p = LogParser()
    hits = [h for line in lines for h in p.feed(line)]
    assert [(h.host, h.user, h.client, h.blocked, h.kind) for h in hits] == [
        ("chatgpt.com", "frank@corp.example", "10.0.0.14", True, "dns_log"),
        ("example.org", "HQ", "10.0.0.15", False, "dns_log"),
    ]


def test_zeek_dns_log():
    lines = ["#separator \\x09",
             "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery",
             "1730512345.1\tCabc\t10.0.0.16\t5353\t10.0.0.1\t53\tudp\t1\thuggingface.co"]
    p = LogParser()
    hits = [h for line in lines for h in p.feed(line)]
    assert [(h.host, h.client) for h in hits] == [("huggingface.co", "10.0.0.16")] and p.formats == {"zeek": 1}


def test_any_other_line_still_gives_its_host_names():
    hits = LogParser().feed("Nov 2 something odd: 10.0.0.20 asked for www.chatgpt.com and example.org")
    assert {(h.host, h.client) for h in hits} == {("www.chatgpt.com", "10.0.0.20"), ("example.org", "10.0.0.20")}


def test_host_of():
    assert host_of("https://user@Claude.AI:443/x?y") == "claude.ai"
    assert host_of("chatgpt.com.") == "chatgpt.com"
    assert host_of("(7)chatgpt(3)com(0)") == "chatgpt.com"
    assert host_of("10.0.0.1") is None and host_of("-") is None and host_of("[::1]:443") is None


def test_only_ai_services_are_kept_and_folded_into_visits():
    lines = [line for _, line, _ in FORMATS] + [
        "1730512400.000  10 10.0.0.5 TCP_TUNNEL/200 1 CONNECT chatgpt.com:443 alice HIER_DIRECT/1.2.3.4 -",
        "1730512500.000  10 10.0.0.5 TCP_TUNNEL/200 1 CONNECT api.openai.com:443 alice HIER_DIRECT/1.2.3.4 -",
        "1730512500.000  10 10.0.0.5 TCP_TUNNEL/200 1 CONNECT www.example.com:443 alice HIER_DIRECT/1.2.3.4 -",
        "Nov  2 10:00:00 dnsmasq[123]: query[A] notchatgpt.com from 10.0.0.8",
    ]
    r = import_lines(lines, AI)
    assert r.lines == len(lines) and r.recognized == len(lines) and r.ai_lines == len(lines) - 2
    alice = r.visits[("chatgpt.com", "alice", "10.0.0.5", "proxy_log")]
    assert alice.hits == 2 and alice.first.timestamp() == 1730512345.123 and alice.last.timestamp() == 1730512400
    assert ("api.openai.com", "alice", "10.0.0.5", "proxy_log") in r.visits
    s = r.summary()
    assert s["top"][0] == {"domain": "chatgpt.com", "hits": 4}
    assert s["people"] == 5 and not s["truncated"]  # alice, bob, carol, dave, eve

    events = {(e["domain"], e["user_id"]): e for e in to_events(r, "upload")}
    e = events[("chatgpt.com", "alice")]
    assert e["agent_id"] == "10.0.0.5" and e["payload"]["hits"] == 2 and e["payload"]["source"] == "proxy_log"
    assert events[("claude.ai", "bob")]["action_taken"] == "blocked"
    # nothing of the line but host, person, computer, time and blocked/allowed
    assert "secret" not in str(list(events.values()))


def test_gzip_and_utf16():
    raw = "Nov  2 10:00:00 dnsmasq[1]: query[A] claude.ai from 10.0.0.8\n".encode()
    gz = gzip.compress(raw * 3)
    lines = list(decode_lines(maybe_gunzip(iter([gz[:10], gz[10:]]), 1 << 20)))
    assert len([x for x in lines if x]) == 3
    u16 = ("﻿" + raw.decode()).encode("utf-16-le")
    assert list(decode_lines(iter([u16[:7], u16[7:]])))[0].endswith("from 10.0.0.8")
    with pytest.raises(ValueError):
        list(maybe_gunzip(iter([gzip.compress(b"x" * 5000)]), 1000))


# ---------------------------------------------------------------- endpoints

SQUID = (
    "1730512345.123  150 10.0.0.5 TCP_TUNNEL/200 3456 CONNECT chat.deepseek.com:443 anna HIER_DIRECT/1.2.3.4 -\n"
    "1730512346.123  150 10.0.0.5 TCP_TUNNEL/200 3456 CONNECT chat.deepseek.com:443 anna HIER_DIRECT/1.2.3.4 -\n"
    "1730512347.123  150 10.0.0.6 TCP_DENIED/403 0 CONNECT chat.deepseek.com:443 bob HIER_NONE/- -\n"
    "1730512348.123  150 10.0.0.7 TCP_TUNNEL/200 3456 CONNECT www.example.com:443 carl HIER_DIRECT/1.2.3.4 -\n"
)


def _capture(monkeypatch):
    sent = []
    from app.workers import telemetry_tasks

    def delay(org, src, events, record_devices=True):
        assert record_devices is False
        sent.append((org, src, events))

    monkeypatch.setattr(telemetry_tasks.process_telemetry_batch, "delay", delay)
    return sent


@pytest.mark.asyncio
async def test_an_admin_uploads_a_proxy_log(client, db_session, org_and_users, admin_token, monkeypatch):
    sent = _capture(monkeypatch)
    h = {**auth_headers(admin_token), "Content-Type": "application/octet-stream"}
    r = await client.post("/api/v1/shadow-ai/logs/import?name=access.log.gz", headers=h,
                          content=gzip.compress(SQUID.encode()))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lines"] == 4 and body["ai_lines"] == 3 and body["events"] == 2 and body["formats"] == {"squid": 4}
    assert body["top"] == [{"domain": "chat.deepseek.com", "hits": 3}]

    # the visits through the pipeline, as the worker runs them
    org = org_and_users["org"].id
    (_, src, events), = sent
    await TelemetryService(db_session).ingest_events(
        org, src, [TelemetryEventIn.model_validate(e) for e in events], record_devices=False)

    rows = (await client.get("/api/v1/shadow-ai/", headers=auth_headers(admin_token))).json()["items"]
    s = next(x for x in rows if x["domain"] == "chat.deepseek.com")
    assert s["detected_via"] == "proxy_log" and s["people"] == 2
    people = (await client.get(f"/api/v1/shadow-ai/{s['id']}/people", headers=auth_headers(admin_token))).json()
    by = {p["user"]: p for p in people["people"]}
    assert by["anna"]["visits"] == 2 and by["anna"]["blocked"] == 0 and by["bob"]["blocked"] == 1
    # addresses in a log are not devices with a collector
    assert await db_session.scalar(select(func.count()).select_from(EndpointDevice)
                                   .where(EndpointDevice.org_id == org)) == 0

    # one upload source, reused, with no usable key
    r = await client.post("/api/v1/shadow-ai/logs/import", headers=h, content=SQUID.encode())
    assert r.status_code == 200
    srcs = (await client.get("/api/v1/ingestion-sources/", headers=auth_headers(admin_token))).json()
    srcs = srcs["items"] if isinstance(srcs, dict) else srcs
    assert len([x for x in srcs if x["source_type"] == "log_upload"]) == 1


@pytest.mark.asyncio
async def test_only_admins_upload(client, approver_token, monkeypatch):
    _capture(monkeypatch)
    h = auth_headers(approver_token)
    r = await client.post("/api/v1/shadow-ai/logs/import", headers=h, content=SQUID.encode())
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_a_log_forwarder_posts_with_a_gateway_key(client, db_session, org_and_users, monkeypatch):
    sent = _capture(monkeypatch)
    gw = await _source(db_session, org_and_users["org"].id, "gateway")
    r = await client.post("/api/v1/shadow-ai/ingest/logs", headers=gw, content=SQUID.encode())
    assert r.status_code == 200, r.text
    assert r.json()["events"] == 2 and len(sent) == 1

    for kind in ("endpoint", "browser_extension"):
        other = await _source(db_session, org_and_users["org"].id, kind)
        r = await client.post("/api/v1/shadow-ai/ingest/logs", headers=other, content=SQUID.encode())
        assert r.status_code == 403, kind

    from app.core.config import settings
    monkeypatch.setattr(settings, "LOG_INGEST_MAX_MB", 0)
    r = await client.post("/api/v1/shadow-ai/ingest/logs", headers=gw, content=SQUID.encode())
    assert r.status_code == 413


@pytest.mark.asyncio
async def test_a_broken_gzip_is_refused(client, admin_token, monkeypatch):
    _capture(monkeypatch)
    h = auth_headers(admin_token)
    r = await client.post("/api/v1/shadow-ai/logs/import", headers=h, content=gzip.compress(SQUID.encode())[:40])
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_a_browser_cannot_claim_many_visits(client, db_session, org_and_users, monkeypatch):
    sent = []
    from app.api import shadow_ai

    monkeypatch.setattr(shadow_ai.process_telemetry_batch, "delay",
                        lambda org, src, events: sent.extend(events) or type("R", (), {"id": "t"})())
    ext = await _source(db_session, org_and_users["org"].id)
    r = await client.post("/api/v1/shadow-ai/ingest", headers=ext, json={"events": [
        {"event_type": "domain_visit", "domain": "grok.com",
         "payload": {"hits": 1000000, "blocked_hits": 5, "source": "dns_log", "tool_name": "Grok"}}]})
    assert r.status_code == 202
    assert sent[0]["payload"] == {"tool_name": "Grok"}


@pytest.mark.asyncio
async def test_a_count_must_be_a_plain_number(db_session, org_and_users):
    gw_key = await _source(db_session, org_and_users["org"].id, "gateway")
    assert gw_key
    from app.models.ingestion_source import IngestionSource

    src = (await db_session.execute(select(IngestionSource).where(
        IngestionSource.org_id == org_and_users["org"].id, IngestionSource.source_type == "gateway"))).scalars().first()
    await TelemetryService(db_session).ingest_events(org_and_users["org"].id, src.id, [
        TelemetryEventIn(event_type="domain_visit", domain="claude.ai", payload={"hits": "lots", "blocked_hits": -1}),
    ], record_devices=False)
    ev = (await db_session.execute(select(AITelemetryEvent).where(AITelemetryEvent.domain == "claude.ai"))).scalars().one()
    assert "hits" not in ev.metadata_json and "blocked_hits" not in ev.metadata_json
