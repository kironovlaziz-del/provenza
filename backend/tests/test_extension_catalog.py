"""The browser extension's side of Shadow AI (extension 2.0): the catalog it
watches and blocks by (GET /shadow-ai/extension/catalog), and old extensions'
secret-paste warnings, which Provenza no longer receives."""

import pytest

from app.core.security import generate_api_key, hash_api_key
from app.models.ingestion_source import IngestionSource
from tests.conftest import auth_headers


async def _source(db, org_id, source_type="browser_extension", enabled=True):
    key = generate_api_key()
    db.add(IngestionSource(org_id=org_id, name=f"{source_type}-src", source_type=source_type,
                           api_key_hash=hash_api_key(key), enabled=enabled))
    await db.flush()
    return {"X-Ingestion-Key": key}


@pytest.mark.asyncio
async def test_the_extension_gets_its_organizations_catalog(client, db_session, org_and_users, admin_token):
    ext = await _source(db_session, org_and_users["org"].id)
    r = await client.get("/api/v1/shadow-ai/extension/catalog", headers=ext)
    assert r.status_code == 200, r.text
    first = r.json()
    by_domain = {d["domain"]: d for d in first["domains"]}
    # the built-in AI services, as unknown, ChatGPT under its current address
    assert by_domain["chatgpt.com"] == {"domain": "chatgpt.com", "name": "ChatGPT",
                                        "category": "general_assistant", "status": "unknown"}
    assert {"cursor.com", "grok.com"} <= set(by_domain)
    # an API host is not something people visit, and a path is not a host
    assert not {"openrouter.ai", "github.com/copilot"} & set(by_domain)
    assert all(d.count("/") == 0 for d in by_domain)

    # the organization's decision wins over the built-in hint, and changes the version
    for domain, status in (("chatgpt.com", "allowed"), ("chat.deepseek.com", "blocked"), ("intra-ai.example", "blocked")):
        r = await client.post("/api/v1/domain-catalog/", json={"domain": domain, "tool_name": domain.split(".")[0],
                                                                 "policy_status": status}, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
    second = (await client.get("/api/v1/shadow-ai/extension/catalog", headers=ext)).json()
    by_domain = {d["domain"]: d for d in second["domains"]}
    assert by_domain["chatgpt.com"]["status"] == "allowed"
    assert by_domain["chat.deepseek.com"]["status"] == "blocked"
    assert by_domain["intra-ai.example"]["status"] == "blocked"
    assert [d["domain"] for d in second["domains"]].count("chatgpt.com") == 1
    assert second["version"] != first["version"]


@pytest.mark.asyncio
async def test_the_catalog_needs_a_working_key(client, db_session, org_and_users):
    assert (await client.get("/api/v1/shadow-ai/extension/catalog",
                             headers={"X-Ingestion-Key": "nope"})).status_code == 401
    off = await _source(db_session, org_and_users["org"].id, enabled=False)
    assert (await client.get("/api/v1/shadow-ai/extension/catalog", headers=off)).status_code == 401


@pytest.mark.asyncio
async def test_an_old_extensions_warnings_no_longer_sink_its_visits(client, db_session, org_and_users,
                                                                   mock_celery_send_task):
    ext = await _source(db_session, org_and_users["org"].id)
    visit = {"event_type": "domain_visit", "domain": "chatgpt.com"}
    warning = {"event_type": "pii_paste_attempt", "domain": "chatgpt.com", "payload": {"findings": []}}
    r = await client.post("/api/v1/shadow-ai/ingest", json={"events": [visit, warning]}, headers=ext)
    assert r.status_code == 202 and r.json()["received"] == 1
    # a batch of warnings only: accepted, nothing to process
    r = await client.post("/api/v1/shadow-ai/ingest", json={"events": [warning]}, headers=ext)
    assert r.status_code == 202 and r.json()["received"] == 0
    # anything else from an extension's (public) key is still refused
    r = await client.post("/api/v1/shadow-ai/ingest", json={"events": [
        visit, {"event_type": "agent_detected", "domain": "localhost"}]}, headers=ext)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_the_download_is_extension_2_with_this_servers_address_and_a_fresh_key(client, admin_token):
    import io
    import json
    import re
    import zipfile

    r = await client.get("/api/v1/shadow-ai/extension/download", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert "provenza-browser-extension.zip" in r.headers["content-disposition"]
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"manifest.json", "managed_schema.json", "blocked/blocked.html", "blocked/blocked.js"} <= names
    manifest = json.loads(z.read("manifest.json"))
    assert manifest["version"].startswith("2.") and manifest["storage"]["managed_schema"] == "managed_schema.json"
    worker = z.read("background/service-worker.js").decode()
    api_url = re.search(r'apiUrl: "([^"]*)"', worker).group(1)
    key = re.search(r'ingestionKey: "([^"]*)"', worker).group(1)
    assert api_url.endswith("/api/v1/shadow-ai/ingest") and key
    # the baked key works for the catalog
    assert (await client.get("/api/v1/shadow-ai/extension/catalog", headers={"X-Ingestion-Key": key})).status_code == 200
