"""
AI Inventory API: auto-discovery, classification, lifecycle rules, human
risk confirmation, data links, RBAC and organization isolation.
"""

import secrets

import pytest

from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers

BASE = "/api/v1/inventory"


async def _create(client, token, **over):
    body = {"name": "sys-" + secrets.token_hex(3), "domain": "general"}
    body.update(over)
    r = await client.post(BASE + "/", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _confirm(client, token, system_id, tier, justification=None):
    body = {"tier": tier}
    if justification:
        body["justification"] = justification
    return await client.post(f"{BASE}/{system_id}/confirm-risk", json=body, headers=auth_headers(token))


async def _stage(client, token, system_id, stage):
    return await client.post(f"{BASE}/{system_id}/stage", json={"stage": stage}, headers=auth_headers(token))


async def _list(client, token, **params):
    params.setdefault("limit", 100)
    r = await client.get(BASE + "/", params=params, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


class TestAutoDiscovery:
    @pytest.mark.asyncio
    async def test_registered_agent_and_provider_appear_unreviewed(self, client, admin_token):
        agent = await client.post(
            "/api/v1/agents/register",
            json={"name": "inv-agent", "agent_type": "custom", "capabilities": ["read"],
                  "allowed_tools": ["db.read"], "allowed_models": ["gpt-4o-mini"], "max_delegation_depth": 2},
            headers=auth_headers(admin_token),
        )
        assert agent.status_code == 200, agent.text
        prov = await client.post(
            "/api/v1/providers/",
            json={"name": "Inv OpenAI", "type": "openai", "api_key": "sk-test-inventory"},
            headers=auth_headers(admin_token),
        )
        assert prov.status_code in (200, 201), prov.text

        items = {i["source_key"]: i for i in (await _list(client, admin_token))["items"]}
        a = items[f"agent:{agent.json()['id']}"]
        p = items[f"provider:{prov.json()['id']}"]
        assert a["kind"] == "agent" and p["kind"] == "llm_provider"
        for entry in (a, p):
            assert entry["review_status"] == "unreviewed"
            assert entry["lifecycle_stage"] == "production"
            assert "in_production_without_confirmed_risk" in entry["attention"]

    @pytest.mark.asyncio
    async def test_sync_is_idempotent(self, client, admin_token):
        await client.post(
            "/api/v1/agents/register",
            json={"name": "idem-agent", "agent_type": "custom", "capabilities": ["read"],
                  "allowed_tools": [], "allowed_models": [], "max_delegation_depth": 1},
            headers=auth_headers(admin_token),
        )
        first = (await _list(client, admin_token))["total"]
        second = (await _list(client, admin_token))["total"]
        assert first == second
        again = await client.post(BASE + "/sync", headers=auth_headers(admin_token))
        assert again.status_code == 200 and again.json()["created"] == 0


class TestClassification:
    @pytest.mark.asyncio
    async def test_hr_system_is_suggested_high(self, client, admin_token):
        s = await _create(client, admin_token, domain="employment")
        assert s["suggested_risk_tier"] == "high"
        assert s["effective_risk_tier"] == "high"
        assert s["confirmed_risk_tier"] is None
        refs = " ".join(r["reference"] for r in s["risk_assessment"]["rationale"])
        assert "Annex III(4)" in refs

    @pytest.mark.asyncio
    async def test_social_scoring_is_suggested_unacceptable(self, client, admin_token):
        s = await _create(client, admin_token, risk_flags=["social_scoring"])
        assert s["suggested_risk_tier"] == "unacceptable"

    @pytest.mark.asyncio
    async def test_unknown_flag_or_domain_rejected(self, client, admin_token):
        r1 = await client.post(BASE + "/", json={"name": "x", "risk_flags": ["mind_reading"]},
                               headers=auth_headers(admin_token))
        r2 = await client.post(BASE + "/", json={"name": "x", "domain": "astrology"},
                               headers=auth_headers(admin_token))
        assert r1.status_code == 422 and r2.status_code == 422

    @pytest.mark.asyncio
    async def test_changing_domain_resets_confirmation(self, client, admin_token, approver_token):
        s = await _create(client, admin_token)
        ok = await _confirm(client, approver_token, s["id"], "minimal")
        assert ok.status_code == 200 and ok.json()["review_status"] == "reviewed"
        r = await client.patch(f"{BASE}/{s['id']}", json={"domain": "employment"},
                               headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["confirmed_risk_tier"] is None
        assert body["review_status"] == "unreviewed"
        assert body["suggested_risk_tier"] == "high"


class TestLifecycleRules:
    @pytest.mark.asyncio
    async def test_production_requires_confirmed_risk(self, client, admin_token):
        s = await _create(client, admin_token, lifecycle_stage="validation")
        blocked = await _stage(client, admin_token, s["id"], "production")
        assert blocked.status_code == 409, blocked.text
        assert (await _confirm(client, admin_token, s["id"], "minimal")).status_code == 200
        ok = await _stage(client, admin_token, s["id"], "production")
        assert ok.status_code == 200 and ok.json()["lifecycle_stage"] == "production"
        assert ok.json()["attention"] == []

    @pytest.mark.asyncio
    async def test_unacceptable_never_goes_to_production(self, client, admin_token):
        s = await _create(client, admin_token, risk_flags=["social_scoring"])
        assert (await _confirm(client, admin_token, s["id"], "unacceptable")).status_code == 200
        r = await _stage(client, admin_token, s["id"], "production")
        assert r.status_code == 409, r.text

    @pytest.mark.asyncio
    async def test_cannot_create_directly_in_production(self, client, admin_token):
        r = await client.post(BASE + "/", json={"name": "sneaky", "lifecycle_stage": "production"},
                              headers=auth_headers(admin_token))
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_retiring_is_always_allowed(self, client, admin_token):
        s = await _create(client, admin_token)
        r = await _stage(client, admin_token, s["id"], "retired")
        assert r.status_code == 200 and r.json()["lifecycle_stage"] == "retired"


class TestRiskConfirmation:
    @pytest.mark.asyncio
    async def test_overriding_the_suggestion_needs_justification(self, client, admin_token):
        s = await _create(client, admin_token, domain="employment")  # suggested high
        bare = await _confirm(client, admin_token, s["id"], "minimal")
        assert bare.status_code == 400
        ok = await _confirm(client, admin_token, s["id"], "limited",
                            "Only schedules interviews; no evaluation of candidates (Art. 6(3) assessment on file)")
        assert ok.status_code == 200, ok.text
        body = ok.json()
        assert body["confirmed_risk_tier"] == "limited"
        assert body["effective_risk_tier"] == "limited"
        assert body["risk_confirmed_by"] is not None and body["risk_confirmed_at"]

    @pytest.mark.asyncio
    async def test_approver_can_confirm_but_not_create(self, client, admin_token, approver_token):
        denied = await client.post(BASE + "/", json={"name": "by-approver"}, headers=auth_headers(approver_token))
        assert denied.status_code == 403
        s = await _create(client, admin_token)
        assert (await _confirm(client, approver_token, s["id"], "minimal")).status_code == 200


class TestDataLinks:
    @pytest.mark.asyncio
    async def test_pii_link_adds_and_removes_data_protection_note(self, client, admin_token):
        s = await _create(client, admin_token)
        r = await client.post(
            f"{BASE}/{s['id']}/data-links",
            json={"relation": "accesses", "external_name": "CRM customer records", "contains_pii": True},
            headers=auth_headers(admin_token),
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert len(body["data_links"]) == 1 and body["data_protection_notes"]
        link_id = body["data_links"][0]["id"]
        d = await client.delete(f"{BASE}/{s['id']}/data-links/{link_id}", headers=auth_headers(admin_token))
        assert d.status_code == 200 and d.json()["data_links"] == [] and d.json()["data_protection_notes"] == []

    @pytest.mark.asyncio
    async def test_link_names_its_data_source(self, client, admin_token):
        s = await _create(client, admin_token)
        for body in ({"relation": "accesses"}, {"relation": "accesses", "external_name": ""},
                     {"relation": "accesses", "external_name": "   "},
                     {"relation": "trained_on", "dataset_id": 1},
                     {"relation": "trained_on", "external_name": "crm", "dataset_id": 1}):
            r = await client.post(f"{BASE}/{s['id']}/data-links", json=body, headers=auth_headers(admin_token))
            assert r.status_code == 422, body


class TestIsolationAndSummary:
    @pytest.mark.asyncio
    async def test_other_org_cannot_see_system(self, client, admin_token, db_session):
        s = await _create(client, admin_token, name="secret-system")
        await _create_org_with_admin_and_approver(
            db_session, org_slug="inv-other",
            admin_email="admin@inv-other.example.com", approver_email="approver@inv-other.example.com",
        )
        await db_session.commit()
        other = await _login(client, "inv-other", "admin@inv-other.example.com", "TestPass123!")
        assert (await client.get(f"{BASE}/{s['id']}", headers=auth_headers(other))).status_code == 404
        ids = [i["id"] for i in (await _list(client, other))["items"]]
        assert s["id"] not in ids
        assert (await _confirm(client, other, s["id"], "minimal")).status_code == 404

    @pytest.mark.asyncio
    async def test_summary_counts(self, client, admin_token):
        await _create(client, admin_token, domain="employment")
        await _create(client, admin_token, risk_flags=["social_scoring"])
        r = await client.get(BASE + "/summary", headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] >= 2
        assert body["by_tier"].get("high", 0) >= 1
        assert body["by_tier"].get("unacceptable", 0) >= 1
        assert "in_production_without_confirmed_risk" in body

    @pytest.mark.asyncio
    async def test_meta_lists_vocabulary(self, client, admin_token):
        r = await client.get(BASE + "/meta", headers=auth_headers(admin_token))
        assert r.status_code == 200
        body = r.json()
        assert "employment" in [d["id"] for d in body["domains"]]
        assert "social_scoring" in body["flags"]["prohibited"]
