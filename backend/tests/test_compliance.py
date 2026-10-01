"""
Compliance auto-mapping: catalog, live status from Provenza data, OWASP
items following the guard modes, per-system EU AI Act obligations for a
high-risk system, attestations (rules, expiry of the manual state), and
immutable reports with an integrity hash.
"""

import secrets

import pytest

from tests.conftest import auth_headers

C = "/api/v1/compliance"


async def _status(client, token, frameworks=None):
    r = await client.get(C + "/status", params={"frameworks": frameworks} if frameworks else None,
                         headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _req(result, rid):
    return next(r for r in result["requirements"] if r["id"] == rid)


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register",
                          json={"name": "cmp-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
                                "allowed_tools": [], "allowed_models": [], "max_delegation_depth": 1},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _high_risk_system(client, token):
    r = await client.post("/api/v1/inventory/", json={"name": "hr-" + secrets.token_hex(3), "kind": "other",
                                                      "domain": "general"}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    r = await client.post(f"/api/v1/inventory/{sid}/confirm-risk",
                          json={"tier": "high", "justification": "screens job applicants"}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return sid


class TestStatus:
    @pytest.mark.asyncio
    async def test_catalog_and_all_frameworks(self, client, admin_token):
        cat = (await client.get(C + "/catalog", headers=auth_headers(admin_token))).json()
        assert set(cat["frameworks"]) == {"eu_ai_act", "gdpr", "iso42001", "nist_ai_rmf", "owasp_agentic"}
        res = await _status(client, admin_token)
        assert len(res["requirements"]) == len(cat["requirements"])
        for fw, s in res["summary"].items():
            assert set(s["counts"]) == {"pass", "partial", "fail", "manual", "na"}
            assert s["score"] is None or 0 <= s["score"] <= 100
        assert all(r["status"] in ("pass", "partial", "fail", "manual", "na") for r in res["requirements"])
        only = await _status(client, admin_token, "gdpr")
        assert set(only["summary"]) == {"gdpr"} and all(r["framework"] == "gdpr" for r in only["requirements"])

    @pytest.mark.asyncio
    async def test_owasp_items_follow_guard_modes(self, client, admin_token):
        await _agent(client, admin_token)
        await client.put("/api/v1/injection/settings", json={"mode": "enforce", "threshold": 60}, headers=auth_headers(admin_token))
        assert _req(await _status(client, admin_token, "owasp_agentic"), "asi01")["status"] == "pass"
        await client.put("/api/v1/injection/settings", json={"mode": "monitor", "threshold": 60}, headers=auth_headers(admin_token))
        assert _req(await _status(client, admin_token, "owasp_agentic"), "asi01")["status"] == "partial"
        await client.put("/api/v1/injection/settings", json={"mode": "off", "threshold": 60}, headers=auth_headers(admin_token))
        r = _req(await _status(client, admin_token, "owasp_agentic"), "asi01")
        assert r["status"] == "fail" and r["fix"] == "/agent-injection"
        await client.put("/api/v1/injection/settings", json={"mode": "monitor", "threshold": 60}, headers=auth_headers(admin_token))

    @pytest.mark.asyncio
    async def test_retention_drives_gdpr_storage_limitation(self, client, admin_token):
        base = {"queue_ttl_seconds": 900, "approval_ttl_hours": 72}
        await client.put("/api/v1/queue/settings", json={**base, "raw_prompt_retention_days": None}, headers=auth_headers(admin_token))
        assert _req(await _status(client, admin_token, "gdpr"), "gdpr.art5_1e")["status"] == "fail"
        await client.put("/api/v1/queue/settings", json={**base, "raw_prompt_retention_days": 90}, headers=auth_headers(admin_token))
        r = _req(await _status(client, admin_token, "gdpr"), "gdpr.art5_1e")
        assert r["status"] == "pass" and any(e["value"] == 90 for e in r["evidence"])
        await client.put("/api/v1/queue/settings", json={**base, "raw_prompt_retention_days": None}, headers=auth_headers(admin_token))


class TestHighRiskSystem:
    @pytest.mark.asyncio
    async def test_per_system_obligations_and_attestation(self, client, admin_token):
        sid = await _high_risk_system(client, admin_token)
        res = await _status(client, admin_token, "eu_ai_act")
        art9 = next(s for s in _req(res, "euaia.art9")["systems"] if s["system_id"] == sid)
        assert art9["status"] == "pass"                                   # risk confirmed by a person
        art11 = next(s for s in _req(res, "euaia.art11")["systems"] if s["system_id"] == sid)
        assert art11["status"] == "manual"                                # technical documentation: a person states it

        r = await client.post(C + "/attestations", json={"requirement_id": "euaia.art11", "system_id": sid, "status": "met",
                                                         "note": "Annex IV file v1", "evidence_url": "https://docs.example/annex-iv"},
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        res = await _status(client, admin_token, "eu_ai_act")
        art11 = next(s for s in _req(res, "euaia.art11")["systems"] if s["system_id"] == sid)
        assert art11["status"] == "pass" and art11["attestation"]["evidence_url"] == "https://docs.example/annex-iv"

        sys_view = (await client.get(f"{C}/systems/{sid}", headers=auth_headers(admin_token))).json()
        assert {r["id"] for r in sys_view["requirements"]} >= {"euaia.art9", "euaia.art11", "euaia.art14"}

        # a newer attestation supersedes the old one; the history stays
        await client.post(C + "/attestations", json={"requirement_id": "euaia.art11", "system_id": sid, "status": "not_met"},
                          headers=auth_headers(admin_token))
        res = await _status(client, admin_token, "eu_ai_act")
        assert next(s for s in _req(res, "euaia.art11")["systems"] if s["system_id"] == sid)["status"] == "fail"
        hist = (await client.get(C + "/attestations", params={"requirement_id": "euaia.art11", "system_id": sid},
                                 headers=auth_headers(admin_token))).json()
        assert [h["status"] for h in hist] == ["not_met", "met"]

    @pytest.mark.asyncio
    async def test_attestation_rules(self, client, admin_token, approver_token):
        sid = await _high_risk_system(client, admin_token)
        cases = [
            ({"requirement_id": "gdpr.art5_1e", "status": "met"}, 409),                     # automatic
            ({"requirement_id": "euaia.art11", "status": "met"}, 422),                      # per system, no id
            ({"requirement_id": "euaia.art4", "system_id": sid, "status": "met"}, 422),     # org-wide with id
            ({"requirement_id": "nope", "status": "met"}, 404),
            ({"requirement_id": "euaia.art4", "status": "maybe"}, 422),
            ({"requirement_id": "euaia.art4", "status": "met", "evidence_url": "javascript:alert(1)"}, 422),
        ]
        for body, code in cases:
            r = await client.post(C + "/attestations", json=body, headers=auth_headers(admin_token))
            assert r.status_code == code, (body, r.status_code, r.text)
        r = await client.post(C + "/attestations", json={"requirement_id": "euaia.art4", "status": "met"},
                              headers=auth_headers(approver_token))
        assert r.status_code == 403
        assert (await client.get(C + "/status", headers=auth_headers(approver_token))).status_code == 200


class TestReports:
    @pytest.mark.asyncio
    async def test_report_snapshot_and_integrity(self, client, admin_token):
        r = await client.post(C + "/reports", json={"frameworks": ["eu_ai_act", "gdpr"]}, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        rid, digest = r.json()["id"], r.json()["sha256"]
        got = (await client.get(f"{C}/reports/{rid}", headers=auth_headers(admin_token))).json()
        assert got["sha256"] == digest and got["integrity_ok"] is True
        assert set(got["content"]["summary"]) == {"eu_ai_act", "gdpr"}
        lst = (await client.get(C + "/reports", headers=auth_headers(admin_token))).json()
        assert lst[0]["id"] == rid and "content" not in lst[0]
        assert (await client.get(f"{C}/reports/99999999", headers=auth_headers(admin_token))).status_code == 404
