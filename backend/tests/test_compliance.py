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
        assert set(cat["frameworks"]) == {"eu_ai_act", "gdpr", "iso42001", "nist_ai_rmf", "owasp_agentic",
                                          "owasp_llm", "mitre_atlas", "nis2", "dora"}
        res = await _status(client, admin_token)
        assert len(res["requirements"]) == len(cat["requirements"])
        for fw, s in res["summary"].items():
            assert set(s["counts"]) == {"pass", "partial", "fail", "manual", "na"}
            assert s["score"] is None or 0 <= s["score"] <= 100
        assert all(r["status"] in ("pass", "partial", "fail", "manual", "na") for r in res["requirements"])
        only = await _status(client, admin_token, "gdpr")
        assert set(only["summary"]) == {"gdpr"} and all(r["framework"] == "gdpr" for r in only["requirements"])

    @pytest.mark.asyncio
    async def test_content_guards_are_attested_not_checked(self, client, admin_token):
        """Provenza no longer scans content: ASI01/05/06/07 and LLM02 are
        confirmed by a person, not measured."""
        await _agent(client, admin_token)
        res = await _status(client, admin_token, "owasp_agentic,owasp_llm")
        for rid in ("asi01", "asi05", "asi06", "asi07", "llm02"):
            r = _req(res, rid)
            assert r["attest"] is True and r["status"] == "manual" and r["fix"] is None, (rid, r)
        r = await client.post(C + "/attestations", json={"requirement_id": "asi01", "status": "met"},
                              headers=auth_headers(admin_token))
        assert r.status_code in (200, 201), r.text
        assert _req(await _status(client, admin_token, "owasp_agentic"), "asi01")["status"] == "pass"

    @pytest.mark.asyncio
    async def test_retention_drives_gdpr_storage_limitation(self, client, admin_token):
        R = "/api/v1/retention/settings"
        await client.put(R, json={"agent_content_retention_days": None}, headers=auth_headers(admin_token))
        r = _req(await _status(client, admin_token, "gdpr"), "gdpr.art5_1e")
        assert r["status"] == "fail" and r["fix"] == "/retention"
        assert _req(await _status(client, admin_token, "gdpr"), "gdpr.art25")["status"] == "partial"
        await client.put(R, json={"agent_content_retention_days": 90}, headers=auth_headers(admin_token))
        res = await _status(client, admin_token, "gdpr")
        r = _req(res, "gdpr.art5_1e")
        assert r["status"] == "pass" and any(e["value"] == 90 for e in r["evidence"])
        assert _req(res, "gdpr.art25")["status"] == "pass"


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


class TestAIActRoles:
    """The organization's role per AI system (provider, deployer, importer,
    distributor) decides which EU AI Act obligations apply to it."""

    @pytest.mark.asyncio
    async def test_a_deployer_gets_deployer_obligations_only(self, client, admin_token):
        sid = await _high_risk_system(client, admin_token)
        r = await client.patch(f"/api/v1/inventory/{sid}", json={"ai_act_roles": ["deployer"]},
                               headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["ai_act_roles"] == ["deployer"]

        res = await _status(client, admin_token, "eu_ai_act")
        on = lambda rid: [s["system_id"] for s in _req(res, rid).get("systems", [])]
        assert sid not in on("euaia.art9") and sid not in on("euaia.art11")   # provider's
        assert sid in on("euaia.art27") and sid in on("euaia.art14")          # deployer's, both
        assert _req(res, "euaia.art17")["status"] == "na"                     # org-wide, provider only
        assert "provider" in _req(res, "euaia.art17")["detail"]
        assert _req(res, "euaia.art26")["status"] != "na"
        assert _req(res, "euaia.art3")["status"] == "pass"

    @pytest.mark.asyncio
    async def test_unstated_roles_keep_every_obligation(self, client, admin_token):
        sid = await _high_risk_system(client, admin_token)
        res = await _status(client, admin_token, "eu_ai_act")
        for rid in ("euaia.art9", "euaia.art23", "euaia.art24", "euaia.art27"):
            assert sid in [s["system_id"] for s in _req(res, rid)["systems"]], rid
        assert _req(res, "euaia.art3")["status"] in ("fail", "partial")

    @pytest.mark.asyncio
    async def test_roles_are_validated(self, client, admin_token):
        sid = await _high_risk_system(client, admin_token)
        for bad in (["manufacturer"], None):
            r = await client.patch(f"/api/v1/inventory/{sid}", json={"ai_act_roles": bad},
                                   headers=auth_headers(admin_token))
            assert r.status_code == 422, bad
        r = await client.patch(f"/api/v1/inventory/{sid}", json={"ai_act_roles": ["deployer", "provider", "deployer"]},
                               headers=auth_headers(admin_token))
        assert r.json()["ai_act_roles"] == ["provider", "deployer"]


class TestMoreFrameworks:
    """OWASP LLM Top 10, MITRE ATLAS, NIS2 and DORA read the same Provenza
    evidence; what only a person can confirm is attested."""

    @pytest.mark.asyncio
    async def test_consumption_caps_and_mfa(self, client, admin_token, db_session, org_and_users):
        res = await _status(client, admin_token, "owasp_llm,mitre_atlas,nis2,dora")
        assert set(res["summary"]) == {"owasp_llm", "mitre_atlas", "nis2", "dora"}
        # the gateway's default caps
        assert _req(res, "llm10")["status"] == "pass" and _req(res, "atlas.m0004")["status"] == "pass"

        assert _req(res, "nis2.21j")["status"] == "fail"           # no second factor required
        # require it for everyone (the admin has one, so its session goes on)
        org_and_users["org"].mfa_required = "all"
        org_and_users["admin"].totp_enabled = True
        await db_session.flush()
        assert _req(await _status(client, admin_token, "nis2"), "nis2.21j")["status"] == "pass"

    @pytest.mark.asyncio
    async def test_attested_items(self, client, admin_token):
        r = await client.post(C + "/attestations", json={"requirement_id": "llm05", "status": "met"},
                              headers=auth_headers(admin_token))
        assert r.status_code in (200, 201), r.text
        assert _req(await _status(client, admin_token, "owasp_llm"), "llm05")["status"] == "pass"



class TestFrameworkSelection:
    """An organization chooses the frameworks it follows; the status and new
    reports default to that choice."""

    @pytest.mark.asyncio
    async def test_choose_frameworks(self, client, admin_token, approver_token):
        h = auth_headers(admin_token)
        got = (await client.get(C + "/frameworks", headers=h)).json()
        assert set(got["selected"]) == set(got["available"]) and "dora" in got["available"]

        r = await client.put(C + "/frameworks", json={"frameworks": ["gdpr", "eu_ai_act"]}, headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["selected"] == ["eu_ai_act", "gdpr"]              # catalog order
        assert (await client.get(C + "/frameworks", headers=h)).json()["selected"] == ["eu_ai_act", "gdpr"]

        assert set((await _status(client, admin_token))["summary"]) == {"eu_ai_act", "gdpr"}
        # an explicit choice still shows any framework
        assert set((await _status(client, admin_token, "dora"))["summary"]) == {"dora"}
        rep = await client.post(C + "/reports", json={}, headers=h)
        assert rep.status_code == 200, rep.text
        got = (await client.get(f"{C}/reports/{rep.json()['id']}", headers=h)).json()
        assert set(got["content"]["summary"]) == {"eu_ai_act", "gdpr"}

        # choosing all of them goes back to "all", including frameworks added later
        every = list((await client.get(C + "/frameworks", headers=h)).json()["available"])
        assert (await client.put(C + "/frameworks", json={"frameworks": every}, headers=h)).status_code == 200
        assert set((await _status(client, admin_token))["summary"]) == set(every)

    @pytest.mark.asyncio
    async def test_rules(self, client, admin_token, approver_token):
        h = auth_headers(admin_token)
        assert (await client.put(C + "/frameworks", json={"frameworks": []}, headers=h)).status_code == 422
        assert (await client.put(C + "/frameworks", json={"frameworks": ["sox"]}, headers=h)).status_code == 422
        # approvers read the choice but do not change it
        assert (await client.get(C + "/frameworks", headers=auth_headers(approver_token))).status_code == 200
        assert (await client.put(C + "/frameworks", json={"frameworks": ["gdpr"]},
                                 headers=auth_headers(approver_token))).status_code == 403

    @pytest.mark.asyncio
    async def test_reports_accept_every_framework(self, client, admin_token):
        r = await client.post(C + "/reports", json={"frameworks": ["nis2", "dora"]}, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert (await client.post(C + "/reports", json={"frameworks": ["nope"]},
                                  headers=auth_headers(admin_token))).status_code == 422
