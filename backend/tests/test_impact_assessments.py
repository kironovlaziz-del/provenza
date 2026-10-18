"""Impact assessments: one questionnaire per AI system (ISO/IEC 42005, DPIA,
FRIA), a draft edited in place, approved versions frozen, and the compliance
requirements that read them (EU AI Act 27, GDPR 35, ISO 42001 A.5)."""

import secrets

from app.core.security import get_password_hash
from app.models.user import User, UserRole
from tests.conftest import _login, auth_headers

IA = "/api/v1/impact-assessments"

COMPLETE = {
    "purpose": "Ranks job applications for recruiters", "affected": ["job_applicants"], "scale": "100_10k",
    "rights": ["non_discrimination", "employment"], "harm": "Qualified people ranked low",
    "severity": "high", "likelihood": "possible", "reversibility": "hard_to_reverse",
    "personal_data": "no",
    "measures": "Bias tests each quarter; a recruiter reviews every rejection",
    "oversight": "The head of recruiting can stop it", "redress": "Applicants may ask for a human review",
    "residual": "medium", "decision": "proceed",
}


async def _system(client, token, roles=None):
    r = await client.post("/api/v1/inventory/", json={"name": "ia-" + secrets.token_hex(3), "kind": "other",
                                                      "domain": "general"}, headers=auth_headers(token))
    sid = r.json()["id"]
    await client.post(f"/api/v1/inventory/{sid}/confirm-risk", json={"tier": "high", "justification": "hiring"},
                      headers=auth_headers(token))
    if roles:
        await client.patch(f"/api/v1/inventory/{sid}", json={"ai_act_roles": roles}, headers=auth_headers(token))
    return sid


def _req(res, rid):
    return next(r for r in res["requirements"] if r["id"] == rid)


async def _row(client, token, rid, sid, fw):
    res = (await client.get("/api/v1/compliance/status", params={"frameworks": fw}, headers=auth_headers(token))).json()
    return next(s for s in _req(res, rid)["systems"] if s["system_id"] == sid)


async def test_draft_approve_and_new_version(client, admin_token):
    h = auth_headers(admin_token)
    sid = await _system(client, admin_token)
    tpl = (await client.get(IA + "/template", headers=h)).json()
    assert [s["id"] for s in tpl["sections"]] == ["purpose", "rights", "data", "measures", "conclusion"]

    r = await client.put(f"{IA}/systems/{sid}/draft", json={"answers": {"severity": "extreme"}}, headers=h)
    assert r.status_code == 422 and r.json()["detail"]["context"]["question"] == "severity"

    r = await client.put(f"{IA}/systems/{sid}/draft", json={"answers": {"purpose": "x"}}, headers=h)
    assert r.status_code == 200 and r.json()["version"] == 1 and "harm" in r.json()["missing"]
    r = await client.post(f"{IA}/systems/{sid}/approve", headers=h)
    assert r.status_code == 422 and "harm" in r.json()["detail"]["context"]["missing"]

    # personal data -> its questions become required
    r = await client.put(f"{IA}/systems/{sid}/draft", json={"answers": {**COMPLETE, "personal_data": "yes"}}, headers=h)
    assert set(r.json()["missing"]) == {"categories", "lawful_basis", "necessity", "retention", "transfers"}

    r = await client.put(f"{IA}/systems/{sid}/draft", json={"answers": COMPLETE}, headers=h)
    assert r.json()["missing"] == []
    r = await client.post(f"{IA}/systems/{sid}/approve", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "approved" and r.json()["review_due"]

    # the next change is version 2; version 1 stays as approved
    r = await client.put(f"{IA}/systems/{sid}/draft", json={"answers": {**COMPLETE, "residual": "low"}}, headers=h)
    assert r.json()["version"] == 2
    view = (await client.get(f"{IA}/systems/{sid}", headers=h)).json()
    assert view["approved"]["version"] == 1 and view["approved"]["answers"]["residual"] == "medium"
    assert view["draft"]["version"] == 2 and [v["version"] for v in view["history"]] == [1]


async def test_compliance_reads_the_assessment(client, admin_token):
    h = auth_headers(admin_token)
    sid = await _system(client, admin_token, roles=["deployer"])
    assert (await _row(client, admin_token, "euaia.art27", sid, "eu_ai_act"))["status"] == "fail"
    await client.put(f"{IA}/systems/{sid}/draft", json={"answers": COMPLETE}, headers=h)
    assert (await _row(client, admin_token, "euaia.art27", sid, "eu_ai_act"))["status"] == "partial"
    await client.post(f"{IA}/systems/{sid}/approve", headers=h)
    assert (await _row(client, admin_token, "euaia.art27", sid, "eu_ai_act"))["status"] == "pass"

    # personal data in its data links, while the assessment says none: the DPIA is incomplete
    r = await client.post(f"/api/v1/inventory/{sid}/data-links",
                          json={"relation": "accesses", "external_name": "hr-db", "contains_pii": True}, headers=h)
    assert r.status_code == 200, r.text
    assert (await _row(client, admin_token, "gdpr.art35", sid, "gdpr"))["status"] == "partial"


async def test_who_may_edit(client, admin_token, approver_token, db_session, org_and_users):
    sid = await _system(client, admin_token)
    r = await client.put(f"{IA}/systems/{sid}/draft", json={"answers": COMPLETE}, headers=auth_headers(approver_token))
    assert r.status_code == 403
    assert (await client.get(f"{IA}/systems/{sid}", headers=auth_headers(approver_token))).status_code == 200

    db_session.add(User(org_id=org_and_users["org"].id, email="dpo@test.example.com", name="DPO",
                        hashed_password=get_password_hash(org_and_users["password"]),
                        role=UserRole.compliance.value, status="active"))
    await db_session.flush()
    dpo = await _login(client, org_and_users["org"].slug, "dpo@test.example.com", org_and_users["password"])
    r = await client.put(f"{IA}/systems/{sid}/draft", json={"answers": COMPLETE}, headers=auth_headers(dpo))
    assert r.status_code == 200, r.text
    assert (await client.post(f"{IA}/systems/{sid}/approve", headers=auth_headers(dpo))).status_code == 200
