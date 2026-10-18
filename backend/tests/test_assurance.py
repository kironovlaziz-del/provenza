"""Assurance records: tests an AI system went through - evaluations, bias
tests, red teaming, robustness - kept append-only, and the compliance
requirements that read them (EU AI Act Art. 10 and 15, ISO 42001 A.6.2.4,
NIST MEASURE 1)."""

import secrets
from datetime import date, timedelta

from tests.conftest import auth_headers

A = "/api/v1/assurance"


async def _system(client, token):
    r = await client.post("/api/v1/inventory/", json={"name": "as-" + secrets.token_hex(3), "kind": "other",
                                                      "domain": "general"}, headers=auth_headers(token))
    sid = r.json()["id"]
    await client.post(f"/api/v1/inventory/{sid}/confirm-risk", json={"tier": "high", "justification": "credit"},
                      headers=auth_headers(token))
    return sid


def _rec(kind, result="passed", days_ago=10, **kw):
    return {"kind": kind, "title": f"{kind} run", "performed_on": (date.today() - timedelta(days=days_ago)).isoformat(),
            "performed_by": "ML team", "result": result, **kw}


async def _row(client, token, rid, sid, fw):
    res = (await client.get("/api/v1/compliance/status", params={"frameworks": fw}, headers=auth_headers(token))).json()
    req = next(r for r in res["requirements"] if r["id"] == rid)
    return next(s for s in req["systems"] if s["system_id"] == sid)


async def test_records_drive_article_15(client, admin_token):
    h = auth_headers(admin_token)
    sid = await _system(client, admin_token)
    assert (await _row(client, admin_token, "euaia.art15", sid, "eu_ai_act"))["status"] == "fail"

    r = await client.post(f"{A}/systems/{sid}", json=_rec("evaluation"), headers=h)
    assert r.status_code == 201, r.text
    row = await _row(client, admin_token, "euaia.art15", sid, "eu_ai_act")
    assert row["status"] == "partial" and "red teaming" in row["detail"]

    await client.post(f"{A}/systems/{sid}", json=_rec("red_team", "passed_with_findings"), headers=h)
    assert (await _row(client, admin_token, "euaia.art15", sid, "eu_ai_act"))["status"] == "pass"

    # a newer failed evaluation, and an old test no longer counts
    await client.post(f"{A}/systems/{sid}", json=_rec("evaluation", "failed", days_ago=1), headers=h)
    row = await _row(client, admin_token, "euaia.art15", sid, "eu_ai_act")
    assert row["status"] == "partial" and "failed" in row["detail"]

    listed = (await client.get(f"{A}/systems/{sid}", headers=h)).json()
    # newest first; on the same day, the later record first
    assert [x["kind"] for x in listed] == ["evaluation", "red_team", "evaluation"]


async def test_bias_test_completes_article_10(client, admin_token):
    h = auth_headers(admin_token)
    sid = await _system(client, admin_token)
    await client.post(f"/api/v1/inventory/{sid}/data-links",
                      json={"relation": "trained_on", "external_name": "loans-2025"}, headers=h)
    row = await _row(client, admin_token, "euaia.art10", sid, "eu_ai_act")
    assert row["status"] == "partial" and "bias" in row["detail"]
    await client.post(f"{A}/systems/{sid}", json=_rec("bias"), headers=h)
    assert (await _row(client, admin_token, "euaia.art10", sid, "eu_ai_act"))["status"] == "pass"


async def test_old_tests_expire_and_input_is_checked(client, admin_token):
    h = auth_headers(admin_token)
    sid = await _system(client, admin_token)
    await client.post(f"{A}/systems/{sid}", json=_rec("evaluation", days_ago=400), headers=h)
    await client.post(f"{A}/systems/{sid}", json=_rec("robustness", days_ago=400), headers=h)
    assert (await _row(client, admin_token, "euaia.art15", sid, "eu_ai_act"))["status"] == "fail"

    future = _rec("evaluation", days_ago=-3)
    assert (await client.post(f"{A}/systems/{sid}", json=future, headers=h)).status_code == 422
    bad_url = _rec("evaluation", evidence_url="javascript:alert(1)")
    assert (await client.post(f"{A}/systems/{sid}", json=bad_url, headers=h)).status_code == 422
    assert (await client.post(f"{A}/systems/{sid}", json=_rec("pentest"), headers=h)).status_code == 422


async def test_users_cannot_record(client, db_session, org_and_users):
    from app.core.security import get_password_hash
    from app.models.user import User, UserRole
    from tests.conftest import _login

    db_session.add(User(org_id=org_and_users["org"].id, email="u@test.example.com", name="U",
                        hashed_password=get_password_hash(org_and_users["password"]),
                        role=UserRole.user.value, status="active"))
    await db_session.flush()
    token = await _login(client, org_and_users["org"].slug, "u@test.example.com", org_and_users["password"])
    admin = await _login(client, org_and_users["org"].slug, org_and_users["admin"].email, org_and_users["password"])
    sid = await _system(client, admin)
    assert (await client.post(f"{A}/systems/{sid}", json=_rec("evaluation"), headers=auth_headers(token))).status_code == 403
