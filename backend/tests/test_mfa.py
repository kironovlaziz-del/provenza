"""Two-factor sign-in (app/core/totp.py, app/services/mfa.py, /auth/login/mfa)."""

import time

import pytest

from app.core import totp
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from tests.conftest import _login, auth_headers

PW = "TestPass123!"


def now_code(secret: str, offset: int = 0) -> str:
    return totp.code_at(secret, int(time.time() // totp.STEP) + offset)


async def _enroll(client, token):
    setup = (await client.post("/api/v1/users/me/mfa/setup", headers=auth_headers(token))).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/") and setup["secret"]
    r = await client.post("/api/v1/users/me/mfa/enable", json={"code": now_code(setup["secret"])},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return setup["secret"], r.json()["recovery_codes"]


async def _password_step(client, org, email):
    r = await client.post("/api/v1/auth/login", json={"org_slug": org.slug, "email": email, "password": PW})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_enroll_and_sign_in_with_a_second_factor(client, org_and_users, admin_token):
    org, admin = org_and_users["org"], org_and_users["admin"]
    assert (await client.post("/api/v1/users/me/mfa/enable", json={"code": "123456"},
                              headers=auth_headers(admin_token))).status_code == 400      # no setup yet
    secret, codes = await _enroll(client, admin_token)
    assert len(codes) == 10
    me = (await client.get("/api/v1/users/me/mfa", headers=auth_headers(admin_token))).json()
    assert me["enabled"] is True and me["recovery_codes_left"] == 10

    step = await _password_step(client, org, admin.email)
    assert step["mfa_required"] is True and step["access_token"] is None and step["mfa_token"]
    # the half-way token is not a session
    assert (await client.get("/api/v1/users/me", headers=auth_headers(step["mfa_token"]))).status_code == 401

    code = now_code(secret, +1)        # the enrolment used the current step
    r = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": step["mfa_token"], "code": code})
    assert r.status_code == 200, r.text
    assert (await client.get("/api/v1/users/me", headers=auth_headers(r.json()["access_token"]))).status_code == 200
    # the same code cannot be used again
    step = await _password_step(client, org, admin.email)
    assert (await client.post("/api/v1/auth/login/mfa", json={"mfa_token": step["mfa_token"], "code": code})
            ).status_code == 401
    # a recovery code works once
    r = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": step["mfa_token"], "code": codes[0]})
    assert r.status_code == 200
    step = await _password_step(client, org, admin.email)
    assert (await client.post("/api/v1/auth/login/mfa", json={"mfa_token": step["mfa_token"], "code": codes[0]})
            ).status_code == 401


@pytest.mark.asyncio
async def test_code_guessing_is_limited(client, org_and_users, admin_token):
    org, admin = org_and_users["org"], org_and_users["admin"]
    await _enroll(client, admin_token)
    step = await _password_step(client, org, admin.email)
    for _ in range(5):
        r = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": step["mfa_token"], "code": "000000"})
        assert r.status_code == 401
    r = await client.post("/api/v1/auth/login/mfa", json={"mfa_token": step["mfa_token"], "code": "000000"})
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_disable_needs_both_factors(client, admin_token):
    secret, _ = await _enroll(client, admin_token)
    assert (await client.post("/api/v1/users/me/mfa/disable", json={"password": "wrong", "code": now_code(secret, 1)},
                              headers=auth_headers(admin_token))).status_code == 400
    r = await client.post("/api/v1/users/me/mfa/disable", json={"password": PW, "code": now_code(secret, 1)},
                          headers=auth_headers(admin_token))
    assert r.status_code == 204
    assert (await client.get("/api/v1/users/me/mfa", headers=auth_headers(admin_token))).json()["enabled"] is False


@pytest.mark.asyncio
async def test_the_organization_policy_holds_users_until_they_enroll(client, db_session, org_and_users, admin_token,
                                                                    approver_token):
    org = org_and_users["org"]
    db_session.add(User(org_id=org.id, email="plain@test.example.com", name="Plain", role=UserRole.user.value,
                        hashed_password=get_password_hash(PW), status="active"))
    await db_session.flush()
    plain = await _login(client, org.slug, "plain@test.example.com", PW)

    secret, _ = await _enroll(client, admin_token)           # the admin first, so they stay usable
    r = await client.put("/api/v1/users/mfa-policy", json={"mfa_required": "reviewers"}, headers=auth_headers(admin_token))
    assert r.status_code == 200
    # the approver must enroll before anything else
    r = await client.get("/api/v1/incidents/", headers=auth_headers(approver_token))
    assert r.status_code == 403 and r.json()["detail"] == "auth.mfa_setup_required"
    assert (await client.get("/api/v1/users/me", headers=auth_headers(approver_token))).status_code == 200
    assert (await client.get("/api/v1/users/me/mfa", headers=auth_headers(approver_token))).json()["required"] is True
    await _enroll(client, approver_token)
    assert (await client.get("/api/v1/incidents/", headers=auth_headers(approver_token))).status_code == 200
    # a plain user is not covered by "reviewers"
    assert (await client.get("/api/v1/incidents/", headers=auth_headers(plain))).status_code == 200
    # while required, the second factor cannot be switched off
    r = await client.post("/api/v1/users/me/mfa/disable", json={"password": PW, "code": now_code(secret, 1)},
                          headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"] == "mfa.required_by_policy"


@pytest.mark.asyncio
async def test_an_admin_resets_a_lost_device(client, org_and_users, admin_token, approver_token):
    org, approver = org_and_users["org"], org_and_users["approver"]
    await _enroll(client, approver_token)
    r = await client.post(f"/api/v1/users/{approver.id}/mfa/reset", headers=auth_headers(approver_token))
    assert r.status_code == 403
    r = await client.post(f"/api/v1/users/{approver.id}/mfa/reset", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["totp_enabled"] is False
    # their sessions ended; the next sign-in is password only (until they enroll again)
    assert (await client.get("/api/v1/users/me", headers=auth_headers(approver_token))).status_code == 401
    step = await _password_step(client, org, approver.email)
    assert step["access_token"] and not step["mfa_required"]
