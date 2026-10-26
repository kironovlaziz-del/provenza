"""Oversight roles. An auditor reads everything an admin or approver reads and
changes nothing; a compliance officer reads the same and confirms compliance
requirements (app/api/deps.py, app/models/user.py)."""

from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.services.mfa import policy_applies
from tests.conftest import _login, auth_headers


async def _token_for(client, db_session, org_and_users, role: UserRole) -> str:
    email = f"{role.value}@test.example.com"
    db_session.add(User(org_id=org_and_users["org"].id, email=email, name=role.value,
                        hashed_password=get_password_hash(org_and_users["password"]),
                        role=role.value, status="active"))
    await db_session.flush()
    return await _login(client, org_and_users["org"].slug, email, org_and_users["password"])


async def test_auditor_reads_admin_pages_and_changes_nothing(client, db_session, org_and_users):
    token = await _token_for(client, db_session, org_and_users, UserRole.auditor)
    h = auth_headers(token)

    r = await client.get("/api/v1/users/", headers=h)  # admin only
    assert r.status_code == 200, r.text

    r = await client.post("/api/v1/kill-switch/events", headers=h,
                          json={"scope": "all_agents", "reason": "x", "confirm": "STOP"})
    assert r.status_code == 403 and r.json()["detail"] == "rbac.read_only"

    # a GET that issues a key stays closed
    r = await client.get("/api/v1/shadow-ai/extension/download", headers=h)
    assert r.status_code == 403

    # what an audit produces is allowed
    r = await client.post("/api/v1/audit-logs/verify", headers=h)
    assert r.status_code == 200, r.text
    # and its own account
    r = await client.get("/api/v1/users/me", headers=h)
    assert r.status_code == 200 and r.json()["role"] == "auditor"


async def test_compliance_reads_but_does_not_administer(client, db_session, org_and_users):
    token = await _token_for(client, db_session, org_and_users, UserRole.compliance)
    h = auth_headers(token)
    assert (await client.get("/api/v1/users/", headers=h)).status_code == 200
    r = await client.post("/api/v1/kill-switch/events", headers=h,
                          json={"scope": "all_agents", "reason": "x", "confirm": "STOP"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "rbac.insufficient_role"


async def test_admin_can_give_the_new_roles(client, admin_token, org_and_users):
    approver_id = org_and_users["approver"].id
    for role in ("auditor", "compliance"):
        r = await client.put(f"/api/v1/users/{approver_id}/role", json={"role": role},
                             headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["role"] == role


def test_reviewers_mfa_policy_covers_the_oversight_roles():
    assert policy_applies("reviewers", "auditor")
    assert policy_applies("reviewers", "compliance")
    assert not policy_applies("reviewers", "user")


async def test_a_public_demo_login_cannot_change_its_own_account(client, db_session, org_and_users, monkeypatch):
    """DEMO_ACCOUNTS: a shared demo login reads like any auditor, but its
    password, second factor and passkeys stay as they are for every visitor."""
    from app.core.config import settings

    token = await _token_for(client, db_session, org_and_users, UserRole.auditor)
    h = auth_headers(token)
    monkeypatch.setattr(settings, "DEMO_ACCOUNTS", "someone@else.example, AUDITOR@test.example.com")

    for path, body in (("/api/v1/users/me/password", {"current_password": org_and_users["password"],
                                                       "new_password": "another-Passw0rd-1"}),
                       ("/api/v1/users/me/mfa/setup", None),
                       ("/api/v1/users/me/passkeys/options", {})):
        r = await client.post(path, headers=h, json=body)
        assert r.status_code == 403 and r.json()["detail"] == "demo.read_only", (path, r.text)

    # it still reads, signs out and runs an audit check
    assert (await client.get("/api/v1/users/me", headers=h)).status_code == 200
    assert (await client.post("/api/v1/audit-logs/verify", headers=h)).status_code == 200

    # an auditor that is not a demo login keeps its own account
    monkeypatch.setattr(settings, "DEMO_ACCOUNTS", "")
    r = await client.post("/api/v1/users/me/mfa/setup", headers=h)
    assert r.status_code != 403, r.text
