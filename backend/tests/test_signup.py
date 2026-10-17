# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Self-service sign-up is off unless ALLOW_PUBLIC_SIGNUP is set, and throttled when on."""

from sqlalchemy import func, select

from app.api import users as users_api
from app.core.config import settings
from app.models.organization import Organization


def _payload(n: int) -> dict:
    return {
        "email": f"owner{n}@example.com",
        "password": "TestPass123!",
        "name": "Owner",
        "org_name": f"Signup Org {n}",
        "org_slug": f"signup-org-{n}",
    }


async def test_signup_is_disabled_by_default(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_PUBLIC_SIGNUP", False)
    before = (await db_session.execute(select(func.count(Organization.id)))).scalar_one()

    resp = await client.post("/api/v1/users/register", json=_payload(1))

    assert resp.status_code == 403
    assert resp.json()["detail"] == "auth.signup_disabled"
    after = (await db_session.execute(select(func.count(Organization.id)))).scalar_one()
    assert after == before


async def test_auth_config_reports_the_flag(client, monkeypatch):
    # /auth/config also carries `features`; assert the field, not the
    # whole shape, so adding a feature flag does not break signup.
    monkeypatch.setattr(settings, "ALLOW_PUBLIC_SIGNUP", False)
    body = (await client.get("/api/v1/auth/config")).json()
    assert body["signup_enabled"] is False
    assert "features" in body

    monkeypatch.setattr(settings, "ALLOW_PUBLIC_SIGNUP", True)
    body = (await client.get("/api/v1/auth/config")).json()
    assert body["signup_enabled"] is True


async def test_signup_is_throttled_per_ip(client, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_PUBLIC_SIGNUP", True)
    for n in range(users_api.SIGNUP_IP_LIMIT):
        resp = await client.post("/api/v1/users/register", json=_payload(100 + n))
        assert resp.status_code == 200, resp.text

    resp = await client.post("/api/v1/users/register", json=_payload(999))
    assert resp.status_code == 429
