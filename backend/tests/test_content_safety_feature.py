"""Feature flag: content_safety off by default, exposed via /auth/config.

The product is AI governance. Content safety (prompt firewall, PII
masking, blocked terms, intent guardrail, injection / memory / code-exec
guards) is an optional add-on for regulated customers. Off by default
so a fresh install reads as governance. /auth/config tells the UI what
to render before the user logs in.
"""

from app.core.config import settings


async def test_auth_config_exposes_features_default_off(client):
    r = await client.get("/api/v1/auth/config")
    assert r.status_code == 200
    body = r.json()
    assert "features" in body
    assert body["features"]["content_safety"] is False


async def test_auth_config_exposes_features_when_enabled(client, monkeypatch):
    monkeypatch.setattr(settings, "CONTENT_SAFETY_ENABLED", True)
    r = await client.get("/api/v1/auth/config")
    body = r.json()
    assert body["features"]["content_safety"] is True


def test_content_safety_off_by_default():
    # The hardcoded default matters: a fresh deploy without .env must
    # start in governance-only mode.
    assert settings.__fields__["CONTENT_SAFETY_ENABLED"].default is False


async def test_signup_enabled_still_in_config(client):
    # Backwards compat: /auth/config existed before the feature flag.
    r = await client.get("/api/v1/auth/config")
    body = r.json()
    assert "signup_enabled" in body
