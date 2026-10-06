"""
Tests for governed chat (POST /providers/{id}/chat): the governance layer
around a provider call. The real provider call is mocked so the test never
touches the network — we assert the GOVERNANCE behavior: blocked prompts
never reach the provider, clean prompts do and are logged, and an active
policy's blocked terms (scope "policy" on the Blocked terms page) are enforced.
"""

import pytest
from unittest.mock import AsyncMock, patch

from tests.conftest import auth_headers
from app.models.ai_policy import AIPolicy, AIPolicyVersion

pytestmark = pytest.mark.asyncio


async def _make_provider(client, token):
    resp = await client.post(
        "/api/v1/providers/",
        json={"name": "MockProv", "type": "openai", "api_key": "sk-test"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 200
    return resp.json()["id"]


async def _add_active_blocked_policy(db_session, org_id, term, approver_id):
    """An active policy with a policy-scoped blocked term (Blocked terms page)."""
    from app.core.term_match import term_key
    from app.models.blocked_term import BlockedTerm

    policy = AIPolicy(org_id=org_id, name="blocklist", status="active")
    db_session.add(policy)
    await db_session.flush()
    db_session.add(AIPolicyVersion(policy_id=policy.id, version=1, rules_json={}, approved_by=approver_id))
    db_session.add(BlockedTerm(org_id=org_id, term=term, key=term_key(term), scope="policy", policy_id=policy.id))
    await db_session.flush()


class TestCleanPrompt:
    async def test_clean_prompt_reaches_provider(self, client, org_and_users, admin_token):
        pid = await _make_provider(client, admin_token)
        with patch("app.api.providers.provider_adapters.call_provider",
                   new=AsyncMock(return_value=("Hello from the model", {}))) as mock_call:
            resp = await client.post(
                f"/api/v1/providers/{pid}/chat",
                json={"message": "What is 2+2?"},
                headers=auth_headers(admin_token),
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["blocked"] is False
        assert body["answer"] == "Hello from the model"
        mock_call.assert_awaited_once()  # provider WAS called


class TestBlockedByPolicy:
    async def test_blocked_term_never_reaches_provider(self, client, db_session, org_and_users, admin_token):
        pid = await _make_provider(client, admin_token)
        await _add_active_blocked_policy(db_session, org_and_users["org"].id, "forbidden", org_and_users["admin"].id)
        with patch("app.api.providers.provider_adapters.call_provider",
                   new=AsyncMock(return_value=("should not happen", {}))) as mock_call:
            resp = await client.post(
                f"/api/v1/providers/{pid}/chat",
                json={"message": "tell me the forbidden thing"},
                headers=auth_headers(admin_token),
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["blocked"] is True
        # the governance guarantee: provider was NEVER called
        mock_call.assert_not_awaited()


class TestProviderNotFound:
    async def test_unknown_provider_404(self, client, org_and_users, admin_token):
        resp = await client.post(
            "/api/v1/providers/999999/chat",
            json={"message": "hi"},
            headers=auth_headers(admin_token),
        )
        assert resp.status_code == 404


class TestModelOverride:
    async def test_chosen_model_is_passed_to_provider(self, client, org_and_users, admin_token):
        pid = await _make_provider(client, admin_token)
        with patch("app.api.providers.provider_adapters.call_provider",
                   new=AsyncMock(return_value=("ok", {}))) as mock_call:
            await client.post(
                f"/api/v1/providers/{pid}/chat",
                json={"message": "hi", "model": "gpt-4o-mini"},
                headers=auth_headers(admin_token),
            )
        # call_provider(type, api_key, base_url, model, prompt) — model is 4th arg
        args = mock_call.call_args.args
        assert "gpt-4o-mini" in args
