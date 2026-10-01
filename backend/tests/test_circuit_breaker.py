"""
ASI08 - chain circuit breaker: a storm of denials / incidents / attempts in
one delegation chain halts the whole chain until an admin resumes it.
Also covers the two gaps found while building it: the policy engine now
honours the chain status, and a chain_id from another org is rejected.
"""

import secrets

import pytest

from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers
from tests.delegation_helpers import delegation_body

BRK = "/api/v1/agent-breaker"
CHECK = "/api/v1/agents/actions/check"


async def _agent(client, token, caps=("read",)):
    r = await client.post(
        "/api/v1/agents/register",
        json={"name": "brk-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": list(caps),
              "allowed_tools": ["db.read"], "allowed_models": [], "max_delegation_depth": 3},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _chain(client, token):
    """root -> child; returns (root, child, chain_id)."""
    root = await _agent(client, token, caps=("read", "write"))
    child = await _agent(client, token)
    r = await client.post(f"/api/v1/agents/{root['id']}/delegate",
                          json=delegation_body(root, child["id"], "task", ["read"]),
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return root, child, r.json()["chain_id"]


async def _settings(client, token, **over):
    body = {"enabled": True, "window_seconds": 300, "max_attempts": 1000, "max_denials": 1000, "max_incidents": 1000}
    body.update(over)
    r = await client.put(BRK + "/settings", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _check(client, token, agent, chain_id, tool="db.read"):
    r = await client.post(CHECK, json={"agent_id": agent["id"], "chain_id": chain_id, "tool_name": tool, "input": {}},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _chain_status(client, token, chain_id):
    r = await client.get(f"/api/v1/agents/delegation-chains/{chain_id}", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()["status"]


class TestTripping:
    @pytest.mark.asyncio
    async def test_denial_storm_halts_the_chain(self, client, admin_token):
        await _settings(client, admin_token, max_denials=3)
        _, child, chain_id = await _chain(client, admin_token)
        for _ in range(3):
            assert (await _check(client, admin_token, child, chain_id, tool="stripe.charge"))["decision"] == "denied"
        # the 4th attempt sees 3 denials in the window -> breaker trips, even a legit tool is refused
        halted = await _check(client, admin_token, child, chain_id, tool="db.read")
        assert halted["decision"] == "denied"
        assert "circuit breaker" in halted["reason"]
        assert await _chain_status(client, admin_token, chain_id) == "tripped"

        inc = await client.get("/api/v1/agents/incidents/", params={"incident_type": "cascade_breaker_tripped"},
                               headers=auth_headers(admin_token))
        items = inc.json()["items"] if isinstance(inc.json(), dict) else inc.json()
        assert any(i["chain_id"] == chain_id for i in items)

        listed = await client.get(BRK + "/chains", headers=auth_headers(admin_token))
        row = next(c for c in listed.json() if c["id"] == chain_id)
        assert row["breaker_details"]["exceeded"] == ["denials"]
        assert row["breaker_details"]["counts"]["denials"] == 3

    @pytest.mark.asyncio
    async def test_runaway_loop_trips_on_attempts(self, client, admin_token):
        await _settings(client, admin_token, max_attempts=10)
        _, child, chain_id = await _chain(client, admin_token)
        for _ in range(10):
            assert (await _check(client, admin_token, child, chain_id))["decision"] == "allowed"
        assert (await _check(client, admin_token, child, chain_id))["decision"] == "denied"
        assert await _chain_status(client, admin_token, chain_id) == "tripped"

    @pytest.mark.asyncio
    async def test_tripped_chain_accepts_no_new_delegations(self, client, admin_token):
        await _settings(client, admin_token, max_denials=2)
        root, child, chain_id = await _chain(client, admin_token)
        for _ in range(3):
            await _check(client, admin_token, child, chain_id, tool="stripe.charge")
        third = await _agent(client, admin_token)
        r = await client.post(f"/api/v1/agents/{child['id']}/delegate",
                              json=delegation_body(child, third["id"], "sub", ["read"], chain_id=chain_id),
                              headers=auth_headers(admin_token))
        assert r.status_code == 409, r.text

    @pytest.mark.asyncio
    async def test_below_threshold_nothing_happens(self, client, admin_token):
        await _settings(client, admin_token, max_denials=5)
        _, child, chain_id = await _chain(client, admin_token)
        for _ in range(4):
            await _check(client, admin_token, child, chain_id, tool="stripe.charge")
        assert (await _check(client, admin_token, child, chain_id))["decision"] == "allowed"
        assert await _chain_status(client, admin_token, chain_id) == "active"


class TestOperatorActions:
    @pytest.mark.asyncio
    async def test_resume_counts_from_the_reset(self, client, admin_token):
        await _settings(client, admin_token, max_denials=2)
        _, child, chain_id = await _chain(client, admin_token)
        for _ in range(3):
            await _check(client, admin_token, child, chain_id, tool="stripe.charge")
        assert await _chain_status(client, admin_token, chain_id) == "tripped"

        r = await client.post(f"{BRK}/chains/{chain_id}/resume", headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        # old denials are before the reset and do not re-trip the chain
        assert (await _check(client, admin_token, child, chain_id))["decision"] == "allowed"
        assert await _chain_status(client, admin_token, chain_id) == "active"

    @pytest.mark.asyncio
    async def test_resume_only_tripped_and_terminate(self, client, admin_token):
        _, child, chain_id = await _chain(client, admin_token)
        assert (await client.post(f"{BRK}/chains/{chain_id}/resume", headers=auth_headers(admin_token))).status_code == 409
        r = await client.post(f"{BRK}/chains/{chain_id}/terminate", headers=auth_headers(admin_token))
        assert r.status_code == 200
        assert (await _check(client, admin_token, child, chain_id))["decision"] == "denied"

    @pytest.mark.asyncio
    async def test_kill_switch_also_ends_tripped_chains(self, client, admin_token):
        await _settings(client, admin_token, max_denials=2)
        root, child, chain_id = await _chain(client, admin_token)
        for _ in range(3):
            await _check(client, admin_token, child, chain_id, tool="stripe.charge")
        assert await _chain_status(client, admin_token, chain_id) == "tripped"
        k = await client.post(f"/api/v1/agents/{root['id']}/kill", json={"reason": "test", "cascade": True},
                              headers=auth_headers(admin_token))
        assert k.status_code == 200, k.text
        assert await _chain_status(client, admin_token, chain_id) == "terminated"


class TestSettings:
    @pytest.mark.asyncio
    async def test_defaults_are_returned(self, client, admin_token):
        r = await client.get(BRK + "/settings", headers=auth_headers(admin_token))
        assert r.status_code == 200
        body = r.json()
        assert body["org"]["enabled"] is True
        assert body["bounds"]["max_denials"][0] >= 2

    @pytest.mark.asyncio
    async def test_bounds_are_enforced(self, client, admin_token):
        base = {"enabled": True, "window_seconds": 300, "max_attempts": 100, "max_denials": 10, "max_incidents": 3}
        for field, bad in (("window_seconds", 0), ("max_denials", 1), ("max_attempts", 5), ("max_incidents", 0)):
            r = await client.put(BRK + "/settings", json={**base, field: bad}, headers=auth_headers(admin_token))
            assert r.status_code == 422, (field, r.text)

    @pytest.mark.asyncio
    async def test_disabling_requires_confirmation(self, client, admin_token):
        base = {"enabled": False, "window_seconds": 300, "max_attempts": 100, "max_denials": 2, "max_incidents": 3}
        assert (await client.put(BRK + "/settings", json=base, headers=auth_headers(admin_token))).status_code == 400
        ok = await client.put(BRK + "/settings", json={**base, "confirm_disable": True}, headers=auth_headers(admin_token))
        assert ok.status_code == 200
        _, child, chain_id = await _chain(client, admin_token)
        for _ in range(4):
            await _check(client, admin_token, child, chain_id, tool="stripe.charge")
        assert await _chain_status(client, admin_token, chain_id) == "active"

    @pytest.mark.asyncio
    async def test_root_agent_override_wins(self, client, admin_token):
        await _settings(client, admin_token, max_denials=1000)
        root, child, chain_id = await _chain(client, admin_token)
        r = await client.put(f"{BRK}/settings/agents/{root['id']}",
                             json={"enabled": True, "window_seconds": 300, "max_attempts": 1000,
                                   "max_denials": 2, "max_incidents": 1000},
                             headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        for _ in range(3):
            await _check(client, admin_token, child, chain_id, tool="stripe.charge")
        assert await _chain_status(client, admin_token, chain_id) == "tripped"
        listed = await client.get(BRK + "/chains", headers=auth_headers(admin_token))
        row = next(c for c in listed.json() if c["id"] == chain_id)
        assert row["breaker_details"]["settings_source"] == "agent"

        gone = await client.delete(f"{BRK}/settings/agents/{root['id']}", headers=auth_headers(admin_token))
        assert gone.status_code == 200

    @pytest.mark.asyncio
    async def test_only_admin_changes_settings(self, client, approver_token):
        body = {"enabled": True, "window_seconds": 300, "max_attempts": 100, "max_denials": 10, "max_incidents": 3}
        assert (await client.put(BRK + "/settings", json=body, headers=auth_headers(approver_token))).status_code == 403
        assert (await client.get(BRK + "/settings", headers=auth_headers(approver_token))).status_code == 200


class TestGapsFound:
    @pytest.mark.asyncio
    async def test_actions_in_a_terminated_chain_are_denied(self, client, admin_token):
        _, child, chain_id = await _chain(client, admin_token)
        await client.post(f"{BRK}/chains/{chain_id}/terminate", headers=auth_headers(admin_token))
        r = await _check(client, admin_token, child, chain_id)
        assert r["decision"] == "denied" and "terminated" in r["reason"]

    @pytest.mark.asyncio
    async def test_chain_of_another_org_is_rejected(self, client, admin_token, db_session):
        _, _, chain_id = await _chain(client, admin_token)
        await _create_org_with_admin_and_approver(
            db_session, org_slug="brk-other",
            admin_email="admin@brk-other.example.com", approver_email="approver@brk-other.example.com",
        )
        await db_session.commit()
        other = await _login(client, "brk-other", "admin@brk-other.example.com", "TestPass123!")
        foreign_agent = await _agent(client, other)
        r = await client.post(CHECK, json={"agent_id": foreign_agent["id"], "chain_id": chain_id,
                                           "tool_name": "db.read", "input": {}},
                              headers=auth_headers(other))
        assert r.status_code == 404, r.text
        resume = await client.post(f"{BRK}/chains/{chain_id}/resume", headers=auth_headers(other))
        assert resume.status_code == 404
