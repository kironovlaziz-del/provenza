"""
ASI10 - behaviour monitor: baseline maturity, anomaly signals, monitor vs
enforce, quarantine (and the chains it roots), release, settings.
History is written back-dated straight into action checks so the baseline
can be exercised without waiting for real days to pass.
"""

import secrets
from datetime import datetime, timedelta, timezone

import pytest

from app.models.agent import Agent
from app.models.agent_action import ActionCheck
from tests.conftest import auth_headers
from tests.delegation_helpers import delegation_body

A = "/api/v1/agents"
B = "/api/v1/agent-behavior"


async def _agent(client, token, tools=("db.read", "db.export"), caps=("read",)):
    r = await client.post(
        f"{A}/register",
        json={"name": "bh-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": list(caps),
              "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 2},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _add_checks(db, agent_id, times, tool="db.read", denied=False, chain_id=None):
    org_id = (await db.get(Agent, agent_id)).org_id
    for t in times:
        db.add(ActionCheck(
            token=secrets.token_hex(16), org_id=org_id, agent_id=agent_id, chain_id=chain_id,
            action_type="tool_call", tool_name=tool, input_sha256="0" * 64, action_capabilities=[],
            decision="denied" if denied else "allowed", reason="history", expires_at=t, created_at=t,
        ))
    await db.commit()


async def _mature_history(db, agent_id, n=120, days=5):
    """n allowed db.read checks, evenly over `days`, ending 2h ago (covers every hour of day)."""
    end = datetime.now(timezone.utc) - timedelta(hours=2)
    step = timedelta(minutes=days * 24 * 60 / n)
    await _add_checks(db, agent_id, [end - i * step for i in range(n)])


async def _burst(db, agent_id, n, tool="db.read", denied=False, minutes_ago=1):
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    await _add_checks(db, agent_id, [t - timedelta(seconds=i) for i in range(n)], tool=tool, denied=denied)


async def _settings(client, token, **over):
    body = {"mode": "monitor", "threshold": 60, "min_samples": 50, "baseline_days": 14}
    body.update(over)
    r = await client.put(B + "/settings", json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text


async def _check(client, token, agent, tool="db.read", chain_id=None):
    r = await client.post(f"{A}/actions/check",
                          json={"agent_id": agent["id"], "chain_id": chain_id, "tool_name": tool, "input": {}},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _overview(client, token):
    r = await client.get(B + "/", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _status(client, token, agent_id):
    return (await client.get(f"{A}/{agent_id}", headers=auth_headers(token))).json()["status"]


class TestMonitorMode:
    @pytest.mark.asyncio
    async def test_new_tool_on_mature_agent_is_flagged_not_blocked(self, client, admin_token, db_session):
        a = await _agent(client, admin_token)
        await _mature_history(db_session, a["id"])
        assert (await _check(client, admin_token, a, tool="db.export"))["decision"] == "allowed"
        ov = await _overview(client, admin_token)
        mine = [x for x in ov["anomalies"] if x["agent_id"] == a["id"]]
        assert mine and "new_tool" in mine[0]["signals"] and mine[0]["outcome"] == "flagged"
        row = next(x for x in ov["agents"] if x["agent_id"] == a["id"])
        assert row["baseline"]["mature"] is True and "db.read" in row["baseline"]["top_tools"]
        assert await _status(client, admin_token, a["id"]) == "active"

    @pytest.mark.asyncio
    async def test_immature_baseline_does_not_flag_new_tools(self, client, admin_token, db_session):
        a = await _agent(client, admin_token)
        await _add_checks(db_session, a["id"], [datetime.now(timezone.utc) - timedelta(days=1, minutes=i) for i in range(10)])
        await _check(client, admin_token, a, tool="db.export")
        ov = await _overview(client, admin_token)
        assert not [x for x in ov["anomalies"] if x["agent_id"] == a["id"]]

    @pytest.mark.asyncio
    async def test_repeated_identical_flags_are_deduplicated(self, client, admin_token, db_session):
        a = await _agent(client, admin_token)
        await _mature_history(db_session, a["id"])
        await _check(client, admin_token, a, tool="db.export")
        await _check(client, admin_token, a, tool="db.export")
        ov = await _overview(client, admin_token)
        assert len([x for x in ov["anomalies"] if x["agent_id"] == a["id"]]) == 1

    @pytest.mark.asyncio
    async def test_off_mode_does_nothing(self, client, admin_token, db_session):
        await _settings(client, admin_token, mode="off")
        a = await _agent(client, admin_token)
        await _mature_history(db_session, a["id"])
        await _check(client, admin_token, a, tool="db.export")
        ov = await _overview(client, admin_token)
        assert not [x for x in ov["anomalies"] if x["agent_id"] == a["id"]]


class TestEnforceMode:
    @pytest.mark.asyncio
    async def test_burst_plus_new_tool_quarantines(self, client, admin_token, db_session):
        await _settings(client, admin_token, mode="enforce", threshold=60)
        a = await _agent(client, admin_token)
        await _mature_history(db_session, a["id"])
        await _burst(db_session, a["id"], 25)
        r = await _check(client, admin_token, a, tool="db.export")
        assert r["decision"] == "denied" and "quarantined" in r["reason"]
        assert await _status(client, admin_token, a["id"]) == "quarantined"
        inc = await client.get(f"{A}/incidents/", params={"incident_type": "rogue_agent_quarantined"},
                               headers=auth_headers(admin_token))
        items = inc.json()["items"] if isinstance(inc.json(), dict) else inc.json()
        hit = next(i for i in items if i["agent_id"] == a["id"])
        assert set(hit["details"]["signals"]) >= {"rate_spike", "new_tool"}

    @pytest.mark.asyncio
    async def test_denial_storm_quarantines_even_a_new_agent(self, client, admin_token, db_session):
        await _settings(client, admin_token, mode="enforce", threshold=40)
        a = await _agent(client, admin_token)
        await _burst(db_session, a["id"], 12, tool="stripe.charge", denied=True, minutes_ago=10)
        assert (await _check(client, admin_token, a))["decision"] == "denied"
        assert await _status(client, admin_token, a["id"]) == "quarantined"

    @pytest.mark.asyncio
    async def test_below_threshold_only_flags(self, client, admin_token, db_session):
        await _settings(client, admin_token, mode="enforce", threshold=60)
        a = await _agent(client, admin_token)
        await _mature_history(db_session, a["id"])
        assert (await _check(client, admin_token, a, tool="db.export"))["decision"] == "allowed"  # new_tool = 30
        assert await _status(client, admin_token, a["id"]) == "active"

    @pytest.mark.asyncio
    async def test_quarantine_trips_chains_the_agent_roots(self, client, admin_token, db_session):
        await _settings(client, admin_token, mode="enforce", threshold=40)
        root = await _agent(client, admin_token, caps=("read", "write"))
        child = await _agent(client, admin_token)
        d = await client.post(f"{A}/{root['id']}/delegate",
                              json=delegation_body(root, child["id"], "task", ["read"]),
                              headers=auth_headers(admin_token))
        chain_id = d.json()["chain_id"]
        await _burst(db_session, root["id"], 12, tool="stripe.charge", denied=True, minutes_ago=10)
        await _check(client, admin_token, root)
        chain = await client.get(f"{A}/delegation-chains/{chain_id}", headers=auth_headers(admin_token))
        assert chain.json()["status"] == "tripped"
        assert (await _check(client, admin_token, child, chain_id=chain_id))["decision"] == "denied"


class TestRelease:
    @pytest.mark.asyncio
    async def test_release_restores_and_restarts_the_windows(self, client, admin_token, db_session):
        await _settings(client, admin_token, mode="enforce", threshold=40)
        a = await _agent(client, admin_token)
        await _burst(db_session, a["id"], 12, tool="stripe.charge", denied=True, minutes_ago=10)
        await _check(client, admin_token, a)
        assert await _status(client, admin_token, a["id"]) == "quarantined"
        r = await client.post(f"{B}/agents/{a['id']}/release", headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        # the old denials are before the release and do not quarantine it again
        assert (await _check(client, admin_token, a))["decision"] == "allowed"
        assert await _status(client, admin_token, a["id"]) == "active"
        again = await client.post(f"{B}/agents/{a['id']}/release", headers=auth_headers(admin_token))
        assert again.status_code == 409


class TestSettings:
    @pytest.mark.asyncio
    async def test_bounds_and_roles(self, client, admin_token, approver_token):
        base = {"mode": "enforce", "threshold": 60, "min_samples": 50, "baseline_days": 14}
        for field, bad in (("threshold", 5), ("min_samples", 1), ("baseline_days", 1), ("mode", "yolo")):
            r = await client.put(B + "/settings", json={**base, field: bad}, headers=auth_headers(admin_token))
            assert r.status_code == 422, (field, r.text)
        assert (await client.put(B + "/settings", json=base, headers=auth_headers(approver_token))).status_code == 403
        assert (await client.get(B + "/", headers=auth_headers(approver_token))).status_code == 200

    @pytest.mark.asyncio
    async def test_refresh_baseline(self, client, admin_token, db_session):
        a = await _agent(client, admin_token)
        await _mature_history(db_session, a["id"])
        r = await client.post(f"{B}/agents/{a['id']}/baseline", headers=auth_headers(admin_token))
        assert r.status_code == 200 and r.json()["mature"] is True and r.json()["samples"] == 120
