"""
Automatic containment (app/services/containment.py): an agent refused again
and again for reaching past its boundaries is quarantined without waiting
for a person, in any mode of the behaviour monitor; a tripwire tool stops it
at once; the calls it left waiting for a person are closed; only a person's
signed release lets it act again, and that release names the quarantine it ends.
"""

import secrets

import pytest
from sqlalchemy import select

from app.models.agent_action import AgentAction, AgentIncident
from app.models.approval import AgentActionApproval
from tests import signer
from tests.conftest import auth_headers
from tests.delegation_helpers import delegation_body
from tests.test_behavior_monitor import A, B, _agent, _check, _overview, _settings, _status, release


def _code(r):
    d = r.json().get("detail")
    return d["code"] if isinstance(d, dict) else d


async def _probe(client, token, agent, n, tool="files.delete"):
    """n calls to a tool the agent has no right to."""
    out = []
    for _ in range(n):
        out.append(await _check(client, token, agent, tool=tool))
    return out


@pytest.mark.asyncio
async def test_an_agent_that_keeps_probing_is_quarantined(client, admin_token, db_session):
    root = await _agent(client, admin_token, caps=("read", "write"))
    child = await _agent(client, admin_token)
    d = await client.post(f"{A}/{root['id']}/delegate", json=delegation_body(root, child["id"], "task", ["read"]),
                          headers=auth_headers(admin_token))
    chain_id = d.json()["chain_id"]
    # allowed calls do not count, and two refusals are not yet a pattern
    assert (await _check(client, admin_token, root))["decision"] == "allowed"
    await _probe(client, admin_token, root, 2)
    assert await _status(client, admin_token, root["id"]) == "active"
    # the third is: stopped at once, in the default "monitor" mode
    third = (await _probe(client, admin_token, root, 1))[0]
    assert third["decision"] == "denied"
    assert await _status(client, admin_token, root["id"]) == "quarantined"
    assert (await _check(client, admin_token, root))["decision"] == "denied"
    chain = await client.get(f"{A}/delegation-chains/{chain_id}", headers=auth_headers(admin_token))
    assert chain.json()["status"] == "tripped"

    inc = (await db_session.execute(select(AgentIncident).where(
        AgentIncident.agent_id == root["id"], AgentIncident.incident_type == "rogue_agent_quarantined"))
    ).scalars().all()
    assert len(inc) == 1 and inc[0].severity == "critical"
    why = inc[0].details["contained"]
    assert why["reason"] == "boundary_refusals" and why["count"] == 3
    assert {r["tool"] for r in why["refusals"]} == {"files.delete"}
    row = next(x for x in (await _overview(client, admin_token))["agents"] if x["agent_id"] == root["id"])
    assert row["quarantine"]["reason"] == "boundary_refusals" and row["quarantine"]["count"] == 3


@pytest.mark.asyncio
async def test_refusals_that_are_not_the_agents_doing_do_not_count(client, admin_token):
    a = await _agent(client, admin_token)
    r = await client.post(f"{A}/{a['id']}/kill", json={"reason": "maintenance", "cascade": False},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    # refused because it is stopped - five times - is not probing
    for _ in range(5):
        assert (await _check(client, admin_token, a, tool="files.delete"))["decision"] == "denied"
    assert await _status(client, admin_token, a["id"]) == "suspended"


@pytest.mark.asyncio
async def test_containment_can_be_turned_off_and_tuned(client, admin_token):
    await _settings(client, admin_token, containment_enabled=False)
    a = await _agent(client, admin_token)
    await _probe(client, admin_token, a, 5)
    assert await _status(client, admin_token, a["id"]) == "active"

    await _settings(client, admin_token, containment_enabled=True, containment_max_boundary=5,
                    containment_window_seconds=60)
    # a client that knows only the monitor's settings leaves these as they are
    await _settings(client, admin_token, mode="monitor")
    s = (await _overview(client, admin_token))["settings"]
    assert (s["containment_enabled"], s["containment_max_boundary"], s["containment_window_seconds"]) == \
        (True, 5, 60)
    b = await _agent(client, admin_token)
    await _probe(client, admin_token, b, 4)
    assert await _status(client, admin_token, b["id"]) == "active"
    await _probe(client, admin_token, b, 1)
    assert await _status(client, admin_token, b["id"]) == "quarantined"

    for bad in ({"containment_max_boundary": 0}, {"containment_window_seconds": 5},
                {"tripwire_tools": ["x" * 101]}):
        body = {"mode": "monitor", "threshold": 60, "min_samples": 50, "baseline_days": 14, **bad}
        r = await client.put(B + "/settings", json=body, headers=auth_headers(admin_token))
        assert r.status_code == 422, (bad, r.text)


@pytest.mark.asyncio
async def test_a_tripwire_stops_the_agent_on_the_first_call(client, admin_token):
    await _settings(client, admin_token, tripwire_tools=["secrets.*"])
    # even a tool the agent may use: no agent has a reason to call a decoy
    a = await _agent(client, admin_token, tools=("db.read", "secrets.dump"))
    first = await _check(client, admin_token, a, tool="secrets.dump")
    assert first["decision"] == "denied"
    assert await _status(client, admin_token, a["id"]) == "quarantined"
    row = next(x for x in (await _overview(client, admin_token))["agents"] if x["agent_id"] == a["id"])
    assert row["quarantine"]["reason"] == "tripwire" and row["quarantine"]["tool"] == "secrets.dump"


@pytest.mark.asyncio
async def test_calls_waiting_for_a_person_are_closed(client, admin_token, db_session):
    a = await _agent(client, admin_token)
    org_id = (await client.get(f"{A}/{a['id']}", headers=auth_headers(admin_token))).json()["org_id"]
    waiting = AgentAction(org_id=org_id, agent_id=a["id"], action_type="tool_call", tool_name="db.export",
                          input_data={"q": 1}, policy_check_result="pending_approval", reason="needs a person")
    db_session.add(waiting)
    await db_session.commit()
    await _probe(client, admin_token, a, 3)
    await db_session.refresh(waiting)
    assert waiting.policy_check_result == "denied" and "quarantined" in waiting.reason
    closed = (await db_session.execute(select(AgentActionApproval).where(
        AgentActionApproval.action_id == waiting.id))).scalar_one()
    assert closed.decision == "expired"
    # and nothing is approved for a quarantined agent
    r = await client.get(f"{A}/actions/{waiting.id}/review", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["reviewer"]["can_decide"] is False


@pytest.mark.asyncio
async def test_only_a_signed_release_lets_it_act_again(client, admin_token):
    a = await _agent(client, admin_token)
    await _probe(client, admin_token, a, 3)
    assert await _status(client, admin_token, a["id"]) == "quarantined"
    # not through the agent's edit form, not even by way of "suspended"
    for st in ("active", "suspended"):
        r = await client.put(f"{A}/{a['id']}", json={"status": st}, headers=auth_headers(admin_token))
        assert r.status_code == 409 and _code(r) == "agent.quarantined_release_signed", r.text

    # a statement signed for this quarantine ...
    s = await signer.signer(client, admin_token)
    base = f"{B}/agents/{a['id']}/release"
    old = (await client.post(base + "/statement", headers=auth_headers(admin_token))).json()["statement"]
    assert old["type"] == "provenza.agent.release" and old["agent_id"] == a["id"]
    r = await release(client, admin_token, a["id"])
    assert r.status_code == 200, r.text
    assert r.json()["incident_id"] == old["incident_id"]
    # counting restarts at the release: one more refusal is not three
    await _probe(client, admin_token, a, 1)
    assert await _status(client, admin_token, a["id"]) == "active"
    await _probe(client, admin_token, a, 2)
    assert await _status(client, admin_token, a["id"]) == "quarantined"
    # ... does not release the next one
    r = await client.post(base, json={"statement": old, "signature": s.sign(old)}, headers=auth_headers(admin_token))
    assert r.status_code == 422 and _code(r) == "session.statement_mismatch", r.text
    assert await _status(client, admin_token, a["id"]) == "quarantined"


@pytest.mark.asyncio
async def test_only_an_admin_releases(client, admin_token, approver_token):
    a = await _agent(client, admin_token)
    await _probe(client, admin_token, a, 3)
    r = await client.post(f"{B}/agents/{a['id']}/release/statement", headers=auth_headers(approver_token))
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_two_agents_are_counted_apart(client, admin_token):
    a = await _agent(client, admin_token)
    b = await _agent(client, admin_token)
    await _probe(client, admin_token, a, 2)
    await _probe(client, admin_token, b, 2, tool="net.scan." + secrets.token_hex(2))
    assert await _status(client, admin_token, a["id"]) == "active"
    assert await _status(client, admin_token, b["id"]) == "active"
