"""
Incident bundle (app/pvp/incident_bundle.py, docs/incident-bundle.md): one
file to investigate an agent incident, checked offline by
tools/provenza_audit.py incident, which shares no code with the server.

An agent is given a task, does one thing inside it, then asks - signing each
request itself - for a tool it has no right to until containment quarantines
it; a person releases it. The bundle shows all of it, says who vouches for
each line, and a change to any signed piece is caught.
"""

import copy
import json

import pytest
from sqlalchemy import select

from app.models.agent_action import AgentIncident
from tests.conftest import auth_headers
from tests.test_behavior_monitor import release
from tests.test_pvp_receipts import tool
from tests.test_task_mandates import _act, _agent, _check, _give

BUNDLE = "/api/v1/pvp/incidents/{}/bundle"


async def _story(client, token, db):
    agent = await _agent(client, token, tools=("db.read", "db.write"))
    r, _, _ = await _give(client, token, agent["id"], tools=["db.read"])
    await _act(client, token, agent, r.json()["id"])
    for _ in range(3):
        chk = await _check(client, token, agent, tool_name="files.delete", signed=True)
        assert chk["decision"] == "denied"
    inc = (await db.execute(select(AgentIncident).where(
        AgentIncident.agent_id == agent["id"], AgentIncident.incident_type == "rogue_agent_quarantined"))
    ).scalar_one()
    assert (await release(client, token, agent["id"])).status_code == 200
    return agent, inc.id


async def _bundle(client, token, incident_id, **params):
    r = await client.get(BUNDLE.format(incident_id), params=params, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _fails(doc, *args, **kw):
    with pytest.raises(tool.Fail) as e:
        tool.check_incident(doc, *args, **kw)
    return str(e.value)


@pytest.mark.asyncio
async def test_the_bundle_tells_the_story_and_who_vouches_for_it(client, admin_token, db_session):
    agent, incident_id = await _story(client, admin_token, db_session)
    doc = await _bundle(client, admin_token, incident_id)
    assert doc["type"] == "incident" and doc["incident"]["id"] == incident_id
    # never a check's token, never a call's input or output
    text = json.dumps(doc)
    assert '"token"' not in text and "select 1" not in text

    lines, events, gaps, keys = tool.check_incident(doc, agent_fp=doc["agent"]["key_fingerprint"])
    assert gaps == [], gaps
    summary = "\n".join(lines)
    assert "actions: 1 recorded in the window, and no other" in summary
    assert "its record is in the signed audit log" in summary
    assert "3 refused for reaching past its boundaries (files.delete)" in summary
    assert "the agent signed the request of 3 of them" in summary
    who = {}
    for _, w, t in events:
        who.setdefault(w, []).append(t)
    assert any("task #" in t for t in who["person's passkey"])
    assert any("released from quarantine" in t for t in who["person's passkey"])
    assert sum("files.delete denied [past its boundaries]" in t for t in who["agent's key"]) == 3
    assert any("agent quarantined - boundary_refusals" in t for t in who["signed log"])
    assert any(t.startswith("INCIDENT #") for t in who["signed log"])
    assert [e[0] for e in events] == sorted(e[0] for e in events)

    # the command line, as an investigator runs it
    path = f"/tmp/incident-{incident_id}.json"
    with open(path, "w") as f:
        json.dump(doc, f)
    assert tool.main(["incident", path, "--agent-fingerprint", doc["agent"]["key_fingerprint"],
                      "--require-full"]) == 0


@pytest.mark.asyncio
async def test_a_change_to_any_signed_piece_is_caught(client, admin_token, db_session):
    _, incident_id = await _story(client, admin_token, db_session)
    doc = await _bundle(client, admin_token, incident_id)

    d = copy.deepcopy(doc)
    signed = next(c for c in d["checks"] if c["requested"] and c["boundary"])
    signed["tool_name"] = "db.read"           # "it only read"
    assert "asks for another call" in _fails(d)

    d = copy.deepcopy(doc)
    rec = next(p for p in d["audit"] if p["record"]["payload"]["action"] == "quarantined")
    rec["record"]["payload"]["metadata"]["contained"]["count"] = 1
    assert "payload differs" in _fails(d)

    d = copy.deepcopy(doc)
    seal = next(s for s in d["completeness"]["seals"] if s["members"])
    seal["members"].pop()                     # an action dropped
    assert "actions given" in _fails(d)

    d = copy.deepcopy(doc)
    d["tasks"][0]["statement"]["task"] = "Delete the old files"
    assert "task" in _fails(d)

    d = copy.deepcopy(doc)
    d["release"]["statement"]["agent_id"] = 999999
    assert "release" in _fails(d)

    assert "not the agent key you gave" in _fails(doc, agent_fp="SHA256:someone-else")


@pytest.mark.asyncio
async def test_what_rests_on_the_servers_word_is_named(client, admin_token, db_session):
    _, incident_id = await _story(client, admin_token, db_session)
    doc = await _bundle(client, admin_token, incident_id)
    for c in doc["checks"]:
        c["requested"] = None                 # as for an agent that signs nothing
    doc["audit"] = [p for p in doc["audit"] if p["record"]["payload"]["action"] != "quarantined"]
    _, _, gaps, _ = tool.check_incident(doc)
    assert any("check(s) the agent did not sign rest on the server's word" in g for g in gaps)
    assert any("incident #" in g and "server's word" in g for g in gaps)
    path = f"/tmp/incident-gaps-{incident_id}.json"
    with open(path, "w") as f:
        json.dump(doc, f)
    assert tool.main(["incident", path]) == 0
    assert tool.main(["incident", path, "--require-full"]) == 1


@pytest.mark.asyncio
async def test_window_and_access(client, admin_token, approver_token, db_session):
    _, incident_id = await _story(client, admin_token, db_session)
    assert (await client.get(BUNDLE.format(incident_id), headers=auth_headers(approver_token))).status_code == 200
    assert (await client.get(BUNDLE.format(999999), headers=auth_headers(admin_token))).status_code == 404
    r = await client.get(BUNDLE.format(incident_id), params={"since": 2_000_000, "until": 1_000_000},
                         headers=auth_headers(admin_token))
    assert r.status_code == 422
    # a window with no recorded action: the bundle says it cannot show completeness
    doc = await _bundle(client, admin_token, incident_id, since=1_000_000, until=1_000_100)
    assert doc["completeness"] is None and doc["completeness_gap"]
    _, _, gaps, _ = tool.check_incident(doc)
    assert any("no proof that the actions are all of them" in g for g in gaps)
