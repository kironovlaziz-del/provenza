# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
A task a person gives an agent, signed (app/services/task_mandates.py,
docs/proof-of-authority.md):

  - the person's session key signs the task, certified by their passkey;
    a statement is used once, and a new task ends the one before;
  - a call that names the task is checked against it - the agent (or the
    root of its delegation chain), the tools, the time, whether it was
    ended - and its evidence names it;
  - with require_task_mandate on, a call that names none is refused;
  - Proof of Authority carries the signed task, and the standalone verifier
    checks it and catches a change to it.
"""

import base64
import copy
import json
import secrets
import time

import pytest
from sqlalchemy import select

from app.core.agent_signing import content_hash, sign_payload, sign_payload_pq
from app.models.agent_action import AgentAction
from app.pvp import signed_policy
from tests import signer
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body, delegation_body
from tests.test_mcp_gateway import _call, _ready, fake  # noqa: F401  (fake: the fixture)
from tests.test_policy_release import _release
from tests.test_pvp_receipts import _agent, tool

A = "/api/v1/agents"
CHECK = "/api/v1/agents/actions/check"
RECORD = "/api/v1/agents/actions/record"


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


async def _statement(client, token, agent_id, task="Reconcile the October invoices", tools=None, hours=8):
    return await client.post(f"{A}/{agent_id}/mandates/statement",
                             json={"task": task, "tools": tools, "valid_hours": hours}, headers=auth_headers(token))


async def _give(client, token, agent_id, task="Reconcile the October invoices", tools=None, hours=8):
    """Give a task as the web interface does: the statement, signed with the session key."""
    s = await signer.signer(client, token)
    r = await _statement(client, token, agent_id, task, tools, hours)
    assert r.status_code == 200, r.text
    st = r.json()["statement"]
    r = await client.post(f"{A}/{agent_id}/mandates", json={"task": task, "tools": tools, "valid_hours": hours,
                                                             "statement": st, "signature": s.sign(st)},
                          headers=auth_headers(token))
    return r, st, s.sign(st)


async def _end(client, token, agent_id, mandate_id):
    """End a task as the web interface does: the end statement, signed with the session key."""
    s = await signer.signer(client, token)
    base = f"{A}/{agent_id}/mandates/{mandate_id}/end"
    r = await client.post(base + "/statement", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    st = r.json()["statement"]
    return await client.post(base, json={"statement": st, "signature": s.sign(st)}, headers=auth_headers(token))


async def _check(client, token, agent, mandate_id=None, tool_name="db.read", chain_id=None, inp=None,
                 signed=None):
    """A check; one that names a task is signed by the agent, as the SDKs sign it."""
    from app.pvp.model import PVPActionRequest

    body = {"agent_id": agent["id"], "tool_name": tool_name, "input": inp or {"q": 1}, "chain_id": chain_id,
            "mandate_id": mandate_id}
    if mandate_id is not None if signed is None else signed:
        body.update(nonce=secrets.token_hex(16), issued_at=int(time.time()))
        body["signature"] = sign_payload(PVPActionRequest(**body).signed_payload(), agent["private_key"])
    r = await client.post(CHECK, json=body, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _act(client, token, agent, mandate_id, tool_name="db.read", chain_id=None):
    inp = {"q": secrets.token_hex(4)}
    chk = await _check(client, token, agent, mandate_id, tool_name, chain_id, inp)
    assert chk["decision"] == "allowed", chk
    r = await client.post(RECORD, json=action_record_body(agent, chk["check_id"], tool_name, inp, output={"rows": 1},
                                                          chain_id=chain_id), headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def _authority(client, token, action_id):
    r = await client.get(f"/api/v1/pvp/authority/{action_id}", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _fails(doc, *args, **kw):
    with pytest.raises(tool.Fail) as e:
        tool.check_authority(doc, *args, **kw)
    return str(e.value)


# ---------------------------------------------------------------------------
# Giving and ending a task
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_give_read_and_end(client, admin_token):
    agent = await _agent(client, admin_token, tools=("db.read", "db.write"))
    r, st, sig = await _give(client, admin_token, agent["id"], tools=["db.read"])
    assert r.status_code == 200, r.text
    first = r.json()
    assert first["status"] == "active" and first["tools"] == ["db.read"] and first["task"].startswith("Reconcile")
    assert st["type"] == "provenza.mandate" and st["agent_id"] == agent["id"] and st["valid_hours"] == 8

    # the agent reads it with its own key - and only its own
    r = await client.get(f"{A}/{agent['id']}/mandates/current", headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200, r.text
    assert r.json()["mandate"]["id"] == first["id"]
    other = await _agent(client, admin_token)
    r = await client.get(f"{A}/{other['id']}/mandates/current", headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 403

    # the same signed statement again: used once
    r = await client.post(f"{A}/{agent['id']}/mandates", json={"task": st["task"], "tools": ["db.read"],
                                                                 "valid_hours": 8, "statement": st, "signature": sig},
                          headers=auth_headers(admin_token))
    assert r.status_code == 409, r.text
    # a statement for another task than the one sent
    r = await client.post(f"{A}/{agent['id']}/mandates", json={"task": "Delete everything", "tools": ["db.read"],
                                                                 "valid_hours": 8, "statement": st, "signature": sig},
                          headers=auth_headers(admin_token))
    assert r.status_code == 422, r.text

    # a new task ends the one before
    r, _, _ = await _give(client, admin_token, agent["id"], task="Close the quarter")
    second = r.json()
    listed = (await client.get(f"{A}/{agent['id']}/mandates", headers=auth_headers(admin_token))).json()
    assert listed["current"]["id"] == second["id"]
    assert {m["id"]: m["status"] for m in listed["history"]} == {second["id"]: "active", first["id"]: "ended"}

    # ending is signed: without the signed statement nothing ends
    r = await client.post(f"{A}/{agent['id']}/mandates/{second['id']}/end", headers=auth_headers(admin_token))
    assert r.status_code == 422
    r = await client.post(f"{A}/{agent['id']}/mandates/{second['id']}/end",
                          json={"statement": st, "signature": sig}, headers=auth_headers(admin_token))
    assert r.status_code == 422                      # a statement of something else
    listed = (await client.get(f"{A}/{agent['id']}/mandates", headers=auth_headers(admin_token))).json()
    assert listed["current"]["id"] == second["id"]
    r = await _end(client, admin_token, agent["id"], second["id"])
    assert r.status_code == 200 and r.json()["status"] == "ended"
    r = await client.get(f"{A}/{agent['id']}/mandates/current", headers={"X-Agent-Key": agent["api_key"]})
    assert r.json()["mandate"] is None


@pytest.mark.asyncio
async def test_bad_tasks_are_refused(client, admin_token):
    agent = await _agent(client, admin_token)
    await signer.signer(client, admin_token)
    r = await _statement(client, admin_token, agent["id"], tools=["db.drop"])
    assert r.status_code == 422 and "db.drop" in r.text
    r = await _statement(client, admin_token, agent["id"], hours=24 * 8)
    assert r.status_code == 422
    r = await _statement(client, admin_token, agent["id"], task="   ")
    assert r.status_code == 422
    r = await _statement(client, admin_token, 999999)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_only_a_signer_gives_a_task(client, admin_token, db_session, org_and_users):
    from app.core.security import get_password_hash
    from app.models.user import User
    from tests.conftest import _login

    agent = await _agent(client, admin_token)
    db_session.add(User(org_id=org_and_users["org"].id, email="mandate-viewer@test.example.com", name="V",
                        hashed_password=get_password_hash(org_and_users["password"]), role="viewer",
                        status="active"))
    await db_session.commit()
    viewer = await _login(client, org_and_users["org"].slug, "mandate-viewer@test.example.com",
                          org_and_users["password"])
    r = await _statement(client, viewer, agent["id"])
    assert r.status_code == 403
    # a signer whose session key no passkey certified yet
    r = await _statement(client, admin_token, agent["id"])
    assert r.status_code == 403 and "session" in r.text


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_calls_are_checked_against_the_task(client, admin_token, db_session):
    agent = await _agent(client, admin_token, tools=("db.read", "db.write"))
    other = await _agent(client, admin_token)
    r, st, _ = await _give(client, admin_token, agent["id"], tools=["db.read"])
    mid = r.json()["id"]

    action_id = await _act(client, admin_token, agent, mid)
    row = (await db_session.execute(select(AgentAction).where(AgentAction.id == action_id))).scalar_one()
    assert row.evidence["mandate"]["id"] == mid
    assert row.evidence["mandate"]["statement_sha256"] == r.json()["statement_sha256"]

    chk = await _check(client, admin_token, agent, mid, tool_name="db.write")
    assert chk["decision"] == "denied" and "does not include the tool db.write" in chk["reason"]
    chk = await _check(client, admin_token, other, mid)
    assert chk["decision"] == "denied" and f"given to agent #{agent['id']}" in chk["reason"]
    chk = await _check(client, admin_token, agent, 999999)
    assert chk["decision"] == "denied" and "does not exist" in chk["reason"]

    # named by someone who holds no key of the agent: it does not count
    chk = await _check(client, admin_token, agent, mid, signed=False)
    assert chk["decision"] == "denied" and "own signed request" in chk["reason"]

    assert (await _end(client, admin_token, agent["id"], mid)).status_code == 200
    chk = await _check(client, admin_token, agent, mid)
    assert chk["decision"] == "denied" and "was ended" in chk["reason"]

    # without a task the call runs as before - until the organization requires one
    assert (await _check(client, admin_token, agent))["decision"] == "allowed"
    r = await client.put("/api/v1/agent-identity/settings", json={
        "require_agent_key": False, "rotation_grace_minutes": 60, "require_task_mandate": True},
        headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    chk = await _check(client, admin_token, agent)
    assert chk["decision"] == "denied" and "requires the agent to name one" in chk["reason"]
    r, _, _ = await _give(client, admin_token, agent["id"])
    assert (await _check(client, admin_token, agent, r.json()["id"]))["decision"] == "allowed"
    # required: the task is the agent's signed word, never an API key holder's claim
    assert (await _check(client, admin_token, agent, r.json()["id"], signed=False))["decision"] == "denied"


@pytest.mark.asyncio
async def test_a_delegated_agent_acts_under_the_roots_task(client, admin_token):
    lead = await _agent(client, admin_token)
    helper = await _agent(client, admin_token)
    r, _, _ = await _give(client, admin_token, lead["id"])
    mid = r.json()["id"]
    r = await client.post(f"{A}/{lead['id']}/delegate",
                          json=delegation_body(lead, helper["id"], "read the table", ["read"], tools=["db.read"]),
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    chain_id = r.json()["chain_id"]
    assert (await _check(client, admin_token, helper, mid, chain_id=chain_id))["decision"] == "allowed"
    # outside the chain the helper is not acting for the lead
    assert (await _check(client, admin_token, helper, mid))["decision"] == "denied"


# ---------------------------------------------------------------------------
# Proof of Authority
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_proof_starts_with_the_person_who_asked(client, admin_token):
    agent = await _agent(client, admin_token)
    await _release(client, admin_token)          # the admin's passkey is in the signed manifest
    r, st, _ = await _give(client, admin_token, agent["id"], tools=["db.read"])
    mid = r.json()["id"]
    doc = await _authority(client, admin_token, await _act(client, admin_token, agent, mid))
    assert doc["mandate"]["mandate_id"] == mid and doc["mandate"]["statement"] == st

    action, lines, gaps = tool.check_authority(doc)
    assert gaps == [], gaps
    assert lines[0].startswith("task:") and f"task #{mid}" in lines[0] and "signed manifest" in lines[0]
    assert "Reconcile the October invoices" in lines[0]

    bad = copy.deepcopy(doc)
    bad["mandate"]["statement"]["task"] = "Pay every invoice"
    assert "not the task the action's evidence names" in _fails(bad)
    bad = copy.deepcopy(doc)
    bad["mandate"]["signature"] = base64.b64encode(b"\0" * 64).decode()
    assert "does not verify" in _fails(bad)
    bad = copy.deepcopy(doc)
    del bad["mandate"]
    assert "does not carry it" in _fails(bad)

    # ended, signed: the proof of the earlier action says when and by whom
    action_id = doc["action_id"]
    assert (await _end(client, admin_token, agent["id"], mid)).status_code == 200
    doc = await _authority(client, admin_token, action_id)
    end = doc["mandate"]["ended"]["statement"]
    assert end["type"] == "provenza.mandate.end" and end["mandate_id"] == mid
    _, lines, gaps = tool.check_authority(doc)
    assert gaps == [] and "ended" in lines[1] and "signed" in lines[1]
    # an end the person did not sign, or of another task, is caught
    bad = copy.deepcopy(doc)
    bad["mandate"]["ended"]["statement"]["issued_at"] += 1
    assert "does not verify" in _fails(bad)
    bad = copy.deepcopy(doc)
    bad["mandate"]["ended"]["statement"]["mandate_id"] += 1
    assert "ends another task" in _fails(bad)
    bad = copy.deepcopy(doc)
    bad["mandate"]["ended"] = None
    assert "no signed statement that ended it" in _fails(bad)
    # an allowed action dated after the signed end
    bad = copy.deepcopy(doc)
    late = copy.deepcopy(bad["mandate"])
    late["ended"]["statement"]["issued_at"] = doc["receipt"]["action"]["recorded_at"] - 3600
    with pytest.raises(tool.Fail):
        tool.check_mandate(late, doc["receipt"]["action"], doc["org_id"])


@pytest.mark.asyncio
async def test_a_replaced_task_names_what_replaced_it(client, admin_token):
    agent = await _agent(client, admin_token)
    await _release(client, admin_token)
    r, _, _ = await _give(client, admin_token, agent["id"])
    mid = r.json()["id"]
    action_id = await _act(client, admin_token, agent, mid)
    r, st2, _ = await _give(client, admin_token, agent["id"], task="Close the quarter")
    doc = await _authority(client, admin_token, action_id)
    assert doc["mandate"]["status"] == "ended" and doc["mandate"]["ended"]["statement"] == st2
    _, lines, gaps = tool.check_authority(doc)
    assert gaps == [] and "a new task replaced it" in lines[1]
    bad = copy.deepcopy(doc)
    bad["mandate"]["ended"]["statement"]["agent_id"] += 1
    assert "does not replace it" in _fails(bad)


@pytest.mark.asyncio
async def test_a_task_given_after_the_release(client, admin_token, approver_token):
    """A person whose passkey the signed manifest does not list: reported, not passed silently."""
    agent = await _agent(client, admin_token)
    await _release(client, admin_token)
    r, _, _ = await _give(client, approver_token, agent["id"])
    doc = await _authority(client, admin_token, await _act(client, admin_token, agent, r.json()["id"]))
    _, lines, gaps = tool.check_authority(doc)
    assert any(g.startswith("task:") and "not in the signed manifest" in g for g in gaps)


def _signed_header(agent, name, arguments, mandate_id):
    """X-Provenza-Action as agent mode sends it, naming the task."""
    nonce, issued = secrets.token_hex(16), int(time.time())
    payload = {"type": "action.request", "agent_id": agent["id"], "chain_id": None, "action_type": "tool_call",
               "tool_name": name, "input_sha256": content_hash(arguments), "tool_version": None,
               "tool_digest": None, "nonce": nonce, "issued_at": issued, "mandate_id": mandate_id}
    body = {"nonce": nonce, "issued_at": issued, "signature": sign_payload(payload, agent["private_key"]),
            "mandate_id": mandate_id}
    if agent.get("pq_private_key"):
        body["pq_signature"] = sign_payload_pq(payload, agent["pq_private_key"])
    return base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")


@pytest.mark.asyncio
async def test_the_agent_signs_the_task_it_acts_for(client, admin_token, fake, db_session):  # noqa: F811
    server, agent = await _ready(client, admin_token, fake)
    r, _, _ = await _give(client, admin_token, agent["id"], tools=["files.read"])
    mid = r.json()["id"]
    args = {"path": "a.txt"}
    r = await _call(client, agent, "tools/call", {"name": "files.read", "arguments": args},
                    headers={"X-Provenza-Action": _signed_header(agent, "files.read", args, mid)})
    assert "result" in r.json(), r.text
    row = (await db_session.execute(select(AgentAction).where(AgentAction.agent_id == agent["id"])
                                    .order_by(AgentAction.id.desc()))).scalars().first()
    assert row.evidence["requested"]["payload"]["mandate_id"] == mid and row.evidence["mandate"]["id"] == mid
    doc = await _authority(client, admin_token, row.id)
    _, lines, _ = tool.check_authority(doc)
    assert lines[0].startswith("task:") and any("signed the request for this call" in x for x in lines)

    # the evidence claiming another task than the agent signed for is caught
    bad = copy.deepcopy(doc)
    bad["receipt"]["action"]["requested"]["payload"]["mandate_id"] = mid + 1
    with pytest.raises(tool.Fail):
        tool.check_authority(bad)

    # a task that ended: refused, and nothing ran
    assert (await _end(client, admin_token, agent["id"], mid)).status_code == 200
    r = await _call(client, agent, "tools/call", {"name": "files.read", "arguments": args},
                    headers={"X-Provenza-Action": _signed_header(agent, "files.read", args, mid)})
    assert "was ended" in json.dumps(r.json())
