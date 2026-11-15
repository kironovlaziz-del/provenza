# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Proof of Authority and completeness reports (docs/proof-of-authority.md;
app/pvp/authority.py, completeness.py), checked by the standalone
tools/provenza_audit.py, which shares no code with the server:

  - the evidence of an action names the signed release it was decided under,
    and - for a call a gateway executed - the agent's own signed request;
  - evidence written before these members existed keeps its form and hash;
  - the proof verifies the chain release -> rights and key -> delegation ->
    request -> record, and catches a change to any link;
  - seals form a chain, and a completeness report shows every action of an
    agent over a period - a dropped action or a dropped seal is caught.
"""

import base64
import copy
import json
import secrets
import time

import pytest
from sqlalchemy import select, update

from app.core.agent_signing import content_hash, sign_payload, sign_payload_pq
from app.models.agent_action import AgentAction
from app.models.pvp_seal import PVPActionSeal
from app.pvp import seal as seals
from app.pvp import signed_policy
from tests.conftest import auth_headers
from tests.delegation_helpers import delegation_body
from tests.test_mcp_gateway import _call, _ready, fake  # noqa: F401  (fake: the fixture)
from tests.test_policy_release import _release
from tests.test_pvp_receipts import _act, _agent, tool

AUTHORITY = "/api/v1/pvp/authority"
COMPLETENESS = "/api/v1/pvp/completeness"


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


async def _authority(client, token, action_id):
    r = await client.get(f"{AUTHORITY}/{action_id}", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _fails(doc, *args, **kw):
    with pytest.raises(tool.Fail) as e:
        tool.check_authority(doc, *args, **kw)
    return str(e.value)


def _signed_header(agent, name, arguments, chain_id=None):
    """X-Provenza-Action as agent mode sends it for a tools/call."""
    nonce, issued = secrets.token_hex(16), int(time.time())
    payload = {"type": "action.request", "agent_id": agent["id"], "chain_id": chain_id, "action_type": "tool_call",
               "tool_name": name, "input_sha256": content_hash(arguments), "tool_version": None,
               "tool_digest": None, "nonce": nonce, "issued_at": issued}
    body = {"nonce": nonce, "issued_at": issued, "signature": sign_payload(payload, agent["private_key"])}
    if agent.get("pq_private_key"):
        body["pq_signature"] = sign_payload_pq(payload, agent["pq_private_key"])
    return base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_older_evidence_keeps_its_form(client, admin_token, db_session):
    """No release, no signed request: the evidence has exactly the members it
    always had, so receipts of older actions still hash to their seal."""
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    row = (await db_session.execute(select(AgentAction).where(AgentAction.id == action_id))).scalar_one()
    assert "release" not in row.evidence and "requested" not in row.evidence
    doc = await _authority(client, admin_token, action_id)
    action, lines, gaps = tool.check_authority(doc)
    assert any(g.startswith("policy:") for g in gaps)       # honest: no signed release behind it
    assert any(line.startswith("agent:") for line in lines)  # the agent signed its record


@pytest.mark.asyncio
async def test_the_whole_chain_under_a_signed_release(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    await _release(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    row = (await db_session.execute(select(AgentAction).where(AgentAction.id == action_id))).scalar_one()
    assert row.evidence["release"]["number"] >= 1 and len(row.evidence["release"]["bundle_sha256"]) == 64

    doc = await _authority(client, admin_token, action_id)
    assert [d["release"]["number"] for d in doc["releases"]][-1] == row.evidence["release"]["number"]
    action, lines, gaps = tool.check_authority(doc)
    assert gaps == [], gaps
    text = "\n".join(lines)
    assert "release #" in text and "the tool db.read" in text and "is the one in the signed manifest" in text
    assert tool.main(["authority", "--require-full", _write(doc)]) == 0

    # every link is checked
    bad = copy.deepcopy(doc)
    bad["releases"][-1]["bundle"]["agents"][str(agent["id"])]["allowed_tools"] = ["db.write"]
    assert "does not hash" in _fails(bad)
    bad = copy.deepcopy(doc)
    bad["releases"][-1]["signatures"] = []
    assert "valid administrator signature" in _fails(bad)
    bad = copy.deepcopy(doc)
    bad["releases"] = []
    assert "carries no releases" in _fails(bad)
    bad = copy.deepcopy(doc)
    bad["receipt"]["action"]["release"]["number"] += 1
    assert "not in its seal" in _fails(bad)               # the evidence is sealed as it was
    # a passkey nobody of the quorum used
    assert "none of the passkeys you gave" in _fails(doc, passkey_fps=["SHA256:nobody"])


@pytest.mark.asyncio
async def test_a_tool_the_signed_policy_does_not_give(client, admin_token, db_session):
    """A file claiming an allowed call the signed policy does not cover is
    refused, even when everything else verifies: the verifier reads the
    rights from the signed bundle itself."""
    agent = await _agent(client, admin_token)
    await _release(client, admin_token)
    doc = await _authority(client, admin_token, await _act(client, admin_token, agent))
    rel = doc["releases"][-1]
    entry = rel["bundle"]["agents"][str(agent["id"])]
    assert "db.read" in entry["allowed_tools"]
    action = doc["receipt"]["action"]
    action_copy = dict(action, tool_name="db.drop")
    with pytest.raises(tool.Fail):
        tool.check_authority(dict(doc, receipt=dict(doc["receipt"], action=action_copy)))


@pytest.mark.asyncio
async def test_the_agents_signed_request_on_an_mcp_call(client, admin_token, fake, db_session):  # noqa: F811
    server, agent = await _ready(client, admin_token, fake)
    args = {"path": "a.txt"}
    header = _signed_header(agent, "files.read", args)
    r = await _call(client, agent, "tools/call", {"name": "files.read", "arguments": args},
                    headers={"X-Provenza-Action": header})
    assert "result" in r.json(), r.text
    row = (await db_session.execute(select(AgentAction).where(AgentAction.agent_id == agent["id"])
                                    .order_by(AgentAction.id.desc()))).scalars().first()
    assert row.executed_by == "mcp_gateway" and row.evidence["requested"]["payload"]["tool_name"] == "files.read"

    doc = await _authority(client, admin_token, row.id)
    action, lines, gaps = tool.check_authority(doc)
    assert any("signed the request for this call" in line for line in lines)
    assert not any(g.startswith("agent:") for g in gaps)
    pinned = tool.fingerprint(agent["public_key"], agent.get("pq_public_key"))
    tool.check_authority(doc, agent_fp=pinned)
    assert "another key" in _fails(doc, agent_fp="SHA256:someone-else")

    # the same header again: the nonce is spent
    r = await _call(client, agent, "tools/call", {"name": "files.read", "arguments": args},
                    headers={"X-Provenza-Action": header})
    assert r.json()["error"]["code"] == -32001 and "replayed" in r.json()["error"]["data"]
    # signed for other arguments: refused before anything runs
    r = await _call(client, agent, "tools/call", {"name": "files.read", "arguments": {"path": "c.txt"}},
                    headers={"X-Provenza-Action": _signed_header(agent, "files.read", {"path": "d.txt"})})
    assert r.json()["error"]["code"] == -32001
    r = await _call(client, agent, "tools/call", {"name": "files.read", "arguments": args},
                    headers={"X-Provenza-Action": "bm90IGpzb24"})
    assert r.json()["error"]["code"] == -32001

    # without the header the call runs as before, and the proof says what is missing
    r = await _call(client, agent, "tools/call", {"name": "files.read", "arguments": {"path": "e.txt"}})
    assert "result" in r.json()
    row = (await db_session.execute(select(AgentAction).where(AgentAction.agent_id == agent["id"])
                                    .order_by(AgentAction.id.desc()))).scalars().first()
    _, _, gaps = tool.check_authority(await _authority(client, admin_token, row.id))
    assert any(g.startswith("agent:") for g in gaps)


@pytest.mark.asyncio
async def test_a_delegated_action(client, admin_token, db_session):
    lead = await _agent(client, admin_token)
    helper = await _agent(client, admin_token)
    await _release(client, admin_token)
    r = await client.post(f"/api/v1/agents/{lead['id']}/delegate",
                          json=delegation_body(lead, helper["id"], "read the table", ["read"], tools=["db.read"]),
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    chain_id = r.json()["chain_id"]
    action_id = await _act(client, admin_token, helper, chain_id=chain_id)

    doc = await _authority(client, admin_token, action_id)
    action, lines, gaps = tool.check_authority(doc)
    assert gaps == [], gaps
    assert any(f"agent {lead['id']} -> agent {helper['id']}" in line for line in lines)
    # a forged hop is caught
    bad = copy.deepcopy(doc)
    bad["delegation"]["hops"][0]["signed_payload"]["task"] = "drop the table"
    assert "does not verify" in _fails(bad)
    bad = copy.deepcopy(doc)
    bad["delegation"]["hops"] = []
    assert "brings agent" in _fails(bad)


# ---------------------------------------------------------------------------
# Completeness
# ---------------------------------------------------------------------------

async def _report(client, token, agent_id, since, until):
    r = await client.get(COMPLETENESS, params={"agent_id": agent_id, "since": since, "until": until},
                         headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_seals_form_a_chain(client, admin_token, db_session, org_and_users):
    org_id = org_and_users["org"].id
    agent = await _agent(client, admin_token)
    for i in range(3):
        await _act(client, admin_token, agent, inp={"q": i})
        await seals.seal_org(db_session, org_id)
    rows = list((await db_session.execute(select(PVPActionSeal).where(PVPActionSeal.org_id == org_id)
                                          .order_by(PVPActionSeal.id))).scalars())
    for prev, cur in zip(rows, rows[1:]):
        assert (cur.prev_seal_id, cur.prev_root) == (prev.id, prev.root)


@pytest.mark.asyncio
async def test_a_completeness_report(client, admin_token, db_session, org_and_users):
    org_id = org_and_users["org"].id
    me, other = await _agent(client, admin_token), await _agent(client, admin_token)
    since = int(time.time()) - 5
    mine = []
    for i in range(3):
        mine.append(await _act(client, admin_token, me, inp={"q": i}))
        await _act(client, admin_token, other, inp={"q": i})
        await seals.seal_org(db_session, org_id)
    mine.append(await _act(client, admin_token, me, inp={"q": "last"}))   # sealed by the report itself
    until = int(time.time()) + 5

    doc = await _report(client, admin_token, me["id"], since, until)
    members, got, first, last, fps = tool.check_completeness(doc)
    assert sorted(m["action_id"] for m in got) == sorted(mine)
    assert {m["agent_id"] for m in members} >= {me["id"], other["id"]}
    assert tool.main(["completeness", _write(doc)]) == 0

    # an action dropped from a seal
    bad = copy.deepcopy(doc)
    seal = next(s for s in bad["seals"] if any(m["action_id"] == mine[0] for m in s["members"]))
    seal["members"] = [m for m in seal["members"] if m["action_id"] != mine[0]]
    with pytest.raises(tool.Fail, match="actions given|hash to its root"):
        tool.check_completeness(bad)
    # an action altered
    bad = copy.deepcopy(doc)
    m = next(m for s in bad["seals"] for m in s["members"] if m["action_id"] == mine[1])
    m["decision"] = "denied"
    with pytest.raises(tool.Fail, match="hash to its root"):
        tool.check_completeness(bad)
    # a whole seal dropped from the middle
    if len(doc["seals"]) >= 3:
        bad = copy.deepcopy(doc)
        del bad["seals"][1]
        with pytest.raises(tool.Fail, match="does not follow"):
            tool.check_completeness(bad)


@pytest.mark.asyncio
async def test_completeness_needs_a_period_with_actions(client, admin_token):
    agent = await _agent(client, admin_token)
    r = await client.get(COMPLETENESS, params={"agent_id": agent["id"], "since": 1000, "until": 2000},
                         headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"] == "pvp.no_actions_in_period"
    r = await client.get(COMPLETENESS, params={"agent_id": agent["id"], "since": 2000, "until": 1000},
                         headers=auth_headers(admin_token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_who_may_download(client, admin_token, db_session, org_and_users):
    from app.core.security import get_password_hash
    from app.models.user import User, UserRole
    from tests.conftest import _login

    db_session.add(User(org_id=org_and_users["org"].id, email="poa-user@test.example.com", name="U",
                        hashed_password=get_password_hash(org_and_users["password"]),
                        role=UserRole.user.value, status="active"))
    await db_session.commit()
    user_token = await _login(client, org_and_users["org"].slug, "poa-user@test.example.com",
                              org_and_users["password"])
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    r = await client.get(f"{AUTHORITY}/{action_id}", headers=auth_headers(user_token))
    assert r.status_code == 403
    r = await client.get(COMPLETENESS, params={"agent_id": agent["id"], "since": 0, "until": 2 ** 31},
                         headers=auth_headers(user_token))
    assert r.status_code == 403


def _write(doc):
    import tempfile

    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(doc, f)
    f.close()
    return f.name


@pytest.mark.asyncio
async def test_an_approved_action(client, admin_token, approver_token):
    """The approver's passkey is one the signed manifest lists; a passkey
    added after the release is reported, not passed silently."""
    from tests import signer
    from tests.test_signed_approvals import TOOL, _check, _gate, _record
    from tests.test_signed_approvals import _agent as _paying_agent

    async def approved_action():
        inp = {"amount": secrets.randbelow(1000) + 1}
        chk = await _check(client, admin_token, agent, inp)
        held = await _record(client, admin_token, agent, chk["check_id"], inp)
        r = await signer.approve(client, approver_token, held["id"], content_hash(inp))
        assert r.status_code == 200, r.text
        chk = await _check(client, admin_token, agent, inp)
        assert chk["decision"] == "allowed"
        return (await _record(client, admin_token, agent, chk["check_id"], inp))["id"]

    await _gate(client, admin_token)
    agent = await _paying_agent(client, admin_token)
    await signer.signer(client, approver_token)            # the approver's passkey, before the release
    await _release(client, admin_token)
    doc = await _authority(client, admin_token, await approved_action())
    action, lines, gaps = tool.check_authority(doc)
    assert gaps == [], gaps
    assert any(line.startswith("approval:") and "approver" in line and "signed manifest" in line for line in lines)
    assert action["tool_name"] == TOOL
