# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP receipts and the TRACE export (app/pvp/evidence.py, seal.py, receipt.py,
jcs.py, trace.py) - checked by the server's model AND by the standalone
tools/provenza_audit.py, which shares no code with the server.

  - an action's evidence is fixed at record time; a later approval or
    retention does not break its receipt;
  - seals put many actions into ONE audit record;
  - action -> seal -> audit record -> signed checkpoint verifies offline,
    and changing any link is caught;
  - the TRACE record is JCS (RFC 8785 vectors), signed, honest about its
    level, and carries receipts that verify.
"""

import base64
import copy
import importlib.util
import json
import secrets
import struct
from pathlib import Path

import pytest
from sqlalchemy import func, select, update

from app.models.agent_action import AgentAction
from app.models.audit_log import AIAuditLog
from app.pvp import jcs, seal as seals
from app.pvp.model import PVPReceipt
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body, delegation_body

ROOT = Path(__file__).resolve().parents[2]
CHECK = "/api/v1/agents/actions/check"
RECORD = "/api/v1/agents/actions/record"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = _load("provenza_audit_tool_pvp", ROOT / "tools" / "provenza_audit.py")


async def _agent(client, token, tools=("db.read",)):
    r = await client.post("/api/v1/agents/register", json={
        "name": "rcp-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
        "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 3,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _act(client, token, agent, tool_name="db.read", inp=None, chain_id=None):
    inp = {"q": "select 1"} if inp is None else inp
    chk = await client.post(CHECK, json={"agent_id": agent["id"], "tool_name": tool_name, "input": inp,
                                         "chain_id": chain_id}, headers=auth_headers(token))
    assert chk.status_code == 200, chk.text
    r = await client.post(RECORD, json=action_record_body(agent, chk.json()["check_id"], tool_name, inp,
                                                          output={"rows": 1}, chain_id=chain_id),
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()["id"]


async def _receipt(client, token, action_id):
    r = await client.get(f"/api/v1/pvp/receipts/{action_id}", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# RFC 8785
# ---------------------------------------------------------------------------

class TestJCS:
    @pytest.mark.parametrize("bits,expected", [
        ("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"),
        ("7fefffffffffffff", "1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"),
        ("4430000000000000", "295147905179352830000"), ("44b52d02c7e14af6", "1e+23"),
        ("444b1ae4d6e2ef50", "1e+21"), ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"), ("41b3de4355555553", "333333333.3333332"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
    ])
    def test_number_vectors_of_rfc_8785(self, bits, expected):
        x = struct.unpack(">d", bytes.fromhex(bits))[0]
        assert jcs.canonicalize(x).decode() == expected
        assert tool.jcs(x).decode() == expected   # the independent implementation agrees

    def test_sorting_by_utf16_code_units(self):
        names = [chr(0x20ac), "\r", chr(0xfb33), "1", chr(0x1f600), chr(0x80), chr(0xf6)]
        got = list(json.loads(jcs.canonicalize({n: 0 for n in names})))
        assert got == ["\r", "1", chr(0x80), chr(0xf6), chr(0x20ac), chr(0x1f600), chr(0xfb33)]

    def test_the_rfc_example(self):
        s = chr(0x20ac) + "$" + chr(0xf) + "\nA'B\"\\\\\"/"
        value = {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27], "string": s,
                 "literals": [None, True, False]}
        expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                    '"string":"' + chr(0x20ac) + '$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
        assert jcs.canonicalize(value).decode() == expected == tool.jcs(value).decode()

    @pytest.mark.parametrize("bad", [float("nan"), 2 ** 53, {1: "x"}, "\ud800"])
    def test_outside_i_json(self, bad):
        with pytest.raises(ValueError):
            jcs.canonicalize(bad)


# ---------------------------------------------------------------------------
# Evidence and seals
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_evidence_is_fixed_at_record_time(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    row = (await db_session.execute(select(AgentAction).where(AgentAction.id == action_id))).scalar_one()
    assert row.evidence["action_id"] == action_id and row.evidence["decision"] == "allowed"
    assert len(row.evidence_sha256) == 64 and row.seal_id is None
    assert "select 1" not in json.dumps(row.evidence)   # hashes, never the content


@pytest.mark.asyncio
async def test_many_actions_one_audit_record(client, admin_token, db_session, org_and_users):
    org_id = org_and_users["org"].id
    agent = await _agent(client, admin_token)
    ids = [await _act(client, admin_token, agent, inp={"q": i}) for i in range(5)]
    before = (await db_session.execute(select(func.count()).select_from(AIAuditLog).where(
        AIAuditLog.org_id == org_id, AIAuditLog.entity_type == "pvp_action_seal"))).scalar_one()
    result = await seals.seal_all(db_session)
    assert result["actions"] >= 5 and result["failed"] == 0
    after = (await db_session.execute(select(func.count()).select_from(AIAuditLog).where(
        AIAuditLog.org_id == org_id, AIAuditLog.entity_type == "pvp_action_seal"))).scalar_one()
    assert after == before + 1
    sealed = (await db_session.execute(select(AgentAction.seal_id).where(AgentAction.id.in_(ids)))).scalars().all()
    assert len(set(sealed)) == 1 and None not in sealed
    assert (await seals.seal_all(db_session))["seals"] == 0   # nothing left


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_receipt_verifies_on_the_server_and_offline(client, admin_token):
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    doc = await _receipt(client, admin_token, action_id)        # sealed on demand
    assert PVPReceipt.model_validate(doc).problems() == []
    action, cp, fp = tool.check_receipt(doc, tool.Trust())
    assert action["action_id"] == action_id and cp["tree_size"] >= 1
    agent_fp = tool.fingerprint(agent["public_key"])
    tool.check_receipt(doc, tool.Trust([fp]), agent_fp)        # pinned audit key and agent key
    with pytest.raises(tool.Fail):
        tool.check_receipt(doc, tool.Trust(), "SHA256:" + "A" * 43)


@pytest.mark.parametrize("tamper,expect", [
    (lambda d: d["action"].__setitem__("tool_name", "db.write"), "seal"),
    (lambda d: d["action"].__setitem__("output_sha256", "0" * 64), "seal"),
    (lambda d: d["seal"].__setitem__("root", "1" * 64), "seal"),
    (lambda d: d["seal"].__setitem__("leaf_index", d["seal"]["size"]), "seal"),
    (lambda d: d["audit_proof"]["record"]["payload"]["metadata"].__setitem__("size", 99), "audit"),
    (lambda d: d["check"].__setitem__("input_sha256", "f" * 64), "check"),
])
@pytest.mark.asyncio
async def test_any_changed_link_is_caught(client, admin_token, tamper, expect):
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    doc = copy.deepcopy(await _receipt(client, admin_token, action_id))
    tamper(doc)
    with pytest.raises(tool.Fail):
        tool.check_receipt(doc, tool.Trust())
    assert PVPReceipt.model_validate(doc).problems() != []


@pytest.mark.asyncio
async def test_approval_and_retention_leave_the_receipt_intact(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    # a human decides later; retention blanks the content
    await db_session.execute(update(AgentAction).where(AgentAction.id == action_id).values(
        policy_check_result="denied", reason="denied by user #1", input_data={}, output_data=None,
        signed_payload=None))
    await db_session.commit()
    doc = await _receipt(client, admin_token, action_id)
    assert doc["action"]["decision"] == "allowed" and doc["current_decision"] == "denied"
    assert PVPReceipt.model_validate(doc).problems() == []
    tool.check_receipt(doc, tool.Trust())


@pytest.mark.asyncio
async def test_receipt_is_per_organization(client, admin_token, db_session):
    from tests.conftest import _create_org_with_admin_and_approver, _login

    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    await _create_org_with_admin_and_approver(db_session, org_slug="rcp-other", admin_email="a@rcp.example.com",
                                              approver_email="b@rcp.example.com")
    await db_session.commit()
    other = await _login(client, "rcp-other", "a@rcp.example.com", "TestPass123!")
    r = await client.get(f"/api/v1/pvp/receipts/{action_id}", headers=auth_headers(other))
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_action_without_evidence_has_no_receipt(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    await db_session.execute(update(AgentAction).where(AgentAction.id == action_id).values(
        evidence=None, evidence_sha256=None))
    await db_session.commit()
    r = await client.get(f"/api/v1/pvp/receipts/{action_id}", headers=auth_headers(admin_token))
    assert r.status_code == 409 and r.json()["detail"] == "pvp.no_evidence"


# ---------------------------------------------------------------------------
# TRACE
# ---------------------------------------------------------------------------

DIGEST = r"^sha(256|384):[0-9a-f]{64,96}$"


def _schema_shape(claims):
    """The constraints of TRACE v0.2's schema/trace-claim.json that apply here."""
    import re

    required = {"eat_profile", "iat", "subject", "model", "runtime", "policy", "data_class", "build_provenance",
                "appraisal", "cnf"}
    allowed = required | {"tool_transcript", "delegation", "origin", "references", "reproducibility",
                          "transparency", "signature"}
    assert required <= set(claims) <= allowed
    assert claims["eat_profile"] == "tag:agentrust-io.com,2026:trace-v0.2"
    assert 1700000000 <= claims["iat"] <= 2 ** 53 - 1
    assert re.match(r"^did:[a-z0-9]+:.+$", claims["subject"])
    assert set(claims["model"]) <= {"provider", "model_id", "version", "weights_digest", "aibom_uri"}
    assert claims["runtime"]["platform"] == "software-only" and re.match(DIGEST, claims["runtime"]["measurement"])
    assert claims["policy"]["enforcement_mode"] in ("enforce", "advisory", "silent", "declared")
    assert re.match(DIGEST, claims["policy"]["bundle_hash"])
    assert re.match(DIGEST, claims["tool_transcript"]["hash"])
    assert claims["build_provenance"]["slsa_level"] == 0 and re.match(DIGEST, claims["build_provenance"]["digest"])
    assert claims["appraisal"]["status"] in ("affirming", "warning", "contraindicated", "none")
    assert claims["origin"]["kind"] == "third-party-control-plane"   # => software-only, as the schema requires
    jwk = claims["cnf"]["jwk"]
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and "d" not in jwk
    for ref in claims["references"]:
        assert ref["rel"] and ref["id"] and ref["resolver"] and re.match(DIGEST, ref["digest"])
    assert "transparency" not in claims   # Provenza's checkpoints are not a SCITT log


@pytest.mark.asyncio
async def test_trace_record_for_an_action(client, admin_token):
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    r = await client.get(f"/api/v1/pvp/receipts/{action_id}/trace", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["level"] == 0 and doc["profile"] == "tag:agentrust-io.com,2026:trace-v0.2"
    claims, fp = tool.check_trace(doc, tool.Trust())
    _schema_shape(claims)
    assert claims["appraisal"]["status"] == "affirming"            # signed by the agent, receipt verifies
    assert claims["policy"]["enforcement_mode"] == "advisory"     # the agent reported its own action
    assert claims["tool_transcript"]["call_count"] == 1
    header = json.loads(base64.urlsafe_b64decode(doc["jwt"].split(".")[0] + "=="))
    assert header == {"alg": "EdDSA", "kid": fp, "typ": "JWT"}
    # the payload is the JCS form of the claims
    payload = base64.urlsafe_b64decode(doc["jwt"].split(".")[1] + "=" * (-len(doc["jwt"].split(".")[1]) % 4))
    assert payload == jcs.canonicalize(claims)


@pytest.mark.parametrize("tamper", [
    lambda d: d["claims"].__setitem__("data_class", "public"),                        # claims beside the JWT
    lambda d: d.__setitem__("jwt", d["jwt"][:-4] + ("AAAA" if not d["jwt"].endswith("AAAA") else "BBBB")),
    lambda d: d["receipts"][0]["action"].__setitem__("tool_name", "db.write"),        # a carried receipt
])
@pytest.mark.asyncio
async def test_trace_tampering_is_caught(client, admin_token, tamper):
    agent = await _agent(client, admin_token)
    action_id = await _act(client, admin_token, agent)
    doc = (await client.get(f"/api/v1/pvp/receipts/{action_id}/trace", headers=auth_headers(admin_token))).json()
    tamper(doc)
    with pytest.raises(tool.Fail):
        tool.check_trace(doc, tool.Trust())


@pytest.mark.asyncio
async def test_trace_record_for_a_chain(client, admin_token):
    root = await _agent(client, admin_token)
    worker = await _agent(client, admin_token)
    d = await client.post(f"/api/v1/agents/{root['id']}/delegate",
                          json=delegation_body(root, worker["id"], "report", ["read"], tools=["db.read"]),
                          headers=auth_headers(admin_token))
    assert d.status_code == 200, d.text
    chain_id = d.json()["chain_id"]
    for i in range(3):
        await _act(client, admin_token, worker, inp={"q": i}, chain_id=chain_id)
    r = await client.get(f"/api/v1/pvp/chains/{chain_id}/trace", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    claims, _ = tool.check_trace(r.json(), tool.Trust())
    _schema_shape(claims)
    assert claims["tool_transcript"]["call_count"] == 3
    assert claims["subject"].endswith(f"agent-{root['id']}")
