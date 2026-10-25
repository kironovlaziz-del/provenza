"""
Approvals signed with the reviewer's session key (docs/pvp/edge.md,
section 3): the server cannot make an approval up, only a signed approval
lets the held call run, and the receipt of the call carries the approval so
tools/provenza_audit.py checks it without the server - session key
signature, passkey certificate, the very call.
"""

import copy
import importlib.util
import json
import secrets
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.core.agent_signing import content_hash
from app.models.approval import AgentActionApproval
from tests import signer
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body

ROOT = Path(__file__).resolve().parents[2]
A = "/api/v1/agents"
TOOL = "payments.charge"

_spec = importlib.util.spec_from_file_location("provenza_audit_tool_approvals", ROOT / "tools" / "provenza_audit.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


async def _agent(client, token):
    r = await client.post(f"{A}/register", json={
        "name": "sa-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
        "allowed_tools": [TOOL], "allowed_models": [], "max_delegation_depth": 2}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _gate(client, token):
    r = await client.post(f"{A}/policies/", json={"name": "gate-" + secrets.token_hex(2),
                                                  "rules": {"require_approval_tools": [TOOL]}, "priority": 100},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text


async def _check(client, token, agent, inp):
    r = await client.post(f"{A}/actions/check", json={"agent_id": agent["id"], "tool_name": TOOL, "input": inp},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _record(client, token, agent, check_id, inp):
    r = await client.post(f"{A}/actions/record", json=action_record_body(agent, check_id, TOOL, inp,
                                                                          output={"ok": True}),
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _held(client, token, inp):
    await _gate(client, token)
    agent = await _agent(client, token)
    chk = await _check(client, token, agent, inp)
    assert chk["decision"] == "pending_approval"
    held = await _record(client, token, agent, chk["check_id"], inp)
    return agent, held["id"]


async def _statement(client, token, action_id, decision="approved"):
    r = await client.post(f"{A}/actions/{action_id}/statement", json={"decision": decision},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()["statement"]


class TestSigning:
    @pytest.mark.asyncio
    async def test_an_approval_needs_a_certified_session_and_its_signature(self, client, admin_token,
                                                                          approver_token):
        inp = {"amount": 10}
        _, action_id = await _held(client, admin_token, inp)
        sha = content_hash(inp)
        # no passkey, no certified session: nothing to sign with
        r = await client.post(f"{A}/actions/{action_id}/statement", json={"decision": "approved"},
                              headers=auth_headers(approver_token))
        assert r.status_code == 403 and r.json()["detail"] == "session.not_certified"
        s = await signer.signer(client, approver_token)
        r = await client.post(f"{A}/actions/{action_id}/approve", json={"input_sha256": sha},
                              headers=auth_headers(approver_token))
        assert r.status_code == 422 and r.json()["detail"] == "session.signature_required"

        st = await _statement(client, approver_token, action_id)
        assert st["type"] == "provenza.approval" and st["decision"] == "approved"
        assert (st["action_id"], st["tool_name"], st["input_sha256"], st["session_id"]) == \
            (action_id, TOOL, sha, s.session_id)

        def approve(statement, signature):
            return client.post(f"{A}/actions/{action_id}/approve",
                               json={"input_sha256": sha, "statement": statement, "signature": signature},
                               headers=auth_headers(approver_token))

        other = dict(st, input_sha256="0" * 64)                      # another call
        assert (await approve(other, s.sign(other))).json()["detail"] == "session.statement_mismatch"
        denial = dict(st, decision="denied")                         # another decision
        assert (await approve(denial, s.sign(denial))).json()["detail"] == "session.statement_mismatch"
        old = dict(st, issued_at=int(time.time()) - 3600)            # not fresh
        assert (await approve(old, s.sign(old))).json()["detail"] == "session.statement_stale"
        stranger = signer.Signer(approver_token, s.device, Ed25519PrivateKey.generate(), s.public_key, s.session_id)
        r = await approve(st, stranger.sign(st))                     # not the certified key
        assert r.status_code == 403 and r.json()["detail"] == "session.bad_signature"

        r = await approve(st, s.sign(st))
        assert r.status_code == 200 and r.json()["policy_check_result"] == "allowed", r.text

    @pytest.mark.asyncio
    async def test_the_owner_gets_no_statement_to_approve(self, client, admin_token, approver_token,
                                                          org_and_users, db_session):
        from sqlalchemy import update

        from app.models.agent import Agent

        agent, action_id = await _held(client, admin_token, {"amount": 1})
        await db_session.execute(update(Agent).where(Agent.id == agent["id"])
                                 .values(owner_user_id=org_and_users["approver"].id))
        await db_session.commit()
        await signer.signer(client, approver_token)
        r = await client.post(f"{A}/actions/{action_id}/statement", json={"decision": "approved"},
                              headers=auth_headers(approver_token))
        assert r.status_code == 403
        assert (await signer.deny(client, approver_token, action_id, "no")).status_code == 200

    @pytest.mark.asyncio
    async def test_denials_are_signed_when_they_can_be(self, client, admin_token, approver_token, db_session):
        _, first = await _held(client, admin_token, {"amount": 1})
        _, second = await _held(client, admin_token, {"amount": 2})
        # a session without a passkey can still refuse - refusing cannot be exploited
        r = await client.post(f"{A}/actions/{first}/deny", json={"reason": "no"}, headers=auth_headers(approver_token))
        assert r.status_code == 200
        r = await signer.deny(client, approver_token, second, "no")
        assert r.status_code == 200, r.text
        rows = {a.action_id: a for a in (await db_session.execute(select(AgentActionApproval).where(
            AgentActionApproval.action_id.in_((first, second))))).scalars()}
        assert rows[first].signed is None
        assert rows[second].signed["statement"]["decision"] == "denied"


class TestOnlySignedApprovalsRun:
    @pytest.mark.asyncio
    async def test_the_approved_call_runs_once_and_a_forged_row_never(self, client, admin_token, approver_token,
                                                                     db_session):
        inp = {"amount": 10}
        agent, action_id = await _held(client, admin_token, inp)
        r = await signer.approve(client, approver_token, action_id, content_hash(inp))
        assert r.status_code == 200, r.text
        row = (await db_session.execute(select(AgentActionApproval).where(
            AgentActionApproval.action_id == action_id))).scalar_one()
        good = copy.deepcopy(row.signed)

        # the stored approval is altered (another amount signed by nobody): it never runs anything
        forged = copy.deepcopy(good)
        forged["statement"]["input_sha256"] = content_hash({"amount": 99999})
        row.signed, row.input_sha256 = forged, content_hash({"amount": 99999})
        await db_session.commit()
        assert (await _check(client, admin_token, agent, {"amount": 99999}))["decision"] == "pending_approval"

        # an approval written without the person (no signature at all)
        row.signed = None
        await db_session.commit()
        assert (await _check(client, admin_token, agent, {"amount": 99999}))["decision"] == "pending_approval"

        # the genuine one, restored, lets exactly this call run, once
        row.signed, row.input_sha256 = good, content_hash(inp)
        await db_session.commit()
        chk = await _check(client, admin_token, agent, inp)
        assert chk["decision"] == "allowed" and f"approval #{row.id}" in chk["reason"]
        assert (await _check(client, admin_token, agent, inp))["decision"] == "pending_approval"


class TestReceipt:
    @pytest.mark.asyncio
    async def test_the_receipt_carries_the_approval_and_verifies_offline(self, client, admin_token,
                                                                         approver_token, tmp_path, capsys):
        inp = {"amount": 10}
        agent, action_id = await _held(client, admin_token, inp)
        assert (await signer.approve(client, approver_token, action_id, content_hash(inp))).status_code == 200
        chk = await _check(client, admin_token, agent, inp)
        assert chk["decision"] == "allowed"
        ran = await _record(client, admin_token, agent, chk["check_id"], inp)
        r = await client.get(f"/api/v1/pvp/receipts/{ran['id']}", headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        receipt = r.json()
        ap = receipt["approval"]
        assert ap["action_id"] == action_id and ap["statement"]["decision"] == "approved"

        passkeys = (await client.get("/api/v1/users/me/passkeys", headers=auth_headers(approver_token))).json()
        fp = passkeys[0]["fingerprint"]
        assert tool.passkey_fingerprint(ap["passkey"]["public_key"]) == fp
        tool.check_receipt(receipt, None, None, [fp])
        path = tmp_path / "receipt.json"
        path.write_text(json.dumps(receipt))
        assert tool.main(["receipt", str(path), "--approver-passkey", fp]) == 0
        assert f"certified by passkey {fp}" in capsys.readouterr().out
        with pytest.raises(tool.Fail, match="not one of the passkeys"):
            tool.check_receipt(receipt, None, None, ["SHA256:someoneelse"])

        def broken(change):
            doc = copy.deepcopy(receipt)
            change(doc["approval"])
            with pytest.raises(tool.Fail):
                tool.check_receipt(doc)

        broken(lambda a: a["statement"].update(user_id=a["statement"]["user_id"] + 1))      # another person
        broken(lambda a: a["statement"].update(input_sha256="0" * 64))                      # another call
        broken(lambda a: a["certificate"]["statement"].update(public_key=a["passkey"]["public_key"][:44]))
        broken(lambda a: a["certificate"]["assertion"].update(
            signature=a["certificate"]["assertion"]["signature"][:-4] + "AAAA"))          # passkey did not sign
        broken(lambda a: a["statement"].update(issued_at=a["certificate"]["statement"]["not_after"] + 1))

        # a receipt of an action no one approved has no approval
        plain = await _act_unheld(client, admin_token)
        assert plain.get("approval") is None


async def _act_unheld(client, token):
    agent = await _agent(client, token)
    inp = {"amount": 1}
    r = await client.post(f"{A}/actions/check", json={"agent_id": agent["id"], "tool_name": "other.tool",
                                                      "input": inp}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    rec = await client.post(f"{A}/actions/record", json=action_record_body(agent, r.json()["check_id"], "other.tool",
                                                                            inp, output={"ok": True}),
                            headers=auth_headers(token))
    assert rec.status_code == 200, rec.text
    r = await client.get(f"/api/v1/pvp/receipts/{rec.json()['id']}", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()
