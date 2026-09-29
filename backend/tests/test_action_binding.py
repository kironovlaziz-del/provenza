"""
Binding between /actions/check and /actions/record (answer to external
review: "the record path is cooperative, action capabilities are empty").

For an agent with a registered key:
  - record requires a single-use check_id issued by /actions/check
  - the recorded action must be exactly the checked one (agent, chain,
    tool, input hash) - otherwise 400 + an `action_mismatch` incident
  - the verdict stored is the one from check time
  - the record must be signed; the signature is verified before the
    check is consumed, and the signed payload is stored for offline
    verification
"""

import secrets

import pytest

from app.core.agent_signing import generate_keypair, verify_payload
from app.services import agent_audit as agent_audit_module
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body

CHECK = "/api/v1/agents/actions/check"
RECORD = "/api/v1/agents/actions/record"
INCIDENTS = "/api/v1/agents/incidents/"
QUERY = {"q": "select 1"}


async def _agent(client, token):
    resp = await client.post(
        "/api/v1/agents/register",
        json={
            "name": "act-" + secrets.token_hex(3), "agent_type": "custom",
            "capabilities": ["read"], "allowed_tools": ["db.read", "db.write"],
            "allowed_models": ["gpt-4o-mini"], "max_delegation_depth": 3,
        },
        headers=auth_headers(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _check(client, token, agent, tool="db.read", inp=None):
    r = await client.post(
        CHECK,
        json={"agent_id": agent["id"], "tool_name": tool, "input": QUERY if inp is None else inp},
        headers=auth_headers(token),
    )
    assert r.status_code == 200, r.text
    return r.json()


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_checked_action_is_recorded_and_verifiable_offline(self, client, admin_token):
        a = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a)
        assert chk["decision"] == "allowed" and len(chk["check_id"]) > 20
        body = action_record_body(a, chk["check_id"], "db.read", QUERY, output={"rows": 1})
        r = await client.post(RECORD, json=body, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["policy_check_result"] == "allowed"
        assert j["check_id"] is not None
        assert j["signed_payload"]["check_id"] == chk["check_id"]
        # an auditor can verify the stored action with only the public key
        assert verify_payload(j["signed_payload"], j["signature"], a["public_key"]) is True

    @pytest.mark.asyncio
    async def test_denied_check_is_recorded_as_denied(self, client, admin_token):
        a = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a, tool="stripe.charge", inp={})
        assert chk["decision"] == "denied"
        r = await client.post(RECORD, json=action_record_body(a, chk["check_id"], "stripe.charge", {}),
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["policy_check_result"] == "denied"


class TestBinding:
    @pytest.mark.asyncio
    async def test_check_id_is_single_use(self, client, admin_token):
        a = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a)
        body = action_record_body(a, chk["check_id"], "db.read", QUERY)
        first = await client.post(RECORD, json=body, headers=auth_headers(admin_token))
        assert first.status_code == 200, first.text
        again = await client.post(RECORD, json=body, headers=auth_headers(admin_token))
        assert again.status_code == 409, again.text

    @pytest.mark.asyncio
    async def test_recording_a_different_tool_raises_incident(self, client, admin_token):
        a = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a, tool="db.read")
        # check a harmless read, then try to record a write under that verdict
        r = await client.post(RECORD, json=action_record_body(a, chk["check_id"], "db.write", QUERY),
                              headers=auth_headers(admin_token))
        assert r.status_code == 400 and "does not match" in r.json()["detail"], r.text
        inc = await client.get(INCIDENTS, params={"incident_type": "action_mismatch"},
                               headers=auth_headers(admin_token))
        assert inc.status_code == 200, inc.text
        body = inc.json()
        items = body["items"] if isinstance(body, dict) else body
        assert any(i["incident_type"] == "action_mismatch" and i["agent_id"] == a["id"] for i in items)

    @pytest.mark.asyncio
    async def test_recording_different_input_is_rejected(self, client, admin_token):
        a = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a)
        r = await client.post(
            RECORD,
            json=action_record_body(a, chk["check_id"], "db.read", {"q": "drop table users"}),
            headers=auth_headers(admin_token),
        )
        assert r.status_code == 400, r.text

    @pytest.mark.asyncio
    async def test_check_of_another_agent_cannot_be_used(self, client, admin_token):
        a = await _agent(client, admin_token)
        b = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a)
        r = await client.post(RECORD, json=action_record_body(b, chk["check_id"], "db.read", QUERY),
                              headers=auth_headers(admin_token))
        assert r.status_code == 400, r.text

    @pytest.mark.asyncio
    async def test_expired_check_is_rejected(self, client, admin_token, monkeypatch):
        monkeypatch.setattr(agent_audit_module, "CHECK_TTL_SECONDS", -1)
        a = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a)
        r = await client.post(RECORD, json=action_record_body(a, chk["check_id"], "db.read", QUERY),
                              headers=auth_headers(admin_token))
        assert r.status_code == 400 and "expired" in r.json()["detail"], r.text


class TestSignature:
    @pytest.mark.asyncio
    async def test_keyed_agent_cannot_record_without_check(self, client, admin_token):
        a = await _agent(client, admin_token)
        r = await client.post(RECORD, json={"agent_id": a["id"], "tool_name": "db.read", "input": QUERY},
                              headers=auth_headers(admin_token))
        assert r.status_code == 401, r.text

    @pytest.mark.asyncio
    async def test_keyed_agent_cannot_record_unsigned(self, client, admin_token):
        a = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a)
        body = action_record_body(a, chk["check_id"], "db.read", QUERY)
        del body["signature"]
        r = await client.post(RECORD, json=body, headers=auth_headers(admin_token))
        assert r.status_code == 401, r.text

    @pytest.mark.asyncio
    async def test_forged_signature_rejected_and_check_not_burned(self, client, admin_token):
        a = await _agent(client, admin_token)
        chk = await _check(client, admin_token, a)
        other_priv, _ = generate_keypair()
        forged = action_record_body({**a, "private_key": other_priv}, chk["check_id"], "db.read", QUERY)
        r = await client.post(RECORD, json=forged, headers=auth_headers(admin_token))
        assert r.status_code == 400 and "signature" in r.json()["detail"], r.text
        # the legitimate agent can still use its check
        ok = await client.post(RECORD, json=action_record_body(a, chk["check_id"], "db.read", QUERY),
                               headers=auth_headers(admin_token))
        assert ok.status_code == 200, ok.text
