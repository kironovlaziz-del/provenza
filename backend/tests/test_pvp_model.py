# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP canonical model (app/pvp/model.py, docs/pvp/spec.md).

Two kinds of guarantee:
  - the model refuses what it must: lax ids, unknown fields, another
    protocol version, half a hybrid signature, NaN in hashed data;
  - signed_payload() is byte-for-byte what the REST endpoints verify, shown
    against the real endpoints: a PVP-signed delegation and action are
    accepted as verified, and the records they produce check out offline
    through PVPAction / PVPReceipt / PVPCheckpoint.
"""

import secrets
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.agent_signing import content_hash, generate_keypair, sign_payload
from app.pvp import model as pvp
from app.pvp.schema import json_schemas, render
from app.services import agent_policy_engine
from tests.conftest import auth_headers

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "docs" / "pvp" / "schemas"


def _sig(priv, payload):
    return sign_payload(payload, priv)


# ---------------------------------------------------------------------------
# What the model refuses
# ---------------------------------------------------------------------------

class TestStrictness:
    @pytest.mark.parametrize("bad", ["5", 5.0, True, 0, -1, 2**31])
    def test_ids_are_strict_positive_int32(self, bad):
        with pytest.raises(ValidationError):
            pvp.PVPActionRequest(agent_id=bad, tool_name="db.read")

    def test_unknown_field_is_refused(self):
        with pytest.raises(ValidationError):
            pvp.parse_message({"type": "action.request", "agent_id": 1, "tool_name": "db.read",
                               "action_capabilities": ["admin"]})

    def test_other_protocol_version_is_refused(self):
        with pytest.raises(ValidationError):
            pvp.parse_message({"pvp": "pvp/2", "type": "query", "subject": "action", "id": 1})

    def test_unknown_type_is_refused(self):
        with pytest.raises(ValidationError):
            pvp.parse_message({"type": "action.execute", "agent_id": 1})

    def test_messages_are_immutable(self):
        q = pvp.PVPQuery(subject="action", id=1)
        with pytest.raises(ValidationError):
            q.id = 2

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), {"deep": [1, float("-inf")]}])
    def test_non_finite_numbers_in_hashed_data_are_refused(self, value):
        with pytest.raises(ValidationError):
            pvp.PVPActionRequest(agent_id=1, tool_name="db.read", input={"x": value})
        with pytest.raises(ValidationError):
            pvp.PVPActionRecord(agent_id=1, tool_name="db.read", output={"x": value})

    def test_action_type_is_a_token_not_free_text(self):
        with pytest.raises(ValidationError):
            pvp.PVPActionRequest(agent_id=1, tool_name="db.read", action_type="Tool Call; drop")

    def test_error_code_is_dotted(self):
        assert pvp.PVPError(code="agent.key_required").code == "agent.key_required"
        with pytest.raises(ValidationError):
            pvp.PVPError(code="Bad Code")


class TestParse:
    def test_each_type_round_trips_through_json(self):
        msgs = [
            pvp.PVPQuery(subject="receipt", id=7, format="trace"),
            pvp.PVPError(code="pvp.schema_invalid", details={"field": "agent_id"}),
            pvp.PVPActionRequest(agent_id=3, chain_id=4, tool_name="db.read", input={"q": "select 1"}),
            pvp.PVPDelegation(from_agent_id=1, to_agent_id=2, task="t", delegated_capabilities=["read"]),
            pvp.PVPAttestation(agent_id=1, kind="k8s_sa", attested_at=10, expires_at=20,
                               claims={"namespace": "prod"}),
        ]
        for m in msgs:
            again = pvp.parse_message(m.model_dump_json())
            assert type(again) is type(m) and again == m
            assert pvp.parse_message(m.model_dump()) == m

    def test_every_message_type_is_in_the_union(self):
        names = {m.model_fields["type"].default for m in pvp.MESSAGE_TYPES}
        assert len(names) == len(pvp.MESSAGE_TYPES) == 11

    def test_decisions_are_the_policy_engine_values(self):
        assert (pvp.ALLOWED, pvp.DENIED, pvp.PENDING_APPROVAL) == (
            agent_policy_engine.ALLOWED, agent_policy_engine.DENIED, agent_policy_engine.PENDING_APPROVAL)


class TestShapes:
    # what is *allowed* (a signed request without nonce / check_id,
    # self-delegation) is the orchestrator's call: tests/test_pvp_orchestrator.py

    def test_hybrid_signature_needs_both_halves(self):
        _, pub = generate_keypair()
        with pytest.raises(ValidationError):
            pvp.PVPSignature(scheme="ed25519+ml-dsa-65", public_key=pub, signature="AAAA")
        with pytest.raises(ValidationError):
            pvp.PVPSignature(scheme="ed25519", public_key=pub, signature="AAAA",
                             pq_public_key="AAAA", pq_signature="AAAA")

    def test_agent_scheme_must_match_keys(self):
        _, pub = generate_keypair()
        base = dict(id=1, org_id=1, name="a", status="active", max_delegation_depth=3)
        assert pvp.PVPAgent(**base, public_key=pub, scheme="ed25519").key_fingerprint.startswith("SHA256:")
        with pytest.raises(ValidationError):
            pvp.PVPAgent(**base, public_key=pub, scheme="ed25519+ml-dsa-65")
        with pytest.raises(ValidationError):
            pvp.PVPAgent(**base, scheme="ed25519")

    def test_attestation_window(self):
        with pytest.raises(ValidationError):
            pvp.PVPAttestation(agent_id=1, kind="k8s_sa", attested_at=20, expires_at=20)

    def test_delegation_payload_sorts_like_the_server(self):
        d = pvp.PVPDelegation(from_agent_id=1, to_agent_id=2, task="t",
                              delegated_capabilities=["b", "a", "b"], delegated_tools=["y", "x", "y"])
        p = d.signed_payload()
        assert p["delegated_capabilities"] == ["a", "b", "b"]   # sorted, not de-duplicated
        assert p["delegated_tools"] == ["x", "y"]               # sorted set
        assert "delegated_tools" not in pvp.PVPDelegation(from_agent_id=1, to_agent_id=2,
                                                          task="t").signed_payload()


# ---------------------------------------------------------------------------
# Offline checks of evidence
# ---------------------------------------------------------------------------

def _signed_action(priv, pub, **over):
    fields = dict(action_id=9, agent_id=3, chain_id=None, action_type="tool_call", tool_name="db.read",
                  check_id="k" * 40, decision="allowed", input_sha256=content_hash({"q": 1}),
                  output_sha256=content_hash(None), recorded_at=int(time.time()))
    payload = {k: fields[k] for k in ("check_id", "agent_id", "chain_id", "action_type", "tool_name",
                                      "input_sha256", "output_sha256")}
    fields.update(over)
    return pvp.PVPAction(**fields, signed_payload=payload, signed_by=pvp.PVPSignature(
        scheme="ed25519", public_key=pub, signature=_sig(priv, payload)))


class TestEvidence:
    def test_consistent_action_has_no_problems(self):
        priv, pub = generate_keypair()
        assert _signed_action(priv, pub).problems() == []

    def test_action_that_differs_from_what_was_signed_is_caught(self):
        priv, pub = generate_keypair()
        a = _signed_action(priv, pub, tool_name="stripe.charge")
        assert "signed_payload_mismatch:tool_name" in a.problems()

    def test_signature_by_another_key_is_caught(self):
        priv, _ = generate_keypair()
        _, other = generate_keypair()
        assert "signature_invalid" in _signed_action(priv, other).problems()

    def test_unsigned_action_is_reported(self):
        a = pvp.PVPAction(action_id=1, agent_id=1, tool_name="t", decision="denied",
                          input_sha256="0" * 64, output_sha256="0" * 64, recorded_at=0)
        assert a.problems() == ["unsigned"]

    def test_receipt_binds_check_to_action(self):
        priv, pub = generate_keypair()
        action = _signed_action(priv, pub)
        check = pvp.PVPCheck(check_id=action.check_id, agent_id=3, tool_name="db.read",
                             input_sha256=action.input_sha256, decision="allowed", expires_at=1)
        assert pvp.PVPReceipt(action=action, check=check).problems() == []
        denied = check.model_copy(update={"decision": "denied"})
        assert "check_mismatch:decision" in pvp.PVPReceipt(action=action, check=denied).problems()


# ---------------------------------------------------------------------------
# Compatibility with the REST endpoints
# ---------------------------------------------------------------------------

async def _agent(client, token, **rights):
    r = await client.post("/api/v1/agents/register", json={
        "name": "pvp-" + secrets.token_hex(3), "agent_type": "custom",
        "capabilities": ["read"], "allowed_tools": ["db.read"], "allowed_models": ["gpt-4o-mini"],
        "max_delegation_depth": 3, **rights,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _wire(msg) -> dict:
    """A PVP message as the REST body of the matching endpoint."""
    return msg.model_dump(exclude={"pvp", "type", "from_agent_id"})


class TestRestCompatibility:
    @pytest.mark.asyncio
    async def test_pvp_signed_delegation_is_verified_by_the_endpoint(self, client, admin_token):
        a = await _agent(client, admin_token)
        b = await _agent(client, admin_token)
        unsigned = pvp.PVPDelegation(from_agent_id=a["id"], to_agent_id=b["id"], task="summarize",
                                     delegated_capabilities=["read"], delegated_tools=["db.read"],
                                     nonce=secrets.token_hex(16), issued_at=int(time.time()), expires_in=600)
        d = unsigned.model_copy(update={"signature": _sig(a["private_key"], unsigned.signed_payload())})
        r = await client.post(f"/api/v1/agents/{a['id']}/delegate", json=_wire(d), headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["verified"] is True

    @pytest.mark.asyncio
    async def test_pvp_signed_action_is_recorded_and_checks_out_offline(self, client, admin_token):
        a = await _agent(client, admin_token)
        req = pvp.PVPActionRequest(agent_id=a["id"], tool_name="db.read", input={"q": "select 1"})
        r = await client.post("/api/v1/agents/actions/check", json=_wire(req), headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        chk = r.json()
        check = pvp.PVPCheck(check_id=chk["check_id"], agent_id=a["id"], tool_name="db.read",
                             input_sha256=req.input_sha256, decision=chk["decision"], reason=chk["reason"],
                             expires_at=int(time.time()) + 60)

        unsigned = pvp.PVPActionRecord(agent_id=a["id"], tool_name="db.read", check_id=check.check_id,
                                       input=req.input, output={"rows": 1})
        rec = unsigned.model_copy(update={"signature": _sig(a["private_key"], unsigned.signed_payload())})
        r = await client.post("/api/v1/agents/actions/record", json=_wire(rec), headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["signed_payload"] == rec.signed_payload()

        action = pvp.PVPAction(
            action_id=out["id"], agent_id=a["id"], tool_name="db.read", check_id=check.check_id,
            decision=out["policy_check_result"], input_sha256=req.input_sha256,
            output_sha256=content_hash({"rows": 1}), recorded_at=int(time.time()),
            signed_payload=out["signed_payload"],
            signed_by=pvp.signature_of(out["signature"], None, a["public_key"], None),
        )
        assert pvp.PVPReceipt(action=action, check=check).problems() == []

    @pytest.mark.asyncio
    async def test_audit_checkpoint_parses_and_verifies(self, client, admin_token):
        await _agent(client, admin_token)  # registration writes an audit record
        r = await client.post("/api/v1/audit-logs/checkpoints", headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        cp = pvp.PVPCheckpoint(**r.json())
        assert cp.problems() == []
        forged = cp.model_copy(update={"tree_size": cp.tree_size + 1})
        assert "statement_mismatch:tree_size" in forged.problems()


# ---------------------------------------------------------------------------
# Published schemas
# ---------------------------------------------------------------------------

def test_committed_json_schemas_match_the_model():
    generated = json_schemas()
    committed = {p.name for p in SCHEMA_DIR.glob("*.schema.json")}
    assert committed == set(generated), "run: python -m app.pvp.schema ../docs/pvp/schemas"
    stale = [n for n, s in generated.items() if (SCHEMA_DIR / n).read_text(encoding="utf-8") != render(s)]
    assert not stale, f"regenerate docs/pvp/schemas: {stale}"
