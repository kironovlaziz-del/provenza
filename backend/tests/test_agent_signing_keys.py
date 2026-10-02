# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Signatures that do not depend on trusting the server.

  - an agent can register its OWN public key: the server never holds the
    private key, and says so (key_origin "agent");
  - verification evidence carries the exact signed text, the key that
    verified it and that key's fingerprint, so a verifier checks bytes
    rather than re-serializing, and can compare the fingerprint with the
    agent owner's;
  - changing an agent's key keeps old records verifiable (signer key is
    stored on the record) and is kept in a key history;
  - non-ASCII text (Cyrillic, Uzbek) signs and verifies like ASCII.
"""

import base64
import hashlib
import json
import secrets

import pytest

from app.core.agent_signing import (
    canonical_text, generate_keypair, key_fingerprint, normalize_public_key, sign_payload, verify_payload,
)
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body, delegation_body

A = "/api/v1/agents"
TASK = "Отчёт за квартал — o'zbekcha: hisobot ✓"


async def _register(client, token, public_key=None, caps=("read", "write")):
    body = {"name": "sk-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": list(caps),
            "allowed_tools": ["db.read"], "allowed_models": [], "max_delegation_depth": 3}
    if public_key is not None:
        body["public_key"] = public_key
    return await client.post(f"{A}/register", json=body, headers=auth_headers(token))


async def _agent_held(client, token, **kw):
    priv, pub = generate_keypair()  # stands in for keygen on the agent's machine
    resp = await _register(client, token, public_key=pub, **kw)
    assert resp.status_code == 200, resp.text
    return {**resp.json(), "private_key": priv}


def _verify_evidence(ev: dict) -> bool:
    """What an independent verifier does: canonical check, then the signature
    over the exact signed text."""
    msg = ev["signed_message"]
    assert canonical_text(json.loads(msg)) == msg
    assert json.loads(msg) == ev["signed_payload"]
    return verify_payload(json.loads(msg), ev["signature"], ev["public_key"])


class TestHelpers:
    def test_fingerprint_is_sha256_of_raw_key(self):
        _, pub = generate_keypair()
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(pub)).digest()).decode().rstrip("=")
        assert key_fingerprint(pub) == expected and len(expected) == 50

    def test_canonical_text_is_ascii_and_signs_non_ascii(self):
        priv, pub = generate_keypair()
        payload = {"task": TASK, "b": [1, {"z": "й", "a": None}]}
        text = canonical_text(payload)
        assert text.isascii() and "\\u041e" in text
        assert verify_payload(json.loads(text), sign_payload(payload, priv), pub)

    @pytest.mark.parametrize("bad", ["not base64!", base64.b64encode(b"x" * 31).decode(), ""])
    def test_bad_public_keys_are_rejected(self, bad):
        with pytest.raises(ValueError):
            normalize_public_key(bad)

    # The identity point and the other small-order points: with such a key a
    # fixed "signature" verifies for every message.
    WEAK = ["01" + "00" * 31, "ec" + "ff" * 30 + "7f", "00" * 32, "00" * 31 + "80",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "ed" + "ff" * 30 + "7f", "ee" + "ff" * 30 + "7f"]

    @pytest.mark.parametrize("hexkey", WEAK)
    def test_weak_keys_are_rejected(self, hexkey):
        with pytest.raises(ValueError):
            normalize_public_key(base64.b64encode(bytes.fromhex(hexkey)).decode())

    def test_forgery_with_a_weak_key_does_not_verify(self):
        identity = bytes.fromhex("01" + "00" * 31)
        forged = base64.b64encode(identity + bytes(32)).decode()
        assert verify_payload({"any": "payload"}, forged, base64.b64encode(identity).decode()) is False

    def test_real_keys_pass(self):
        for _ in range(20):
            _, pub = generate_keypair()
            assert normalize_public_key(pub) == pub


class TestAgentHeldKeys:
    async def test_register_with_own_key_returns_no_private_key(self, client, admin_token):
        _, pub = generate_keypair()
        resp = await _register(client, admin_token, public_key=pub)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["private_key"] is None
        assert body["public_key"] == pub and body["key_origin"] == "agent"
        assert body["key_fingerprint"] == key_fingerprint(pub)

        keys = (await client.get(f"{A}/{body['id']}/signing-keys", headers=auth_headers(admin_token))).json()
        assert [(k["origin"], k["fingerprint"], k["retired_at"]) for k in keys] == [("agent", key_fingerprint(pub), None)]

    async def test_server_generated_key_is_labelled(self, client, admin_token):
        body = (await _register(client, admin_token)).json()
        assert body["private_key"] and body["key_origin"] == "server"

    async def test_a_server_generated_key_cannot_be_relabelled_agent_held(self, client, admin_token):
        server_made = (await _register(client, admin_token)).json()
        resp = await _register(client, admin_token, public_key=server_made["public_key"])
        assert resp.status_code == 422
        assert resp.json()["detail"] == "agent.key_server_generated"

    async def test_one_key_per_agent(self, client, admin_token):
        a = await _agent_held(client, admin_token)
        resp = await _register(client, admin_token, public_key=a["public_key"])
        assert resp.status_code == 422
        assert resp.json()["detail"] == "agent.key_in_use"

    async def test_empty_public_key_is_an_error_not_a_server_key(self, client, admin_token):
        resp = await _register(client, admin_token, public_key="")
        assert resp.status_code == 422

    async def test_invalid_public_key_is_refused(self, client, admin_token):
        resp = await _register(client, admin_token, public_key=base64.b64encode(b"short").decode())
        assert resp.status_code == 422


class TestEvidence:
    async def test_signed_delegation_with_cyrillic_task_is_verifiable_independently(self, client, admin_token):
        a = await _agent_held(client, admin_token)
        b = await _agent_held(client, admin_token)
        r = await client.post(f"{A}/{a['id']}/delegate", json=delegation_body(a, b["id"], TASK, ["read"]),
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["verified"] is True

        ev = (await client.get(f"{A}/delegation-hops/{r.json()['hop_id']}/verification",
                               headers=auth_headers(admin_token))).json()
        assert ev["format"] == "provenza-signature-evidence/1" and ev["algorithm"] == "ed25519"
        assert ev["public_key"] == a["public_key"] and ev["key_origin"] == "agent"
        assert ev["key_fingerprint"] == key_fingerprint(a["public_key"])
        assert ev["signed_payload"]["task"] == TASK
        assert _verify_evidence(ev)

    async def test_recorded_action_has_evidence(self, client, admin_token):
        a = await _agent_held(client, admin_token)
        chk = (await client.post(f"{A}/actions/check", json={"agent_id": a["id"], "tool_name": "db.read",
                                                             "input": {"q": "пример"}},
                                 headers=auth_headers(admin_token))).json()
        rec = await client.post(f"{A}/actions/record",
                                json=action_record_body(a, chk["check_id"], "db.read", {"q": "пример"}),
                                headers=auth_headers(admin_token))
        assert rec.status_code == 200, rec.text
        ev = (await client.get(f"{A}/actions/{rec.json()['id']}/verification",
                               headers=auth_headers(admin_token))).json()
        assert ev["record"] == "agent_action" and ev["public_key"] == a["public_key"]
        assert ev["server_verified"] is True
        assert _verify_evidence(ev)

    async def test_unsigned_hop_has_no_evidence_to_verify(self, client, admin_token, db_session):
        from app.models.agent import Agent
        a = await _agent_held(client, admin_token)
        b = await _agent_held(client, admin_token)
        # a keyless agent delegates unsigned (cooperative path)
        agent = await db_session.get(Agent, a["id"])
        agent.public_key = None
        await db_session.flush()
        r = await client.post(f"{A}/{a['id']}/delegate",
                              json={"to_agent_id": b["id"], "task": "x", "delegated_capabilities": ["read"]},
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        ev = (await client.get(f"{A}/delegation-hops/{r.json()['hop_id']}/verification",
                               headers=auth_headers(admin_token))).json()
        assert ev["has_signature"] is False and ev["public_key"] is None


class TestKeyChange:
    async def test_replacing_the_key_keeps_old_records_verifiable(self, client, admin_token):
        a = await _agent_held(client, admin_token)
        b = await _agent_held(client, admin_token)
        old = await client.post(f"{A}/{a['id']}/delegate", json=delegation_body(a, b["id"], "before", ["read"]),
                                headers=auth_headers(admin_token))
        assert old.status_code == 200, old.text

        new_priv, new_pub = generate_keypair()
        r = await client.post(f"{A}/{a['id']}/signing-key", json={"public_key": new_pub},
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["public_key"] == new_pub and r.json()["key_origin"] == "agent"

        # the old record still verifies - with the key that signed it
        ev = (await client.get(f"{A}/delegation-hops/{old.json()['hop_id']}/verification",
                               headers=auth_headers(admin_token))).json()
        assert ev["public_key"] == a["public_key"] and _verify_evidence(ev)

        # the old private key no longer works, the new one does
        stale = await client.post(f"{A}/{a['id']}/delegate", json=delegation_body(a, b["id"], "after", ["read"]),
                                  headers=auth_headers(admin_token))
        assert stale.status_code == 400
        fresh = await client.post(f"{A}/{a['id']}/delegate",
                                  json=delegation_body({**a, "private_key": new_priv}, b["id"], "after", ["read"]),
                                  headers=auth_headers(admin_token))
        assert fresh.status_code == 200, fresh.text

        keys = (await client.get(f"{A}/{a['id']}/signing-keys", headers=auth_headers(admin_token))).json()
        assert [k["fingerprint"] for k in keys] == [key_fingerprint(new_pub), key_fingerprint(a["public_key"])]
        assert keys[0]["retired_at"] is None and keys[1]["retired_at"] is not None

    async def test_moving_off_a_server_generated_key(self, client, admin_token):
        a = (await _register(client, admin_token)).json()
        _, pub = generate_keypair()
        r = await client.post(f"{A}/{a['id']}/signing-key", json={"public_key": pub},
                              headers=auth_headers(admin_token))
        assert r.json()["key_origin"] == "agent"
        keys = (await client.get(f"{A}/{a['id']}/signing-keys", headers=auth_headers(admin_token))).json()
        assert [k["origin"] for k in keys] == ["agent", "server"]

    async def test_only_admins_set_keys(self, client, admin_token, approver_token):
        a = await _agent_held(client, admin_token)
        _, pub = generate_keypair()
        r = await client.post(f"{A}/{a['id']}/signing-key", json={"public_key": pub},
                              headers=auth_headers(approver_token))
        assert r.status_code == 403
