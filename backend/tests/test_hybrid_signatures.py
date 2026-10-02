# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Hybrid post-quantum signatures: Ed25519 + ML-DSA-65 (FIPS 204).

  - a hybrid agent signs the same canonical bytes with both keys, and a
    signature counts only if BOTH verify (AND, never OR) - a forger has to
    break the elliptic curve and the lattice scheme;
  - one fingerprint pins both public keys;
  - evidence carries both signatures and keys, so a verifier checks both;
  - an organization can require hybrid keys (require_pq_signatures): new
    classical keys are refused, and agents still on Ed25519 alone can no
    longer delegate, record actions or send messages.
"""

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone

import pytest

from app.core.agent_signing import (
    SCHEME_CLASSIC, SCHEME_HYBRID, canonical_text, content_hash, generate_keypair, generate_pq_keypair,
    key_fingerprint, normalize_pq_public_key, pq_available, sign_payload, sign_payload_pq,
    verify_agent_signature, verify_payload_pq,
)
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body, delegation_body

pytestmark = pytest.mark.skipif(not pq_available(), reason="ML-DSA needs cryptography >= 48")

A = "/api/v1/agents"
X = "/api/v1/a2a"
ID = "/api/v1/agent-identity"
TASK = "Отчёт за квартал — o'zbekcha: hisobot ✓"
MLDSA65_SPKI_PREFIX = "308207b2300b0609608648016503040312038207a100"  # as printed in the docs


def _hybrid_keys():
    """What `provenza_sign.py keygen --hybrid` produces on the agent's machine."""
    priv, pub = generate_keypair()
    seed, pq_pub = generate_pq_keypair()
    return {"private_key": priv, "public_key": pub, "pq_private_key": seed, "pq_public_key": pq_pub}


async def _register(client, token, **extra):
    body = {"name": "pq-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read", "write"],
            "allowed_tools": ["db.read"], "allowed_models": [], "max_delegation_depth": 3, **extra}
    return await client.post(f"{A}/register", json=body, headers=auth_headers(token))


async def _hybrid_agent(client, token):
    keys = _hybrid_keys()
    resp = await _register(client, token, public_key=keys["public_key"], pq_public_key=keys["pq_public_key"])
    assert resp.status_code == 200, resp.text
    return {**resp.json(), "private_key": keys["private_key"], "pq_private_key": keys["pq_private_key"]}


async def _classic_agent(client, token):
    priv, pub = generate_keypair()
    resp = await _register(client, token, public_key=pub)
    assert resp.status_code == 200, resp.text
    return {**resp.json(), "private_key": priv}


async def _require_pq(client, token, on=True):
    r = await client.put(f"{ID}/settings", json={"require_agent_key": False, "rotation_grace_minutes": 60,
                                                 "require_pq_signatures": on}, headers=auth_headers(token))
    assert r.status_code == 200, r.text


class TestPrimitives:
    def test_both_halves_are_required(self):
        k = _hybrid_keys()
        payload = {"task": TASK, "n": 1}
        ed, pq = sign_payload(payload, k["private_key"]), sign_payload_pq(payload, k["pq_private_key"])
        assert verify_agent_signature(payload, ed, pq, k["public_key"], k["pq_public_key"])
        # a valid Ed25519 signature alone is not enough for a hybrid key
        assert not verify_agent_signature(payload, ed, None, k["public_key"], k["pq_public_key"])
        # ... nor is a valid ML-DSA signature with a broken Ed25519 one
        other = _hybrid_keys()
        assert not verify_agent_signature(payload, sign_payload(payload, other["private_key"]), pq,
                                          k["public_key"], k["pq_public_key"])
        # ML-DSA signature from another key
        assert not verify_agent_signature(payload, ed, sign_payload_pq(payload, other["pq_private_key"]),
                                          k["public_key"], k["pq_public_key"])
        # tampered payload
        assert not verify_agent_signature({**payload, "n": 2}, ed, pq, k["public_key"], k["pq_public_key"])

    def test_classical_key_ignores_no_pq_and_needs_ed25519(self):
        priv, pub = generate_keypair()
        payload = {"a": 1}
        assert verify_agent_signature(payload, sign_payload(payload, priv), None, pub, None)
        assert not verify_agent_signature(payload, None, None, pub, None)

    def test_ml_dsa_signs_the_canonical_bytes(self):
        k = _hybrid_keys()
        payload = {"task": TASK}
        sig = sign_payload_pq(payload, k["pq_private_key"])
        assert len(base64.b64decode(sig)) == 3309
        # a verifier that only has the signed text gets the same answer
        assert verify_payload_pq(json.loads(canonical_text(payload)), sig, k["pq_public_key"])

    def test_hybrid_fingerprint_covers_both_keys(self):
        k = _hybrid_keys()
        raw = base64.b64decode(k["public_key"]) + base64.b64decode(k["pq_public_key"])
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        assert key_fingerprint(k["public_key"], k["pq_public_key"]) == expected
        assert expected != key_fingerprint(k["public_key"])

    def test_documented_openssl_prefix_wraps_the_raw_key(self):
        # docs/agent-signing.md: raw ML-DSA-65 key -> SubjectPublicKeyInfo DER
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import mldsa
        pub = mldsa.MLDSA65PrivateKey.generate().public_key()
        der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        assert der == bytes.fromhex(MLDSA65_SPKI_PREFIX) + pub.public_bytes_raw()

    @pytest.mark.parametrize("bad", ["", "not base64!", base64.b64encode(b"x" * 1951).decode(),
                                     base64.b64encode(b"x" * 32).decode()])
    def test_bad_pq_keys_are_rejected(self, bad):
        with pytest.raises(ValueError):
            normalize_pq_public_key(bad)


class TestRegistration:
    async def test_agent_held_hybrid_key(self, client, admin_token):
        a = await _hybrid_agent(client, admin_token)
        assert a["signature_scheme"] == SCHEME_HYBRID and a["key_origin"] == "agent"
        assert a["key_fingerprint"] == key_fingerprint(a["public_key"], a["pq_public_key"])
        keys = (await client.get(f"{A}/{a['id']}/signing-keys", headers=auth_headers(admin_token))).json()
        assert keys[0]["scheme"] == SCHEME_HYBRID and keys[0]["pq_public_key"] == a["pq_public_key"]

    async def test_server_generated_hybrid_returns_both_private_keys_once(self, client, admin_token):
        resp = await _register(client, admin_token, key_scheme="hybrid")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["private_key"] and body["pq_private_key"] and body["pq_public_key"]
        assert body["signature_scheme"] == SCHEME_HYBRID and body["key_origin"] == "server"
        got = await client.get(f"{A}/{body['id']}", headers=auth_headers(admin_token))
        assert "pq_private_key" not in got.json()

    async def test_classical_registration_stays_classical(self, client, admin_token):
        a = await _classic_agent(client, admin_token)
        assert a["signature_scheme"] == SCHEME_CLASSIC and a["pq_public_key"] is None

    async def test_pq_key_alone_is_refused(self, client, admin_token):
        _, pq_pub = generate_pq_keypair()
        resp = await _register(client, admin_token, pq_public_key=pq_pub)
        assert resp.status_code == 422

    async def test_hybrid_scheme_with_own_key_needs_the_pq_key(self, client, admin_token):
        _, pub = generate_keypair()
        resp = await _register(client, admin_token, public_key=pub, key_scheme="hybrid")
        assert resp.status_code == 422

    async def test_pq_key_cannot_be_reused_by_another_agent(self, client, admin_token):
        a = await _hybrid_agent(client, admin_token)
        _, pub = generate_keypair()
        resp = await _register(client, admin_token, public_key=pub, pq_public_key=a["pq_public_key"])
        assert resp.status_code == 422
        assert resp.json()["detail"] == "agent.key_in_use"


class TestSignedRecords:
    async def test_hybrid_delegation_and_its_evidence(self, client, admin_token):
        a = await _hybrid_agent(client, admin_token)
        b = await _hybrid_agent(client, admin_token)
        r = await client.post(f"{A}/{a['id']}/delegate", json=delegation_body(a, b["id"], TASK, ["read"]),
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["verified"] is True

        ev = (await client.get(f"{A}/delegation-hops/{r.json()['hop_id']}/verification",
                               headers=auth_headers(admin_token))).json()
        assert ev["algorithm"] == SCHEME_HYBRID
        assert ev["pq_public_key"] == a["pq_public_key"] and ev["pq_signature"]
        assert ev["key_fingerprint"] == key_fingerprint(a["public_key"], a["pq_public_key"])
        # an independent verifier checks both halves over the exact signed text
        msg = json.loads(ev["signed_message"])
        assert canonical_text(msg) == ev["signed_message"]
        assert verify_agent_signature(msg, ev["signature"], ev["pq_signature"], ev["public_key"], ev["pq_public_key"])

    async def test_ed25519_only_signature_from_a_hybrid_agent_is_refused(self, client, admin_token):
        a = await _hybrid_agent(client, admin_token)
        b = await _hybrid_agent(client, admin_token)
        body = delegation_body(a, b["id"], "x", ["read"])
        body.pop("pq_signature")
        r = await client.post(f"{A}/{a['id']}/delegate", json=body, headers=auth_headers(admin_token))
        assert r.status_code == 400

    async def test_wrong_ml_dsa_signature_is_refused(self, client, admin_token):
        a = await _hybrid_agent(client, admin_token)
        b = await _hybrid_agent(client, admin_token)
        mallory = _hybrid_keys()
        body = delegation_body({**a, "pq_private_key": mallory["pq_private_key"]}, b["id"], "x", ["read"])
        r = await client.post(f"{A}/{a['id']}/delegate", json=body, headers=auth_headers(admin_token))
        assert r.status_code == 400

    async def test_hybrid_action_record(self, client, admin_token):
        a = await _hybrid_agent(client, admin_token)
        chk = (await client.post(f"{A}/actions/check", json={"agent_id": a["id"], "tool_name": "db.read",
                                                             "input": {"q": "пример"}},
                                 headers=auth_headers(admin_token))).json()
        body = action_record_body(a, chk["check_id"], "db.read", {"q": "пример"})
        rec = await client.post(f"{A}/actions/record", json=body, headers=auth_headers(admin_token))
        assert rec.status_code == 200, rec.text
        ev = (await client.get(f"{A}/actions/{rec.json()['id']}/verification",
                               headers=auth_headers(admin_token))).json()
        assert ev["algorithm"] == SCHEME_HYBRID and ev["server_verified"] is True
        assert ev["pq_public_key"] == a["pq_public_key"]

    async def test_moving_a_classical_agent_to_hybrid_keeps_old_records_verifiable(self, client, admin_token):
        a = await _classic_agent(client, admin_token)
        b = await _classic_agent(client, admin_token)
        old = await client.post(f"{A}/{a['id']}/delegate", json=delegation_body(a, b["id"], "before", ["read"]),
                                headers=auth_headers(admin_token))
        assert old.status_code == 200, old.text

        k = _hybrid_keys()
        r = await client.post(f"{A}/{a['id']}/signing-key",
                              json={"public_key": k["public_key"], "pq_public_key": k["pq_public_key"]},
                              headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert r.json()["signature_scheme"] == SCHEME_HYBRID

        ev = (await client.get(f"{A}/delegation-hops/{old.json()['hop_id']}/verification",
                               headers=auth_headers(admin_token))).json()
        assert ev["algorithm"] == SCHEME_CLASSIC and ev["pq_public_key"] is None
        assert verify_agent_signature(json.loads(ev["signed_message"]), ev["signature"], None, ev["public_key"], None)

        fresh = await client.post(f"{A}/{a['id']}/delegate",
                                  json=delegation_body({**a, **k}, b["id"], "after", ["read"]),
                                  headers=auth_headers(admin_token))
        assert fresh.status_code == 200, fresh.text


class TestOrgPolicy:
    async def test_classical_registration_refused_when_required(self, client, admin_token):
        await _require_pq(client, admin_token)
        _, pub = generate_keypair()
        resp = await _register(client, admin_token, public_key=pub)
        assert resp.status_code == 422 and resp.json()["detail"] == "agent.pq_required"
        resp = await _register(client, admin_token)  # server-generated, Ed25519 only
        assert resp.status_code == 422 and resp.json()["detail"] == "agent.pq_required"
        assert (await _register(client, admin_token, key_scheme="hybrid")).status_code == 200
        await _hybrid_agent(client, admin_token)

    async def test_classical_key_change_refused_when_required(self, client, admin_token):
        a = await _hybrid_agent(client, admin_token)
        await _require_pq(client, admin_token)
        _, pub = generate_keypair()
        r = await client.post(f"{A}/{a['id']}/signing-key", json={"public_key": pub},
                              headers=auth_headers(admin_token))
        assert r.status_code == 422 and r.json()["detail"] == "agent.pq_required"

    async def test_existing_classical_agent_can_no_longer_sign(self, client, admin_token):
        a = await _classic_agent(client, admin_token)
        b = await _hybrid_agent(client, admin_token)
        await _require_pq(client, admin_token)

        r = await client.post(f"{A}/{a['id']}/delegate", json=delegation_body(a, b["id"], "x", ["read"]),
                              headers=auth_headers(admin_token))
        assert r.status_code == 403 and r.json()["detail"] == "agent.pq_required"

        chk = (await client.post(f"{A}/actions/check", json={"agent_id": a["id"], "tool_name": "db.read",
                                                             "input": {}},
                                 headers=auth_headers(admin_token))).json()
        rec = await client.post(f"{A}/actions/record", json=action_record_body(a, chk["check_id"], "db.read", {}),
                                headers=auth_headers(admin_token))
        assert rec.status_code == 403 and rec.json()["detail"] == "agent.pq_required"

        # a hybrid agent is unaffected
        ok = await client.post(f"{A}/{b['id']}/delegate", json=delegation_body(b, a["id"], "y", ["read"]),
                               headers=auth_headers(admin_token))
        assert ok.status_code == 200, ok.text

    async def test_keyless_agent_can_no_longer_delegate_unsigned(self, client, admin_token, db_session):
        from app.models.agent import Agent
        a = await _hybrid_agent(client, admin_token)
        b = await _hybrid_agent(client, admin_token)
        agent = await db_session.get(Agent, a["id"])
        agent.public_key, agent.pq_public_key = None, None
        await db_session.flush()
        await _require_pq(client, admin_token)
        r = await client.post(f"{A}/{a['id']}/delegate",
                              json={"to_agent_id": b["id"], "task": "x", "delegated_capabilities": ["read"]},
                              headers=auth_headers(admin_token))
        assert r.status_code == 403 and r.json()["detail"] == "agent.pq_required"

    async def test_saving_settings_without_the_field_keeps_the_policy(self, client, admin_token):
        await _require_pq(client, admin_token)
        r = await client.put(f"{ID}/settings", json={"require_agent_key": False, "rotation_grace_minutes": 30},
                             headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        overview = (await client.get(f"{ID}/", headers=auth_headers(admin_token))).json()
        assert overview["settings"]["require_pq_signatures"] is True
        assert overview["settings"]["rotation_grace_minutes"] == 30


class TestA2A:
    @staticmethod
    def _envelope(src, dst_id, payload, chain_id):
        return {"type": "a2a_message", "from_agent_id": src["id"], "to_agent_id": dst_id, "chain_id": chain_id,
                "message_type": "task.request", "payload_sha256": content_hash(payload),
                "nonce": secrets.token_hex(16), "issued_at": datetime.now(timezone.utc).isoformat()}

    async def _pair(self, client, token, src_factory, mode="enforce"):
        r = await client.put(X + "/settings", json={"mode": mode, "allow_same_chain": True,
                                                   "max_age_seconds": 300, "message_ttl_seconds": 3600},
                             headers=auth_headers(token))
        assert r.status_code == 200, r.text
        src = await src_factory(client, token)
        dst = await _hybrid_agent(client, token)
        d = await client.post(f"{A}/{src['id']}/delegate", json=delegation_body(src, dst["id"], "report", ["read"]),
                              headers=auth_headers(token))
        assert d.status_code == 200, d.text
        return src, dst, d.json()["chain_id"]

    async def _send(self, client, token, src, dst, chain_id, *, pq=True):
        env = self._envelope(src, dst["id"], "hi", chain_id)
        body = {"envelope": env, "signature": sign_payload(env, src["private_key"]), "payload": "hi"}
        if pq and src.get("pq_private_key"):
            body["pq_signature"] = sign_payload_pq(env, src["pq_private_key"])
        r = await client.post(X + "/send", json=body, headers=auth_headers(token))
        assert r.status_code == 200, r.text
        return r.json()

    async def test_hybrid_message_needs_both_signatures(self, client, admin_token):
        src, dst, chain_id = await self._pair(client, admin_token, _hybrid_agent)
        s = await self._send(client, admin_token, src, dst, chain_id)
        assert s["status"] == "accepted" and s["signature_valid"]
        s = await self._send(client, admin_token, src, dst, chain_id, pq=False)
        assert s["status"] == "rejected" and not s["signature_valid"]

    @pytest.mark.parametrize("mode", ["enforce", "monitor", "off"])
    async def test_classical_sender_rejected_when_policy_requires_pq(self, client, admin_token, mode):
        # an organization policy, so it holds whatever the A2A guard mode
        src, dst, chain_id = await self._pair(client, admin_token, _classic_agent, mode=mode)
        await _require_pq(client, admin_token)
        s = await self._send(client, admin_token, src, dst, chain_id)
        assert s["status"] == "rejected"
        assert any("post-quantum" in r for r in s["reasons"])
