"""
Replay protection for signed delegations (answer to external review):

  - a captured signed /delegate request cannot be re-submitted (nonce is
    single-use, enforced by a DB unique constraint)
  - an old signed request cannot be submitted later (issued_at freshness
    window), and the TTL counts from the SIGNED issued_at, so a late
    resend can never extend a delegation's lifetime
  - nonce / issued_at are inside the signature: changing them breaks it
  - an agent that has a registered key cannot delegate unsigned
"""

import secrets
import time
from datetime import datetime

import pytest

from app.core.agent_signing import sign_payload
from tests.conftest import auth_headers
from tests.delegation_helpers import delegation_body


async def _agent(client, token, name, caps):
    resp = await client.post(
        "/api/v1/agents/register",
        json={
            "name": name, "agent_type": "custom", "capabilities": caps,
            "allowed_tools": ["db.read"], "allowed_models": ["gpt-4o-mini"],
            "max_delegation_depth": 3,
        },
        headers=auth_headers(token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _pair(client, token):
    a = await _agent(client, token, "root-" + secrets.token_hex(3), ["read", "write"])
    b = await _agent(client, token, "child-" + secrets.token_hex(3), ["read"])
    return a, b


def _url(agent):
    return f"/api/v1/agents/{agent['id']}/delegate"


class TestReplay:
    @pytest.mark.asyncio
    async def test_same_signed_request_twice_is_rejected(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        body = delegation_body(a, b["id"], "t", ["read"])
        first = await client.post(_url(a), json=body, headers=auth_headers(admin_token))
        assert first.status_code == 200, first.text
        replay = await client.post(_url(a), json=body, headers=auth_headers(admin_token))
        assert replay.status_code == 409, replay.text
        assert "Replayed" in replay.json()["detail"]

    @pytest.mark.asyncio
    async def test_fresh_nonce_each_time_is_accepted(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        for _ in range(2):
            r = await client.post(_url(a), json=delegation_body(a, b["id"], "t", ["read"]),
                                  headers=auth_headers(admin_token))
            assert r.status_code == 200, r.text

    @pytest.mark.asyncio
    async def test_nonce_is_scoped_per_agent(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        c = await _agent(client, admin_token, "other-" + secrets.token_hex(3), ["read"])
        nonce = secrets.token_hex(16)
        r1 = await client.post(_url(a), json=delegation_body(a, b["id"], "t", ["read"], nonce=nonce),
                               headers=auth_headers(admin_token))
        r2 = await client.post(_url(c), json=delegation_body(c, b["id"], "t", ["read"], nonce=nonce),
                               headers=auth_headers(admin_token))
        assert r1.status_code == 200, r1.text
        assert r2.status_code == 200, r2.text


class TestFreshness:
    @pytest.mark.asyncio
    async def test_stale_request_is_rejected(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        body = delegation_body(a, b["id"], "t", ["read"], issued_at=int(time.time()) - 400)
        r = await client.post(_url(a), json=body, headers=auth_headers(admin_token))
        assert r.status_code == 400 and "stale" in r.json()["detail"], r.text

    @pytest.mark.asyncio
    async def test_future_issued_at_is_rejected(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        body = delegation_body(a, b["id"], "t", ["read"], issued_at=int(time.time()) + 120)
        r = await client.post(_url(a), json=body, headers=auth_headers(admin_token))
        assert r.status_code == 400 and "future" in r.json()["detail"], r.text

    @pytest.mark.asyncio
    async def test_ttl_counts_from_signed_issued_at(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        issued = int(time.time()) - 100          # still inside the 5-min window
        body = delegation_body(a, b["id"], "t", ["read"], issued_at=issued, expires_in=150)
        r = await client.post(_url(a), json=body, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        chain = await client.get(f"/api/v1/agents/delegation-chains/{r.json()['chain_id']}",
                                 headers=auth_headers(admin_token))
        assert chain.status_code == 200, chain.text
        exp = datetime.fromisoformat(chain.json()["hops"][0]["expires_at"])
        # issued_at + 150, NOT server-receive-time + 150 (which would be ~100s later)
        assert abs(exp.timestamp() - (issued + 150)) < 3


class TestSignatureCoversReplayFields:
    @pytest.mark.asyncio
    async def test_swapping_nonce_breaks_signature(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        body = delegation_body(a, b["id"], "t", ["read"])
        body["nonce"] = secrets.token_hex(16)    # attacker picks a fresh nonce
        r = await client.post(_url(a), json=body, headers=auth_headers(admin_token))
        assert r.status_code == 400 and "signature" in r.json()["detail"], r.text

    @pytest.mark.asyncio
    async def test_bumping_issued_at_breaks_signature(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        body = delegation_body(a, b["id"], "t", ["read"])
        body["issued_at"] += 1                   # attacker "refreshes" an old request
        r = await client.post(_url(a), json=body, headers=auth_headers(admin_token))
        assert r.status_code == 400 and "signature" in r.json()["detail"], r.text


class TestSignatureRequired:
    @pytest.mark.asyncio
    async def test_keyed_agent_cannot_delegate_unsigned(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        r = await client.post(_url(a), json={"to_agent_id": b["id"], "task": "t",
                                             "delegated_capabilities": ["read"]},
                              headers=auth_headers(admin_token))
        assert r.status_code == 401, r.text

    @pytest.mark.asyncio
    async def test_signed_without_replay_fields_is_rejected(self, client, admin_token):
        a, b = await _pair(client, admin_token)
        payload = {"from_agent_id": a["id"], "to_agent_id": b["id"], "task": "t",
                   "delegated_capabilities": ["read"], "chain_id": None,
                   "expires_in": None, "nonce": None, "issued_at": None}
        body = {"to_agent_id": b["id"], "task": "t", "delegated_capabilities": ["read"],
                "signature": sign_payload(payload, a["private_key"])}
        r = await client.post(_url(a), json=body, headers=auth_headers(admin_token))
        assert r.status_code == 400 and "nonce" in r.json()["detail"], r.text
