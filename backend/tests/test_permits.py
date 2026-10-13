# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Signed action permits (app/pvp/permits.py): issued with an allowed check,
verifiable by a tool from the public JWKS alone, redeemable once, for exactly
the checked tool and input, and visible on the check the record consumed.
"""

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select

from app.core.agent_signing import content_hash
from app.models.agent_action import ActionCheck
from app.pvp import permits
from app.pvp.orchestrator import PVPOrchestrator
from tests.conftest import auth_headers

CHECK = "/api/v1/agents/actions/check"
PERMITS = "/api/v1/pvp/permits"
INPUT = {"query": "select 1", "limit": 5}


def _b64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parts(token):
    h, c, s = token.split(".")
    return json.loads(_b64(h)), json.loads(_b64(c)), _b64(s), f"{h}.{c}".encode()


async def _agent(client, token, tools=("db.read",)):
    r = await client.post("/api/v1/agents/register", json={
        "name": "pmt-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
        "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 2,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


async def _check(client, agent, tool="db.read", input_data=INPUT):
    r = await client.post(CHECK, json={"agent_id": agent["id"], "action_type": "tool_call", "tool_name": tool,
                                       "input": input_data}, headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200, r.text
    return r.json()


async def _slug(db_session, agent_id):
    from app.models.agent import Agent
    from app.models.organization import Organization

    org_id = (await db_session.get(Agent, agent_id)).org_id
    return (await db_session.get(Organization, org_id)).slug


async def _redeem(client, permit, **extra):
    return await client.post(f"{PERMITS}/redeem", json={"permit": permit, **extra})


@pytest.mark.asyncio
async def test_an_allowed_check_carries_a_permit_a_tool_can_verify_from_the_jwks(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    chk = await _check(client, agent)
    assert chk["decision"] == "allowed" and chk["permit"]
    header, claims, signature, signing_input = parts(chk["permit"])
    slug = await _slug(db_session, agent["id"])
    assert header["alg"] == "EdDSA" and header["typ"] == "provenza-permit+jwt"
    assert claims["iss"] == f"provenza:org:{slug}" and claims["sub"] == f"agent:{agent['id']}"
    assert claims["aud"] == "db.read" and claims["act"] == "tool_call" and claims["chain"] is None
    assert claims["ish"] == content_hash(INPUT)
    assert claims["exp"] == int(datetime.fromisoformat(chk["expires_at"].replace("Z", "+00:00")).timestamp())
    assert claims["jti"] != chk["check_id"]   # the check_id stays the agent's

    # the tool: no account, only the public JWKS
    r = await client.get(f"{PERMITS}/{slug}/jwks.json")
    assert r.status_code == 200 and "max-age" in r.headers["cache-control"]
    jwk = next(k for k in r.json()["keys"] if k["kid"] == header["kid"])
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and set(jwk) == {"kty", "crv", "x", "kid", "use", "alg"}
    Ed25519PublicKey.from_public_bytes(_b64(jwk["x"])).verify(signature, signing_input)
    assert (await client.get(f"{PERMITS}/no-such-org/jwks.json")).status_code == 404


@pytest.mark.asyncio
async def test_a_denied_check_has_no_permit(client, admin_token):
    agent = await _agent(client, admin_token)
    chk = await _check(client, agent, tool="db.drop")
    assert chk["decision"] == "denied" and chk["permit"] is None


@pytest.mark.asyncio
async def test_redeemed_once_for_exactly_the_checked_tool_and_input(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    chk = await _check(client, agent)
    permit = chk["permit"]
    # another tool or another input: refused, and the permit stays unused
    r = await _redeem(client, permit, tool="db.write", input_sha256=content_hash(INPUT))
    assert r.status_code == 403 and r.json()["detail"] == "permit.mismatch"
    r = await _redeem(client, permit, tool="db.read", input_sha256=content_hash({"query": "drop"}))
    assert r.status_code == 403
    r = await _redeem(client, permit, tool="db.read", input_sha256=content_hash(INPUT))
    assert r.status_code == 200, r.text
    assert r.json()["agent_id"] == agent["id"] and r.json()["tool"] == "db.read"
    r = await _redeem(client, permit, tool="db.read", input_sha256=content_hash(INPUT))
    assert r.status_code == 409 and r.json()["detail"] == "permit.redeemed"

    # the check the record will consume shows the permit and its redemption
    row = (await db_session.execute(select(ActionCheck).where(ActionCheck.token == chk["check_id"]))).scalar_one()
    await db_session.refresh(row)
    view = PVPOrchestrator.check_out(row)
    assert view.permit is None and view.permit_id == parts(permit)[1]["jti"] and view.permit_redeemed_at


@pytest.mark.asyncio
async def test_forged_tampered_and_expired_permits_are_refused(client, admin_token, monkeypatch):
    agent = await _agent(client, admin_token)
    permit = (await _check(client, agent))["permit"]
    h, c, s = permit.split(".")
    claims = json.loads(_b64(c))
    claims["aud"] = "db.write"
    forged_claims = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    for bad in (f"{h}.{forged_claims}.{s}", f"{h}.{c}.{s[:-4]}AAAA", "not.a.permit", "x" * 5000, permit + ".x"):
        r = await _redeem(client, bad)
        assert r.status_code in (400, 422), (bad[:40], r.text)

    real = datetime

    class Later(real):
        @classmethod
        def now(cls, tz=None):
            return real.now(tz) + timedelta(minutes=10)

    monkeypatch.setattr(permits, "datetime", Later)
    r = await _redeem(client, permit)
    assert r.status_code == 401 and r.json()["detail"] == "permit.expired"


@pytest.mark.asyncio
async def test_rotation_keeps_the_old_key_for_permits_in_flight(client, admin_token, approver_token, db_session):
    agent = await _agent(client, admin_token)
    old = (await _check(client, agent))["permit"]
    old_kid = parts(old)[0]["kid"]
    assert (await client.post(f"{PERMITS}/keys/rotate", headers=auth_headers(approver_token))).status_code == 403
    r = await client.post(f"{PERMITS}/keys/rotate", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["kid"] != old_kid
    new = (await _check(client, agent))["permit"]
    assert parts(new)[0]["kid"] == r.json()["kid"]
    slug = await _slug(db_session, agent["id"])
    kids = [k["kid"] for k in (await client.get(f"{PERMITS}/{slug}/jwks.json")).json()["keys"]]
    assert kids[0] == r.json()["kid"] and old_kid in kids
    assert (await _redeem(client, old)).status_code == 200      # signed before the rotation, still good


def test_permits_live_shorter_than_the_key_grace():
    from app.services.agent_audit import CHECK_TTL_SECONDS

    assert timedelta(seconds=CHECK_TTL_SECONDS) < permits.KEY_GRACE


@pytest.mark.asyncio
async def test_a_permit_dies_with_its_agent(client, admin_token, db_session):
    from sqlalchemy import update

    from app.models.agent import Agent

    agent = await _agent(client, admin_token)
    permit = (await _check(client, agent))["permit"]
    await db_session.execute(update(Agent).where(Agent.id == agent["id"]).values(status="suspended"))
    await db_session.commit()
    r = await _redeem(client, permit)
    assert r.status_code == 403 and r.json()["detail"] == "permit.agent_inactive"
