# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Enforce mode (docs/pvp/edge.md, section 4; app/pvp/enforcement.py): no action
runs without the agent's own signature and an enforcement point's judgement
under the signed policy. This server's gateways execute nothing, the REST
check-then-act path only observes, an egress proxy takes part only when it
enforces the signed policy itself and brings the agent's signed request, and
an action a proxy reports without both signatures is a critical incident.
"""

import base64
import json
import secrets
import time

import pytest
from sqlalchemy import select

from app.core.agent_signing import content_hash, sign_payload
from app.models.agent_action import ActionCheck, AgentAction, AgentIncident
from app.pvp import enforcement, signed_policy
from app.pvp.model import PVPActionRequest
from tests.conftest import auth_headers
from tests.test_egress_proxy import _px, _setup, charge
from tests.test_policy_release import _release
from tests.test_proxy_actions import META, _llm
from tests.test_proxy_actions import _agent as _tool_agent
from tests.test_proxy_actions import _tool
from tests.test_proxy_witness import ProxyKey
from tests.test_sealed_credentials import _proxy

R = "/api/v1/policy-releases"
P = "/api/v1/egress-proxy"
CHECK = "/api/v1/agents/actions/check"
ENFORCING = {enforcement.PROXY_MODE_HEADER: "enforce"}


@pytest.fixture(autouse=True)
def _fresh_cache():
    signed_policy.forget()
    yield
    signed_policy.forget()


async def _mode(client, token, mode="enforce"):
    r = await client.put(f"{R}/settings", json={"quorum": 1, "validity_days": 90, "offline_seconds": 900,
                                                "enforcement": mode}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def signed_request(agent, route, desc, **over):
    """The agent's signed request for a request to the proxy, as the SDKs and
    the proxy's agent mode send it (X-Provenza-Request)."""
    fields = {"agent_id": agent["id"], "chain_id": None, "action_type": "proxy", "tool_name": "proxy." + route,
              "input": desc, "nonce": secrets.token_hex(16), "issued_at": int(time.time()), **over}
    payload = PVPActionRequest(**fields).signed_payload()
    return _b64({"payload": payload, "signature": sign_payload(payload, agent["private_key"]),
                 "public_key": agent.get("public_key", "")})


def http_request(route, method="POST", path="/", body=b"{}"):
    import hashlib

    return {"route": route, "method": method, "path": path, "query_sha256": None,
            "body_sha256": hashlib.sha256(body).hexdigest(), "body_bytes": len(body)}


# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_mode_is_part_of_the_signed_policy(client, admin_token, db_session, org_and_users):
    from app.services.policy_release import working_copy

    st = (await client.get(f"{R}/state", headers=auth_headers(admin_token))).json()
    assert st["settings"]["enforcement"] == "observe"
    org_id = org_and_users["org"].id
    bundle = (await working_copy(db_session, org_id))[0]
    assert "enforcement" not in bundle            # observe: releases made before enforce mode are unchanged
    assert (await _mode(client, admin_token))["enforcement"] == "enforce"
    bundle = (await working_copy(db_session, org_id))[0]
    assert bundle["enforcement"] == {"mode": "enforce"}
    # a PUT without it keeps it; anything else is refused
    r = await client.put(f"{R}/settings", json={"quorum": 1, "validity_days": 90, "offline_seconds": 900},
                         headers=auth_headers(admin_token))
    assert r.json()["enforcement"] == "enforce"
    r = await client.put(f"{R}/settings", json={"quorum": 1, "validity_days": 90, "offline_seconds": 900,
                                                "enforcement": "strict"}, headers=auth_headers(admin_token))
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_turning_it_off_needs_a_signed_release(client, admin_token, db_session, org_and_users):
    await _mode(client, admin_token)
    await _release(client, admin_token)           # the release in force says enforce
    await _mode(client, admin_token, "observe")   # the working copy alone does not loosen it
    assert await enforcement.enforced(db_session, org_and_users["org"].id) is True


@pytest.mark.asyncio
async def test_the_rest_path_only_observes(client, admin_token, db_session):
    _, _, agent = await _setup(client, admin_token)
    before = await client.post(CHECK, json={"agent_id": agent["id"], "action_type": "proxy",
                                            "tool_name": "proxy.stripe", "input": charge()},
                               headers={"X-Agent-Key": agent["api_key"]})
    assert before.json()["decision"] == "allowed" and before.json()["permit"]
    await _mode(client, admin_token)
    r = await client.post(CHECK, json={"agent_id": agent["id"], "action_type": "proxy",
                                       "tool_name": "proxy.stripe", "input": charge()},
                          headers={"X-Agent-Key": agent["api_key"]})
    chk = r.json()
    assert chk["decision"] == "allowed" and chk["permit"] is None
    assert chk["reason"].endswith(enforcement.OBSERVATION)
    row = (await db_session.execute(select(ActionCheck).where(ActionCheck.token == chk["check_id"]))).scalar_one()
    assert row.agent_signed is True               # the agent signed its check (the conftest client signs it)


@pytest.mark.asyncio
async def test_this_servers_gateways_execute_nothing(client, admin_token, db_session):
    await _tool(client, admin_token, db_session, source="none")
    agent = await _tool_agent(client, admin_token)
    await _mode(client, admin_token)
    headers = {"X-Agent-Key": agent["api_key"]}
    body = client._signed({"agent_id": agent["id"], "tool_name": "crm.set_tier",
                           "input": {"id": "c/42", "tier": "gold"}}, headers)
    r = await client.post("/api/v1/http-tools/call", json=body, headers=headers)
    out = r.json()
    assert out["decision"] == "denied" and enforcement.REFUSAL in out["reason"], out
    action = await db_session.get(AgentAction, out["action_id"])
    assert action.executed_by == "http_gateway" and action.output_data is None


@pytest.mark.asyncio
async def test_a_proxy_takes_part_only_when_it_enforces_the_signed_policy(client, admin_token):
    _, proxy, agent = await _setup(client, admin_token)
    await _mode(client, admin_token)
    headers = {**_px(proxy), "X-Agent-Key": agent["api_key"]}
    r = await client.post(f"{P}/check", json=charge(), headers=headers)
    assert r.status_code == 403 and r.json()["detail"] == "enforcement.proxy_not_enforcing"
    r = await client.post(f"{P}/check-info", json={"check_id": "x" * 20}, headers=_px(proxy))
    assert r.status_code == 403
    # an enforcing proxy without the agent's signed request: the agent's key alone is not enough
    r = await client.post(f"{P}/check", json=charge(), headers={**headers, **ENFORCING})
    assert r.status_code == 401 and r.json()["detail"] == "enforcement.agent_signature_required"


@pytest.mark.asyncio
async def test_a_mediated_check_with_the_agents_signed_request(client, admin_token, db_session):
    _, proxy, agent = await _setup(client, admin_token)
    await _mode(client, admin_token)
    sr = signed_request(agent, "stripe", charge())
    headers = {**_px(proxy), **ENFORCING, "X-Agent-Key": agent["api_key"], enforcement.REQUEST_HEADER: sr}
    r = await client.post(f"{P}/check", json=charge(), headers=headers)
    assert r.status_code == 200, r.text
    chk = r.json()
    assert chk["decision"] == "allowed"
    row = (await db_session.execute(select(ActionCheck).where(ActionCheck.token == chk["check_id"]))).scalar_one()
    assert row.agent_signed is True
    # the same signed request again, or one for another request
    assert (await client.post(f"{P}/check", json=charge(), headers=headers)).status_code == 409
    other = {**headers, enforcement.REQUEST_HEADER: signed_request(agent, "stripe", charge(body_bytes=1))}
    r = await client.post(f"{P}/check", json=charge(), headers=other)
    assert r.status_code == 403 and r.json()["detail"] == "enforcement.not_the_signed_request"
    red = await client.post(f"{P}/redeem", json={"check_id": chk["check_id"], **charge()},
                            headers={**_px(proxy), **ENFORCING})
    assert red.status_code == 200 and red.json()["allowed"] is True, red.text


@pytest.mark.asyncio
async def test_a_check_the_agent_did_not_sign_is_not_redeemed(client, admin_token, db_session):
    _, proxy, agent = await _setup(client, admin_token)
    # mediated, before enforce mode: the proxy checked with the agent's key alone
    chk = (await client.post(f"{P}/check", json=charge(),
                             headers={**_px(proxy), "X-Agent-Key": agent["api_key"]})).json()
    assert chk["decision"] == "allowed"
    await _mode(client, admin_token)
    red = (await client.post(f"{P}/redeem", json={"check_id": chk["check_id"], **charge()},
                             headers={**_px(proxy), **ENFORCING})).json()
    assert red["allowed"] is False and "did not sign" in red["reason"]
    action = await db_session.get(AgentAction, red["action_id"])
    assert action.policy_check_result == "denied"


async def _llm_plan(client, proxy, agent, **headers):
    return await client.post(f"{P}/llm/plan", json=META,
                             headers={**proxy.headers, "X-Agent-Key": agent["api_key"], **ENFORCING, **headers})


@pytest.mark.asyncio
async def test_a_gateway_action_at_a_proxy_needs_the_signed_request(client, admin_token, db_session):
    proxy = await _proxy(client, admin_token)
    _, agent = await _llm(client, admin_token, db_session)
    await _mode(client, admin_token)
    r = await _llm_plan(client, proxy, agent)
    assert r.status_code == 401 and r.json()["detail"] == "enforcement.agent_signature_required"
    desc = http_request("_llm", path="/v1/chat/completions")
    wrong = http_request("_mcp")
    r = await _llm_plan(client, proxy, agent, **{enforcement.REQUEST_HEADER: signed_request(agent, "_mcp", wrong),
                                                 enforcement.DESCRIPTOR_HEADER: _b64(wrong)})
    assert r.status_code == 403 and r.json()["detail"] == "enforcement.not_the_signed_request"
    r = await _llm_plan(client, proxy, agent, **{enforcement.REQUEST_HEADER: signed_request(agent, "_llm", desc),
                                                 enforcement.DESCRIPTOR_HEADER: _b64(http_request("_llm"))})
    assert r.status_code == 403                    # signed for another request than the one described
    sr = signed_request(agent, "_llm", desc)
    ok = {enforcement.REQUEST_HEADER: sr, enforcement.DESCRIPTOR_HEADER: _b64(desc)}
    plan = (await _llm_plan(client, proxy, agent, **ok)).json()
    assert plan["decision"] == "allowed", plan
    row = (await db_session.execute(select(ActionCheck).where(ActionCheck.token == plan["check_id"]))).scalar_one()
    assert row.agent_signed is True
    assert (await _llm_plan(client, proxy, agent, **ok)).status_code == 409      # once


@pytest.mark.asyncio
async def test_an_action_reported_without_both_signatures_is_an_incident(client, admin_token, db_session):
    proxy = await _proxy(client, admin_token)
    _, agent = await _llm(client, admin_token, db_session)
    await _mode(client, admin_token)
    rel = (await _release(client, admin_token))["in_force"]
    key = ProxyKey()
    key.key, key.public = proxy.signing, proxy.public

    async def plan():
        desc = http_request("_llm", path="/v1/chat/completions")
        out = (await _llm_plan(client, proxy, agent, **{
            enforcement.REQUEST_HEADER: signed_request(agent, "_llm", desc),
            enforcement.DESCRIPTOR_HEADER: _b64(desc)})).json()
        assert out["decision"] == "allowed", out
        return out

    output = {"finish_reason": "stop", "prompt_tokens": 1, "completion_tokens": 1, "response_sha256": "d" * 64}

    async def complete(p, **receipt_fields):
        receipt = None
        if receipt_fields:
            receipt = key.receipt(check_id=p["check_id"], agent_id=agent["id"], chain_id=None,
                                  action_type=p["action_type"], tool_name=p["tool_name"],
                                  input_sha256=p["input_sha256"], output_sha256=content_hash(output),
                                  decision="allowed", **receipt_fields)
        r = await client.post(f"{P}/complete", json={"check_id": p["check_id"], "status": 200, "output": output,
                                                     **({"receipt": receipt} if receipt else {})},
                              headers={**proxy.headers, **ENFORCING})
        assert r.status_code == 200, r.text
        return (await db_session.execute(select(AgentIncident).where(
            AgentIncident.incident_type == "unenforced_action",
            AgentIncident.details["check_id"].astext == str((await db_session.execute(select(ActionCheck.id).where(
                ActionCheck.token == p["check_id"]))).scalar_one())))).scalars().all()

    policy = {"release": rel["number"], "bundle_sha256": rel["bundle"]["sha256"]}
    assert len(await complete(await plan())) == 1                                  # no receipt
    assert len(await complete(await plan(), policy=None, agent_signature="verified")) == 1
    assert len(await complete(await plan(), policy=policy, agent_signature="not_presented")) == 1
    forged = {"release": rel["number"], "bundle_sha256": "0" * 64}
    [incident] = await complete(await plan(), policy=forged, agent_signature="verified")
    assert incident.severity == "critical" and "never signed" in incident.details["reason"]
    assert await complete(await plan(), policy=policy, agent_signature="verified") == []


def test_the_card_digests_an_enforcing_proxy_computes_are_the_servers():
    """sdk/testdata/enforce-vectors.json, checked by proxy/internal/egress too."""
    from pathlib import Path

    from app.pvp.a2a_wire import pinned_card
    from app.services.supply_chain import manifest_digest

    v = json.loads((Path(__file__).resolve().parents[2] / "sdk" / "testdata" / "enforce-vectors.json").read_text())
    for c in v["a2a_cards"]:
        assert manifest_digest(pinned_card(c["card"])) == c["digest"]
