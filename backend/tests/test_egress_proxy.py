# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress proxy, server side (app/pvp/egress_proxy.py, app/api/egress_proxy.py):
routes and proxy keys, the route rules in checks, redeem / complete, and every
way a proxy request can be refused.
"""

import hashlib
import importlib.util
import secrets
from pathlib import Path

import pytest
from sqlalchemy import select

from app.models.agent_action import AgentAction, AgentIncident
from app.pvp.egress_proxy import descriptor, path_problem
from tests.conftest import _create_org_with_admin_and_approver, _login, auth_headers

E = "/api/v1/egress"
P = "/api/v1/egress-proxy"
CHECK = "/api/v1/agents/actions/check"
SECRET = "Bearer sk_live_" + "x" * 24
ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("provenza_audit_tool_egress", ROOT / "tools" / "provenza_audit.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


BODY = b'{"amount":1000,"currency":"usd"}'


def charge(**over):
    d = descriptor("stripe", "POST", "/v1/charges", None, sha(BODY), len(BODY))
    d.update(over)
    return d


async def _setup(client, token, *, tools=("proxy.stripe",), **route):
    r = await client.post(f"{E}/routes", json={
        "slug": "stripe", "name": "Stripe", "upstream_url": "https://api.stripe.com",
        "methods": ["GET", "POST"], "path_prefixes": ["/v1/charges", "/v1/customers"],
        "credential_source": "local", **route}, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    p = await client.post(f"{E}/proxies", json={"name": "billing-host"}, headers=auth_headers(token))
    assert p.status_code == 200, p.text
    a = await client.post("/api/v1/agents/register", json={
        "name": "egp-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["pay"],
        "allowed_tools": list(tools), "allowed_models": [], "max_delegation_depth": 2}, headers=auth_headers(token))
    assert a.status_code == 200, a.text
    return r.json(), p.json(), a.json()


async def _check(client, agent, desc, tool_name=None, action_type="proxy"):
    r = await client.post(CHECK, json={"agent_id": agent["id"], "action_type": action_type,
                                       "tool_name": tool_name or f"proxy.{desc['route']}", "input": desc},
                          headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200, r.text
    return r.json()


def _px(proxy):
    return {"X-Proxy-Key": proxy["key"]}


async def _redeem(client, proxy, check_id, desc):
    return await client.post(f"{P}/redeem", json={"check_id": check_id, **desc}, headers=_px(proxy))


# ---------------------------------------------------------------------------

def test_path_rules():
    assert path_problem("/v1/charges") is None
    for bad in ("v1/charges", "/v1/../admin", "/v1/%2e%2e/admin", "/v1/./x", "/v1/a%2Fb", "/v1/a%5cb"):
        assert path_problem(bad), bad


@pytest.mark.asyncio
async def test_the_whole_way(client, admin_token, db_session):
    route, proxy, agent = await _setup(client, admin_token)
    assert route["tool_name"] == "proxy.stripe" and route["has_secret"] and route["credential"]["source"] == "local"
    assert proxy["key"].startswith("pvz_proxy_")

    cfg = await client.get(f"{P}/config", headers=_px(proxy))
    assert cfg.status_code == 200, cfg.text
    [r] = cfg.json()["routes"]
    # never a credential: a sealed one comes as an envelope only the proxy opens (test_sealed_credentials.py)
    assert "secret" not in r and r["upstream_url"] == "https://api.stripe.com"

    chk = await _check(client, agent, charge())
    assert chk["decision"] == "allowed", chk
    red = await _redeem(client, proxy, chk["check_id"], charge())
    assert red.status_code == 200 and red.json()["allowed"] is True, red.text
    # reserved: the agent cannot record it itself, nor redeem it twice
    assert (await _redeem(client, proxy, chk["check_id"], charge())).status_code == 409

    done = await client.post(f"{P}/complete", json={"check_id": chk["check_id"], "status": 200,
                                                    "response_sha256": "b" * 64, "response_bytes": 512,
                                                    "duration_ms": 87}, headers=_px(proxy))
    assert done.status_code == 200, done.text
    action = await db_session.get(AgentAction, done.json()["action_id"])
    assert (action.tool_name, action.action_type, action.policy_check_result, action.executed_by) == (
        "proxy.stripe", "proxy", "allowed", "egress_proxy")
    assert action.output_data == {"status": 200, "response_sha256": "b" * 64, "response_bytes": 512}
    assert (await client.post(f"{P}/complete", json={"check_id": chk["check_id"], "status": 200},
                              headers=_px(proxy))).status_code == 409

    receipt = (await client.get(f"/api/v1/pvp/receipts/{action.id}", headers=auth_headers(admin_token))).json()
    a, _, _ = tool.check_receipt(receipt, tool.Trust())
    assert a["executed_by"] == "egress_proxy"
    open_ = (await client.get(f"{E}/redemptions", params={"open": True}, headers=auth_headers(admin_token))).json()
    assert open_ == []


@pytest.mark.asyncio
async def test_the_route_decides_what_reaches_the_upstream(client, admin_token):
    _, _, agent = await _setup(client, admin_token, max_body_bytes=100)
    for desc, why in [(charge(method="DELETE"), "method"), (charge(path="/v1/refunds"), "outside"),
                      (charge(path="/v1/charges/../../admin"), "segment"), (charge(body_bytes=101), "larger"),
                      (charge(route="nope"), "does not exist")]:
        chk = await _check(client, agent, desc)
        assert chk["decision"] == "denied" and why in chk["reason"], (desc, chk)
    # tool name and route must agree; the descriptor has exactly its fields
    assert (await _check(client, agent, charge(), tool_name="proxy.other"))["decision"] == "denied"
    assert (await _check(client, agent, {**charge(), "extra": 1}))["decision"] == "denied"


@pytest.mark.asyncio
async def test_rights_still_apply_and_a_refusal_is_recorded_at_redeem(client, admin_token, db_session):
    _, proxy, agent = await _setup(client, admin_token, tools=("db.read",))     # no proxy.stripe right
    chk = await _check(client, agent, charge())
    assert chk["decision"] == "denied"
    red = (await _redeem(client, proxy, chk["check_id"], charge())).json()
    assert red["allowed"] is False and red["action_id"]
    action = await db_session.get(AgentAction, red["action_id"])
    assert action.policy_check_result == "denied" and action.executed_by == "egress_proxy"


@pytest.mark.asyncio
async def test_a_request_other_than_the_checked_one_is_refused_and_burns_the_check(client, admin_token, db_session):
    _, proxy, agent = await _setup(client, admin_token)
    chk = await _check(client, agent, charge())
    # checked 1000 USD, the proxy is about to send another body
    other = charge(body_sha256=sha(b'{"amount":999999}'))
    r = await _redeem(client, proxy, chk["check_id"], other)
    assert r.status_code == 400 and r.json()["detail"] == "egress.request_mismatch"
    assert (await _redeem(client, proxy, chk["check_id"], charge())).status_code == 409   # burned
    inc = (await db_session.execute(select(AgentIncident).where(
        AgentIncident.agent_id == agent["id"], AgentIncident.incident_type == "action_mismatch"))).scalars().all()
    assert inc


@pytest.mark.asyncio
async def test_only_proxy_checks_can_be_redeemed(client, admin_token):
    _, proxy, agent = await _setup(client, admin_token, tools=("proxy.stripe", "db.read"))
    chk = await _check(client, agent, {"q": "select 1"}, tool_name="db.read", action_type="tool_call")
    r = await _redeem(client, proxy, chk["check_id"], charge())
    assert r.status_code == 400 and r.json()["detail"] == "egress.request_mismatch"


@pytest.mark.asyncio
async def test_proxy_keys(client, admin_token, approver_token, db_session):
    _, proxy, agent = await _setup(client, admin_token)
    assert (await client.get(f"{P}/config")).status_code == 401
    assert (await client.get(f"{P}/config", headers={"X-Proxy-Key": "pvz_proxy_wrong"})).status_code == 401
    assert (await client.get(f"{E}/proxies", headers=auth_headers(approver_token))).status_code == 403
    listed = await client.get(f"{E}/proxies", headers=auth_headers(admin_token))
    assert proxy["key"] not in listed.text
    r = await client.post(f"{E}/proxies/{proxy['id']}/revoke", headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert (await client.get(f"{P}/config", headers=_px(proxy))).status_code == 401

    # another organization's proxy sees none of these routes, and cannot redeem these checks
    await _create_org_with_admin_and_approver(db_session, org_slug="egress-other", admin_email="a@eg.example.com",
                                              approver_email="b@eg.example.com")
    await db_session.commit()
    other = await _login(client, "egress-other", "a@eg.example.com", "TestPass123!")
    other_proxy = (await client.post(f"{E}/proxies", json={"name": "x"}, headers=auth_headers(other))).json()
    assert (await client.get(f"{P}/config", headers=_px(other_proxy))).json()["routes"] == []
    chk = await _check(client, agent, charge())
    assert (await _redeem(client, other_proxy, chk["check_id"], charge())).status_code == 404


@pytest.mark.asyncio
async def test_route_admin(client, admin_token):
    route, _, _ = await _setup(client, admin_token)
    for bad in ({"upstream_url": "http://169.254.169.254/"}, {"path_prefixes": ["/v1/../x"]},
                {"auth_header": "Host"}, {"methods": []}, {"slug": "Bad Slug"},
                {"credential_source": "local", "secret": "s3cret"}, {"credential_source": "sealed", "secret": "x"}):
        body = {"slug": "x", "name": "x", "upstream_url": "https://api.example.com", **bad}
        assert (await client.post(f"{E}/routes", json=body, headers=auth_headers(admin_token))).status_code == 422, bad
    # a credential is never taken in clear text
    r = await client.patch(f"{E}/routes/{route['id']}", json={"secret": "s3cret"}, headers=auth_headers(admin_token))
    assert r.status_code == 422 and r.json()["detail"] == "credential.plaintext_refused"
    r = await client.patch(f"{E}/routes/{route['id']}", json={"credential_source": "none"},
                           headers=auth_headers(admin_token))
    assert r.status_code == 200 and r.json()["has_secret"] is False


@pytest.mark.asyncio
async def test_mediated_check_needs_the_proxy_and_an_agent_of_its_organization(client, admin_token, db_session):
    _, proxy, agent = await _setup(client, admin_token)
    body = charge()
    # the proxy alone, or a key nobody has, gets nothing
    r = await client.post(f"{P}/check", json=body, headers=_px(proxy))
    assert r.status_code == 401 and r.json()["detail"] == "egress.agent_key_invalid"
    r = await client.post(f"{P}/check", json=body, headers={**_px(proxy), "X-Agent-Key": "pvz_agent_nope"})
    assert r.status_code == 401
    # the agent's key without the proxy's: not this endpoint
    assert (await client.post(f"{P}/check", json=body, headers={"X-Agent-Key": agent["api_key"]})).status_code == 401
    # an agent of another organization, through this organization's proxy
    await _create_org_with_admin_and_approver(db_session, org_slug="egress-med", admin_email="a@med.example.com",
                                              approver_email="b@med.example.com")
    await db_session.commit()
    other = await _login(client, "egress-med", "a@med.example.com", "TestPass123!")
    foreign = (await client.post("/api/v1/agents/register", json={
        "name": "foreign", "agent_type": "custom", "capabilities": [], "allowed_tools": ["proxy.stripe"],
        "allowed_models": [], "max_delegation_depth": 1}, headers=auth_headers(other))).json()
    r = await client.post(f"{P}/check", json=body, headers={**_px(proxy), "X-Agent-Key": foreign["api_key"]})
    assert r.status_code == 401
    # its own agent: a check the proxy then redeems for exactly this request
    r = await client.post(f"{P}/check", json=body, headers={**_px(proxy), "X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200 and r.json()["decision"] == "allowed", r.text
    red = await _redeem(client, proxy, r.json()["check_id"], body)
    assert red.status_code == 200 and red.json()["allowed"] is True
    # a suspended agent: its key still matches, and is refused
    from sqlalchemy import update
    from app.models.agent import Agent
    await db_session.execute(update(Agent).where(Agent.id == agent["id"]).values(status="suspended"))
    await db_session.commit()
    r = await client.post(f"{P}/check", json=body, headers={**_px(proxy), "X-Agent-Key": agent["api_key"]})
    assert r.status_code == 403 and r.json()["detail"] == "egress.agent_inactive"
