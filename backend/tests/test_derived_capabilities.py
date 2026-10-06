# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Rights are computed by the server, never declared by the caller
(services/agent_rights.py):

  - an action needs what the Tool Registry says the tool requires;
    a request that declares capabilities is refused;
  - inside a chain an agent holds what its incoming hop delegated, capped
    by its own registration; tools narrow along the chain like capabilities;
  - only members of a chain (its root, or agents reached by a hop) can act
    or delegate in it; depth counts from the delegating agent's own hop;
  - inactive agents can neither delegate nor receive; a grant that expired
    cannot be passed on.
"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import select

from app.models.agent_action import AgentIncident
from app.models.tool_registry import ToolRegistryEntry
from app.schemas.agent import AgentCreate
from app.services.agent_registry import AgentRegistry
from app.services.delegation_service import DelegationService
from tests.conftest import auth_headers

CHECK = "/api/v1/agents/actions/check"


@pytest_asyncio.fixture
async def ag(db_session, org_and_users):
    org = org_and_users["org"]
    reg = AgentRegistry(db_session)

    async def make(name, caps, tools, depth=3):
        a, _, _ = await reg.register(org.id, None, AgentCreate(
            name=name, capabilities=caps, allowed_tools=tools, max_delegation_depth=depth))
        return a

    return {
        "org": org,
        "root": await make("root", ["read", "write", "payments"], ["files.read", "files.write", "stripe.charge"]),
        "mid": await make("mid", ["read", "write", "payments"], ["files.read", "files.write", "stripe.charge"]),
        "leaf": await make("leaf", ["read"], ["files.read", "files.write"]),
        "outsider": await make("outsider", ["read", "write", "payments"], ["files.read", "files.write", "stripe.charge"]),
    }


def _svc(db):
    return DelegationService(db)


async def _delegate(db, org, frm, to, caps, chain_id=None, tools=None, expires_at=None):
    return await _svc(db).delegate(org_id=org.id, from_agent_id=frm.id, to_agent_id=to.id, task="t",
                                   delegated_capabilities=caps, signature=None, chain_id=chain_id,
                                   delegated_tools=tools, expires_at=expires_at)


async def _check(client, token, agent, tool, chain_id=None, **extra):
    body = {"agent_id": agent.id, "tool_name": tool, **extra}
    if chain_id is not None:
        body["chain_id"] = chain_id
    return await client.post(CHECK, json=body, headers=auth_headers(token))


# --- declared capabilities ---------------------------------------------------------

async def test_declared_capabilities_are_refused(client, admin_token, ag):
    r = await _check(client, admin_token, ag["root"], "files.read", action_capabilities=["read"])
    assert r.status_code == 422
    assert "no longer accepted" in r.text


async def test_tool_registry_decides_what_an_action_needs(client, db_session, admin_token, ag):
    org = ag["org"]
    db_session.add(ToolRegistryEntry(org_id=org.id, pattern="stripe.*", kind="tool", status="approved",
                                     required_capabilities=["payments"]))
    await db_session.flush()
    # root holds "payments": allowed
    r = await _check(client, admin_token, ag["root"], "stripe.charge")
    assert r.json()["decision"] == "allowed", r.text
    # mid receives only read: the tool is still in its tools, the capability is not
    chain, _ = await _delegate(db_session, org, ag["root"], ag["mid"], ["read"])
    r = await _check(client, admin_token, ag["mid"], "stripe.charge", chain.id)
    d = r.json()
    assert d["decision"] == "denied" and d["incident_type"] == "capability_escalation"


# --- membership and depth ------------------------------------------------------------

async def test_an_outsider_cannot_delegate_into_a_chain(db_session, ag):
    org = ag["org"]
    chain, _ = await _delegate(db_session, org, ag["root"], ag["mid"], ["read"])
    with pytest.raises(HTTPException) as e:
        await _delegate(db_session, org, ag["outsider"], ag["leaf"], ["read"], chain.id)
    assert e.value.status_code == 403 and "not_in_chain" in e.value.detail
    inc = (await db_session.execute(select(AgentIncident).where(
        AgentIncident.chain_id == chain.id, AgentIncident.incident_type == "not_in_chain"))).scalar_one_or_none()
    assert inc is not None


async def test_an_outsider_cannot_act_in_a_chain(client, db_session, admin_token, ag):
    chain, _ = await _delegate(db_session, ag["org"], ag["root"], ag["mid"], ["read"])
    r = await _check(client, admin_token, ag["outsider"], "files.read", chain.id)
    assert r.json()["decision"] == "denied" and r.json()["incident_type"] == "not_in_chain"


async def test_depth_counts_from_the_delegating_agents_own_hop(db_session, org_and_users):
    org = org_and_users["org"]
    reg = AgentRegistry(db_session)
    a, _, _ = await reg.register(org.id, None, AgentCreate(name="a", capabilities=["read"], max_delegation_depth=1))
    b, _, _ = await reg.register(org.id, None, AgentCreate(name="b", capabilities=["read"], max_delegation_depth=1))
    c, _, _ = await reg.register(org.id, None, AgentCreate(name="c", capabilities=["read"], max_delegation_depth=1))
    chain, _ = await _delegate(db_session, org, a, b, ["read"])
    # the root delegating again in the same chain is still depth 1 (used to count as 2)
    _, hop = await _delegate(db_session, org, a, c, ["read"], chain.id)
    assert hop.depth == 1


async def test_the_roots_depth_limit_binds_the_whole_chain(db_session, org_and_users):
    org = org_and_users["org"]
    reg = AgentRegistry(db_session)
    a, _, _ = await reg.register(org.id, None, AgentCreate(name="a", capabilities=["read"], max_delegation_depth=1))
    b, _, _ = await reg.register(org.id, None, AgentCreate(name="b", capabilities=["read"], max_delegation_depth=5))
    c, _, _ = await reg.register(org.id, None, AgentCreate(name="c", capabilities=["read"], max_delegation_depth=5))
    chain, _ = await _delegate(db_session, org, a, b, ["read"])
    with pytest.raises(HTTPException) as e:
        await _delegate(db_session, org, b, c, ["read"], chain.id)
    assert e.value.status_code == 403


# --- narrowing ------------------------------------------------------------------------

async def test_tools_narrow_along_the_chain(client, db_session, admin_token, ag):
    org = ag["org"]
    chain, _ = await _delegate(db_session, org, ag["root"], ag["mid"], ["read"], tools=["files.read"])
    assert (await _check(client, admin_token, ag["mid"], "files.read", chain.id)).json()["decision"] == "allowed"
    # files.write is in mid's own registration, but was not delegated to it in this chain
    r = await _check(client, admin_token, ag["mid"], "files.write", chain.id)
    assert r.json()["decision"] == "denied"
    # and it cannot pass on what it did not receive
    with pytest.raises(HTTPException) as e:
        await _delegate(db_session, org, ag["mid"], ag["leaf"], ["read"], chain.id, tools=["files.write"])
    assert e.value.status_code == 403


async def test_tools_not_named_are_inherited_never_widened(db_session, ag):
    org = ag["org"]
    chain, _ = await _delegate(db_session, org, ag["root"], ag["mid"], ["read"], tools=["files.read"])
    _, hop = await _delegate(db_session, org, ag["mid"], ag["leaf"], ["read"], chain.id)
    assert hop.delegated_tools == ["files.read"]


async def test_a_grant_is_capped_by_the_receivers_registration(client, db_session, admin_token, ag):
    from app.services.agent_rights import hop_rights

    org = ag["org"]
    _, hop = await _delegate(db_session, org, ag["root"], ag["leaf"], ["read", "write"])
    r = hop_rights(ag["leaf"], hop)
    assert r.capabilities == ["read"]          # leaf was never registered with "write"
    assert "stripe.charge" not in r.tools      # nor with that tool


# --- status and expiry ----------------------------------------------------------------

async def test_inactive_agents_neither_delegate_nor_receive(db_session, ag):
    org = ag["org"]
    ag["leaf"].status = "suspended"
    await db_session.flush()
    with pytest.raises(HTTPException) as e:
        await _delegate(db_session, org, ag["root"], ag["leaf"], ["read"])
    assert e.value.status_code == 409
    with pytest.raises(HTTPException) as e:
        await _delegate(db_session, org, ag["leaf"], ag["root"], ["read"])
    assert e.value.status_code == 409


async def test_no_delegation_to_oneself(db_session, ag):
    with pytest.raises(HTTPException) as e:
        await _delegate(db_session, ag["org"], ag["root"], ag["root"], ["read"])
    assert e.value.status_code == 400


async def test_an_expired_grant_cannot_be_passed_on(db_session, ag):
    org = ag["org"]
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    chain, _ = await _delegate(db_session, org, ag["root"], ag["mid"], ["read"], expires_at=past)
    with pytest.raises(HTTPException) as e:
        await _delegate(db_session, org, ag["mid"], ag["leaf"], ["read"], chain.id)
    assert e.value.status_code == 403 and "expired" in e.value.detail


async def test_signed_delegation_of_tools_over_the_api(client, db_session, org_and_users, admin_token):
    from tests.delegation_helpers import delegation_body

    org = org_and_users["org"]
    reg = AgentRegistry(db_session)
    root, _, priv = await reg.register(org.id, None, AgentCreate(
        name="r", capabilities=["read", "write"], allowed_tools=["files.read", "files.write"]))
    leaf, _, _ = await reg.register(org.id, None, AgentCreate(
        name="l", capabilities=["read"], allowed_tools=["files.read", "files.write"]))
    body = delegation_body({"id": root.id, "private_key": priv}, leaf.id, "t", ["read", "write"],
                           tools=["files.read"])
    r = await client.post(f"/api/v1/agents/{root.id}/delegate", json=body, headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["verified"] is True
    assert d["effective_capabilities"] == ["read"] and d["effective_tools"] == ["files.read"]

    # the tools are part of what was signed: changing them breaks the signature
    body2 = delegation_body({"id": root.id, "private_key": priv}, leaf.id, "t", ["read"], tools=["files.read"])
    body2["delegated_tools"] = ["files.read", "files.write"]
    r = await client.post(f"/api/v1/agents/{root.id}/delegate", json=body2, headers=auth_headers(admin_token))
    assert r.status_code == 400


async def test_an_exact_entry_does_not_shadow_a_glob_that_requires_more(client, db_session, admin_token, ag):
    org = ag["org"]
    # first use auto-registers "stripe.refund" (requires nothing); later an admin adds "stripe.*"
    db_session.add(ToolRegistryEntry(org_id=org.id, pattern="stripe.refund", kind="tool", status="approved"))
    db_session.add(ToolRegistryEntry(org_id=org.id, pattern="stripe.*", kind="tool", status="approved",
                                     required_capabilities=["payments"]))
    ag["leaf"].allowed_tools = ["stripe.refund"]
    await db_session.flush()
    r = await _check(client, admin_token, ag["leaf"], "stripe.refund")
    assert r.json()["decision"] == "denied" and r.json()["incident_type"] == "capability_escalation"


async def test_an_orchestrator_without_tools_still_delegates_to_workers(client, db_session, admin_token, org_and_users):
    """Nobody named tools: each agent keeps its own; capabilities stay the boundary."""
    org = org_and_users["org"]
    reg = AgentRegistry(db_session)
    boss, _, _ = await reg.register(org.id, None, AgentCreate(name="boss", capabilities=["read"]))
    worker, _, _ = await reg.register(org.id, None, AgentCreate(name="w", capabilities=["read"],
                                                                allowed_tools=["files.read"]))
    chain, hop = await _delegate(db_session, org, boss, worker, ["read"])
    assert hop.delegated_tools is None
    assert (await _check(client, admin_token, worker, "files.read", chain.id)).json()["decision"] == "allowed"


async def test_a_deep_agent_may_act_where_it_was_legitimately_placed(client, db_session, admin_token, org_and_users):
    org = org_and_users["org"]
    reg = AgentRegistry(db_session)
    a, _, _ = await reg.register(org.id, None, AgentCreate(name="a", capabilities=["read"], max_delegation_depth=3,
                                                           allowed_tools=["files.read"]))
    b, _, _ = await reg.register(org.id, None, AgentCreate(name="b", capabilities=["read"], max_delegation_depth=3,
                                                           allowed_tools=["files.read"]))
    c, _, _ = await reg.register(org.id, None, AgentCreate(name="c", capabilities=["read"], max_delegation_depth=1,
                                                           allowed_tools=["files.read"]))
    chain, _ = await _delegate(db_session, org, a, b, ["read"])
    await _delegate(db_session, org, b, c, ["read"], chain.id)
    # c's own limit (1) concerns what IT may delegate, not where it may act
    assert (await _check(client, admin_token, c, "files.read", chain.id)).json()["decision"] == "allowed"


async def test_a_new_grant_replaces_an_expired_one(db_session, ag):
    org = ag["org"]
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    chain, _ = await _delegate(db_session, org, ag["root"], ag["mid"], ["read"], expires_at=past)
    await _delegate(db_session, org, ag["root"], ag["mid"], ["read"], chain.id)  # fresh, open-ended grant
    _, hop = await _delegate(db_session, org, ag["mid"], ag["leaf"], ["read"], chain.id)
    assert hop.depth == 2
