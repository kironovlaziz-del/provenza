# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Egress actions (app/pvp/egress.py) - what provenza.auto reports: the AI
domain catalog is the right, the server decides, policies still apply.
"""

import secrets

import pytest
from sqlalchemy import select

from app.models.agent_action import AgentIncident
from app.models.tool_registry import ToolRegistryEntry
from tests.conftest import auth_headers
from tests.delegation_helpers import action_record_body

CHECK = "/api/v1/agents/actions/check"
RECORD = "/api/v1/agents/actions/record"


async def _agent(client, token):
    r = await client.post("/api/v1/agents/register", json={
        "name": "egr-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": ["read"],
        "allowed_tools": ["db.read"], "allowed_models": [], "max_delegation_depth": 2,
    }, headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


def _egress(host, path="/v1/chat/completions"):
    return {"host": host, "method": "POST", "path": path, "body_sha256": "a" * 64, "body_bytes": 120}


async def _check(client, agent, host, tool=None):
    r = await client.post(CHECK, json={"agent_id": agent["id"], "action_type": "egress",
                                       "tool_name": tool or f"egress.{host}", "input": _egress(host)},
                          headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200, r.text
    return r.json()


async def _catalog_entry(client, token, domain, status):
    r = await client.post("/api/v1/domain-catalog/", json={"domain": domain, "policy_status": status},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_catalog_for_agents(client, admin_token):
    agent = await _agent(client, admin_token)
    await _catalog_entry(client, admin_token, "deepseek.com", "blocked")
    r = await client.get("/api/v1/pvp/egress-catalog", headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200, r.text
    domains = {d["domain"]: d["status"] for d in r.json()["domains"]}
    assert domains["deepseek.com"] == "blocked"                 # the organization's decision wins
    assert domains["generativelanguage.googleapis.com"] == "unknown"   # a built-in hint
    assert not any("/" in d for d in domains)                   # hosts only


@pytest.mark.asyncio
async def test_blocked_domain_is_denied_with_an_incident(client, admin_token, db_session):
    agent = await _agent(client, admin_token)
    await _catalog_entry(client, admin_token, "deepseek.com", "blocked")
    chk = await _check(client, agent, "api.deepseek.com")
    assert chk["decision"] == "denied" and chk["incident_type"] == "ai_domain_blocked"
    r = await client.post(RECORD, json=action_record_body(agent, chk["check_id"], "egress.api.deepseek.com",
                                                          _egress("api.deepseek.com"), action_type="egress"),
                          headers={"X-Agent-Key": agent["api_key"]})
    assert r.status_code == 200, r.text
    incident = (await db_session.execute(select(AgentIncident).where(
        AgentIncident.agent_id == agent["id"], AgentIncident.incident_type == "ai_domain_blocked"))).scalar_one()
    assert incident.severity == "critical"


@pytest.mark.asyncio
async def test_unknown_and_allowed_domains_pass_without_tool_rights(client, admin_token, db_session):
    agent = await _agent(client, admin_token)                   # allowed_tools has no egress.* entry
    await _catalog_entry(client, admin_token, "openai.com", "allowed")
    assert (await _check(client, agent, "api.openai.com"))["decision"] == "allowed"
    assert (await _check(client, agent, "api.groq.com"))["decision"] == "allowed"   # not classified yet
    # provider hosts are managed in the catalog, not as Tool Registry tools
    entries = (await db_session.execute(select(ToolRegistryEntry.pattern).where(
        ToolRegistryEntry.pattern.like("egress.%")))).scalars().all()
    assert entries == []


@pytest.mark.asyncio
async def test_policies_still_apply(client, admin_token):
    agent = await _agent(client, admin_token)
    r = await client.post("/api/v1/agents/policies/", json={"name": "no groq", "agent_id": agent["id"],
                                                            "rules": {"deny_tools": ["egress.api.groq.com"]}},
                          headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert (await _check(client, agent, "api.groq.com"))["decision"] == "denied"


@pytest.mark.asyncio
async def test_tool_name_must_name_its_host(client, admin_token):
    agent = await _agent(client, admin_token)
    await _catalog_entry(client, admin_token, "deepseek.com", "blocked")
    # claiming an allowed host in the name while sending to a blocked one
    chk = await _check(client, agent, "api.deepseek.com", tool="egress.api.openai.com")
    assert chk["decision"] == "denied" and "names its host" in chk["reason"]
