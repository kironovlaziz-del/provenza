# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent Manifests (app/services/agent_manifest.py): a manifest Provenza issues
for an agent verifies with the AgenTrust agent-manifest SDK itself - its COSE
envelope, its schema, its tool catalog root - binds only what Provenza
governs, and is issued again only when that changes.
"""

import base64

import pytest
from agent_manifest import (OverallResult, RevocationStore, VerificationContext, decode_cose_manifest,
                            verify_cose_manifest, verify_manifest)
from agent_manifest._merkle import build_catalog_tree
from agent_manifest.models import ToolEntry
from sqlalchemy import select

from app.models.agent import Agent
from app.models.audit_log import AIAuditLog
from tests.conftest import auth_headers
from tests.test_mcp_gateway import READ_TOOL, _agent, _approve, _ready, _server, _sync, fake  # noqa: F401

AGENTS = "/api/v1/agents"


async def _manifest(client, token, agent_id):
    r = await client.get(f"{AGENTS}/{agent_id}/manifest", headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.asyncio
async def test_a_manifest_verifies_with_the_sdk(client, admin_token, fake):  # noqa: F811
    _, agent = await _ready(client, admin_token, fake)
    body = await _manifest(client, admin_token, agent["id"])
    m = body["manifest"]
    envelope = base64.b64decode(body["envelope"])

    # the SDK's own COSE verification, with the organization's keys
    v = verify_cose_manifest(envelope, body["trusted_keys"])
    assert v.verified and v.manifest["manifest_id"] == body["manifest_id"]
    assert len(v.signatures) == 2  # Ed25519 + ML-DSA-65 (hybrid COSE_Sign)

    # composition-only: what Provenza does not see is declared, never guessed
    assert m["version"] == "0.2" and m["profile"] == "composition-only"
    assert {"system_prompt", "model_identity", "rag_corpus", "memory_baseline", "supply_chain",
            "policy_bundle", "delegation_chain"} <= set(m["unbound_artifacts"])
    assert m["agent_id"].startswith("spiffe://") and m["agent_id"].endswith(f"/agent/{agent['id']}")
    assert m["issuer"].endswith("/provenza")

    # the tool catalog: the approved definition, the cMCP projection, the spec's Merkle root
    tm = m["artifacts"]["tool_manifest"]
    assert [t["tool_name"] for t in tm["tools"]] == ["files.read"]
    assert tm["rug_pull_policy"] == "require-reapproval" and tm["allow_dynamic_registration"] is False
    assert tm["catalog_hash"] == build_catalog_tree([ToolEntry.model_validate(t) for t in tm["tools"]])

    # the audit log it is recorded in
    dt = m["artifacts"]["decision_trace"]
    assert dt["trace_type"] == "merkle-log" and dt["audit_key_sealed"] is False
    assert dt["audit_chain_root"].startswith("sha256:")

    # the SDK's verification engine: authentic, deliberately incomplete
    result = verify_manifest(envelope, VerificationContext(trusted_keys=body["trusted_keys"]), RevocationStore())
    assert result.result == OverallResult.INCOMPLETE, result
    # without the keys nothing is trusted
    assert verify_manifest(envelope, VerificationContext(), RevocationStore()).result != OverallResult.VALID


@pytest.mark.asyncio
async def test_reissued_only_when_what_it_binds_changes(client, admin_token, db_session, fake):  # noqa: F811
    server, agent = await _ready(client, admin_token, fake, tools=("files.read",))
    first = await _manifest(client, admin_token, agent["id"])
    # more audit records, same bindings: the same manifest
    again = await _manifest(client, admin_token, agent["id"])
    assert again["manifest_id"] == first["manifest_id"]

    # the agent gets another approved tool: a new manifest, chained to the first
    await _approve(client, admin_token, server, "write")
    row = await db_session.get(Agent, agent["id"])
    row.allowed_tools = ["files.read", "files.write"]
    await db_session.commit()
    second = await _manifest(client, admin_token, agent["id"])
    assert second["manifest_id"] != first["manifest_id"]
    assert second["previous_manifest_id"] == first["manifest_id"]
    assert [t["tool_name"] for t in second["manifest"]["artifacts"]["tool_manifest"]["tools"]] == \
        ["files.read", "files.write"]

    issued = (await db_session.execute(select(AIAuditLog).where(AIAuditLog.action == "agent_manifest_issued")
                                       )).scalars().all()
    assert [r.metadata_json["manifest_id"] for r in issued] == [first["manifest_id"], second["manifest_id"]]


@pytest.mark.asyncio
async def test_a_partial_tool_catalog_is_not_claimed(client, admin_token, fake):  # noqa: F811
    # registered for a tool Provenza does not serve as an MCP tool: no catalog
    _, agent = await _ready(client, admin_token, fake, tools=("files.read", "crm.update"))
    m = (await _manifest(client, admin_token, agent["id"]))["manifest"]
    assert "tool_manifest" not in m["artifacts"] and "tool_manifest" in m["unbound_artifacts"]


@pytest.mark.asyncio
async def test_hitl_required_follows_the_policy(client, admin_token, fake):  # noqa: F811
    _, agent = await _ready(client, admin_token, fake)
    assert (await _manifest(client, admin_token, agent["id"]))["manifest"]["hitl_record"] == {"required": False}
    r = await client.put("/api/v1/policy-layers", json={"scope": "org", "yaml": "tools:\n  require_approval: [\"files.*\"]\n"},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    m = (await _manifest(client, admin_token, agent["id"]))["manifest"]
    assert m["hitl_record"] == {"required": True}


@pytest.mark.asyncio
async def test_a_tampered_manifest_fails(client, admin_token, fake):  # noqa: F811
    import cbor2

    _, agent = await _ready(client, admin_token, fake)
    body = await _manifest(client, admin_token, agent["id"])
    tag = cbor2.loads(base64.b64decode(body["envelope"]))
    parts = list(tag.value)
    parts[2] = parts[2].replace(b"files.read", b"files.rm!!")  # the payload, same length
    forged = cbor2.dumps(cbor2.CBORTag(tag.tag, parts), canonical=True)
    with pytest.raises(Exception):
        verify_cose_manifest(forged, body["trusted_keys"])
    assert decode_cose_manifest(base64.b64decode(body["envelope"])).manifest["manifest_id"] == body["manifest_id"]


@pytest.mark.asyncio
async def test_cose_download_and_roles(client, admin_token, approver_token, fake):  # noqa: F811
    _, agent = await _ready(client, admin_token, fake)
    r = await client.get(f"{AGENTS}/{agent['id']}/manifest.cose", headers=auth_headers(approver_token))
    assert r.status_code == 200 and r.headers["content-type"] == "application/cose"
    assert decode_cose_manifest(r.content).manifest["agent_id"].endswith(f"/agent/{agent['id']}")


@pytest.mark.asyncio
async def test_plain_users_cannot_issue(client, db_session, org_and_users, admin_token, fake):  # noqa: F811
    from app.models.user import UserRole
    from tests.test_oversight_roles import _token_for

    _, agent = await _ready(client, admin_token, fake)
    user = await _token_for(client, db_session, org_and_users, UserRole.user)
    r = await client.get(f"{AGENTS}/{agent['id']}/manifest", headers=auth_headers(user))
    assert r.status_code == 403
