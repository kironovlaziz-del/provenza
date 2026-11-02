# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent Manifests (AgenTrust Agent Manifest, specification v0.2) for agents.

An Agent Manifest is a signed record of how an agent was set up and approved,
which anyone can check without asking the server. Provenza issues one per
agent, signed by the organization's audit key (Ed25519, plus ML-DSA-65 when
the server has it - a hybrid COSE_Sign), with the `agent-manifest` SDK.

Stated honestly - Provenza binds only what it governs and knows:

  profile           "composition-only": Provenza is the policy gate, not the
                    agent. It does not see the agent's system prompt, model
                    weights, memory, RAG corpus or build; those are declared
                    in unbound_artifacts, never guessed. A verifier therefore
                    answers INCOMPLETE - the signature is authentic, the
                    manifest deliberately partial.
  tool_manifest     the approved MCP tools Provenza serves the agent, each with
                    the hashes of its approved definition (the cMCP projection:
                    input/output schema, description), and the Merkle catalog
                    root. Bound only when every tool the agent is registered for
                    is such a tool - a partial catalog would claim the agent has
                    no other tools. A definition changed upstream is withheld
                    until re-approved: rug_pull_policy "require-reapproval".
  decision_trace    the organization's audit log: the root of its latest signed
                    Merkle checkpoint, the key that signs checkpoints, the
                    window and size of the log. audit_key_sealed is false: the
                    key is software-held, not sealed in a TEE.
  hitl_record       required when the agent's policies hold actions for a
                    person's approval. Approvals are not attached (they are
                    signed per action, under app/services/signing_sessions).
  policy_bundle     not bound: the specification names Cedar, Rego and AGT
                    YAML policies, and Provenza's policy format is none of them.
  identity          agent_id: the SPIFFE ID the agent attested with, else
                    spiffe://<server>/org/<slug>/agent/<id>; issuer:
                    spiffe://<server>/org/<slug>/provenza.

A manifest is issued again when what it binds changes, when the signing key
changes, or when it nears expiry (default validity 90 days); it then names the
one before it (previous_manifest_id). Otherwise the current one is returned.
"""

import base64
import hashlib
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit_chain as ac
from app.core.config import settings
from app.models.agent import Agent, AgentPolicy
from app.models.agent_manifest import AgentManifestRecord
from app.models.audit_log import AIAuditLog
from app.models.organization import Organization
from app.services import audit_proofs

SPEC_VERSION = "0.2"
VALIDITY = timedelta(days=90)
RENEW_BEFORE = timedelta(days=7)
RUG_PULL_POLICY = "require-reapproval"
ALL_ARTIFACTS = ("system_prompt", "policy_bundle", "tool_manifest", "model_identity", "rag_corpus",
                 "memory_baseline", "decision_trace", "delegation_chain", "supply_chain", "hitl_record")

_LABEL = re.compile(r"[^a-z0-9._-]+")
_SEGMENT = re.compile(r"[^A-Za-z0-9._-]+")


class ManifestUnavailable(Exception):
    """The server cannot sign manifests (the SDK is missing)."""


def _sdk():
    try:
        import agent_manifest  # noqa: F401
        from agent_manifest import _cose, _signing, models
        from agent_manifest._canonicalize import canonicalize
        from agent_manifest._merkle import build_catalog_tree
    except ImportError as e:  # pragma: no cover - a pinned requirement
        raise ManifestUnavailable(str(e))
    return models, _cose, _signing, canonicalize, build_catalog_tree


# ---------------------------------------------------------------- identity

def trust_domain(base_url: str) -> str:
    """The SPIFFE trust domain of this server: its host name, lower case."""
    host = (urlparse(settings.PUBLIC_BASE_URL or base_url).hostname or "provenza.local").lower()
    return _LABEL.sub("-", host).strip(".-") or "provenza.local"


def _segment(value: str) -> str:
    return _SEGMENT.sub("-", value).strip("-") or "x"


def agent_spiffe_id(agent: Agent, org: Organization, td: str) -> str:
    attested = (agent.attested_subject or "").strip()
    if attested.startswith("spiffe://"):
        return attested
    return f"spiffe://{td}/org/{_segment(org.slug)}/agent/{agent.id}"


def issuer_spiffe_id(org: Organization, td: str) -> str:
    return f"spiffe://{td}/org/{_segment(org.slug)}/provenza"


def uuid7() -> str:
    """A UUID v7 (RFC 9562): 48-bit milliseconds, version 7, variant 10."""
    ts = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    rand = int.from_bytes(os.urandom(10), "big")
    hi = (ts << 16) | (0x7 << 12) | ((rand >> 62) & 0xFFF)
    lo = (0b10 << 62) | (rand & 0x3FFFFFFFFFFFFFFF)
    h = f"{hi:016x}{lo:016x}"
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- bindings

def tool_hashes(definition: Dict[str, Any]) -> Tuple[str, str]:
    """(schema_hash, description_hash) of an MCP tool definition, as cMCP
    projects its catalog into a manifest: RFC 8785 of {input_schema,
    output_schema}, and of the description string."""
    _, _, _, canonicalize, _ = _sdk()
    schema = canonicalize({"input_schema": definition.get("inputSchema"),
                           "output_schema": definition.get("outputSchema")}, exclude_none=False)
    description = canonicalize(definition.get("description") or "", exclude_none=False)
    return _sha256(schema), _sha256(description)


async def _tool_manifest(db: AsyncSession, agent: Agent, org: Organization, td: str) -> Optional[Dict[str, Any]]:
    """The agent's approved MCP tool catalog, or None when the agent is
    registered for tools Provenza does not serve as MCP tools."""
    from app.pvp.mcp_gateway import MCPGateway

    allowed = {t for t in (agent.allowed_tools or []) if isinstance(t, str)}
    served = {tool.exposed_name: (tool, server) for tool, server in await MCPGateway(db)._approved(agent.org_id)
              if tool.exposed_name in allowed}
    if not allowed or set(served) != allowed:
        return None
    from app.models.tool_registry import ToolRegistryEntry

    tools = []
    for name in sorted(served):
        tool, server = served[name]
        entry = await db.get(ToolRegistryEntry, tool.registry_entry_id) if tool.registry_entry_id else None
        schema_hash, description_hash = tool_hashes(tool.definition or {})
        tools.append({
            "tool_id": name,
            "tool_name": name,
            "endpoint_id": f"spiffe://{td}/org/{_segment(org.slug)}/mcp/{_segment(server.slug)}",
            "schema_hash": schema_hash,
            "description_hash": description_hash,
            "version": (entry.pinned_version if entry and entry.pinned_version else f"pinned-{tool.digest[:12]}"),
        })
    models, _, _, _, build_catalog_tree = _sdk()
    catalog = build_catalog_tree([models.ToolEntry.model_validate(t) for t in tools])
    return {"catalog_hash": catalog, "tools": tools, "allow_dynamic_registration": False,
            "rug_pull_policy": RUG_PULL_POLICY}


async def _decision_trace(db: AsyncSession, org_id: int, base_url: str) -> Optional[Dict[str, Any]]:
    cp = await audit_proofs.latest_checkpoint(db, org_id)
    if cp is None:
        cp = await audit_proofs.checkpoint(db, org_id)
    if cp is None:
        return None
    first = await db.scalar(select(func.min(AIAuditLog.created_at)).where(AIAuditLog.org_id == org_id))
    last = cp.issued_at
    if first is None or first > last:
        first = last
    server = (settings.PUBLIC_BASE_URL or base_url).rstrip("/")
    return {
        "trace_type": "merkle-log",
        "audit_chain_root": "sha256:" + cp.root_hash,
        "audit_chain_uri": f"{server}/api/v1/audit/checkpoints",
        "signing_key_id": cp.key_fingerprint,
        "audit_key_sealed": False,
        "first_entry_at": _ts(first),
        "last_entry_at": _ts(last),
        "entry_count": int(cp.tree_size),
    }


async def _hitl_required(db: AsyncSession, agent: Agent) -> bool:
    from app.services import hier_policy

    eff = await hier_policy.for_agent(db, agent)
    if (eff.fields.get("tools.require_approval") or {}).get("items"):
        return True
    rows = (await db.execute(select(AgentPolicy.rules).where(
        AgentPolicy.org_id == agent.org_id,
        (AgentPolicy.agent_id == agent.id) | (AgentPolicy.agent_id.is_(None)),
    ))).scalars().all()
    for rules in rows:
        for rule in (rules if isinstance(rules, list) else [rules]):
            if isinstance(rule, dict) and any(k.startswith("require_approval") and v for k, v in rule.items()):
                return True
    return False


async def content(db: AsyncSession, agent: Agent, base_url: str) -> Dict[str, Any]:
    """What the manifest binds, without its ids and times."""
    org = await db.get(Organization, agent.org_id)
    td = trust_domain(base_url)
    artifacts: Dict[str, Any] = {}
    tm = await _tool_manifest(db, agent, org, td)
    if tm is not None:
        artifacts["tool_manifest"] = tm
    trace = await _decision_trace(db, agent.org_id, base_url)
    if trace is not None:
        artifacts["decision_trace"] = trace
    out: Dict[str, Any] = {
        "agent_id": agent_spiffe_id(agent, org, td),
        "issuer": issuer_spiffe_id(org, td),
        "artifacts": artifacts,
        "hitl_record": {"required": await _hitl_required(db, agent)},
    }
    bound = set(artifacts) | {"hitl_record"}
    out["unbound_artifacts"] = [a for a in ALL_ARTIFACTS if a not in bound]
    return out


def _content_hash(c: Dict[str, Any], key_fingerprint: str) -> str:
    _, _, _, canonicalize, _ = _sdk()
    stable = {**c, "artifacts": {k: v for k, v in c["artifacts"].items() if k != "decision_trace"},
              "key": key_fingerprint}
    return hashlib.sha256(canonicalize(stable)).hexdigest()


def build(c: Dict[str, Any], *, manifest_id: str, previous: Optional[str], issued_at: datetime) -> Dict[str, Any]:
    """The manifest document, checked against the SDK's schema."""
    models, _, _, _, _ = _sdk()
    at = _ts(issued_at)
    artifacts = {k: {**v, "bound_at": at} for k, v in c["artifacts"].items()}
    doc: Dict[str, Any] = {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "manifest_id": manifest_id,
        "agent_id": c["agent_id"],
        "version": SPEC_VERSION,
        "issued_at": at,
        "expires_at": _ts(issued_at + VALIDITY),
        "issuer": c["issuer"],
        "crypto_profile": "standard",
        "profile": "composition-only",
        "unbound_artifacts": c["unbound_artifacts"],
        "artifacts": artifacts,
        "hitl_record": c["hitl_record"],
    }
    if previous:
        doc["previous_manifest_id"] = previous
    models.Manifest.model_validate(doc)  # raises on anything the specification refuses
    return doc


def _keypair(key):
    """The organization's audit key as an SDK key pair (hybrid when it has
    an ML-DSA-65 half)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _, _, _signing, _, _ = _sdk()
    priv = audit_proofs.private_keys(key)
    ed_priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv["ed"]))
    ed = _signing.Ed25519KeyPair(private_key=ed_priv, public_key=ed_priv.public_key())
    if not priv["pq"] or not key.pq_public_key:
        return ed
    pq = _signing.MlDsa65KeyPair(private_key_bytes=base64.b64decode(priv["pq"]),
                                 public_key_bytes=base64.b64decode(key.pq_public_key))
    return _signing.HybridKeyPair(ed25519=ed, ml_dsa65=pq)


def trusted_keys_of(key) -> Dict[str, str]:
    """{kid hex: base64url public key} - what verify_cose_manifest takes: the
    COSE kid is SHA-256 of the raw public key."""
    out = {}
    for b64 in (key.public_key, key.pq_public_key):
        if b64:
            raw = base64.b64decode(b64)
            out[hashlib.sha256(raw).hexdigest()] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return out


async def current(db: AsyncSession, agent: Agent, base_url: str, user_id: Optional[int]) -> AgentManifestRecord:
    """The agent's manifest: the latest one while it still binds what is
    true now, else a newly issued one (recorded in the audit log)."""
    _, _cose, _, _, _ = _sdk()
    key = await audit_proofs.current_key(db, agent.org_id)
    c = await content(db, agent, base_url)
    h = _content_hash(c, key.fingerprint)
    last = (await db.execute(
        select(AgentManifestRecord).where(AgentManifestRecord.agent_id == agent.id)
        .order_by(AgentManifestRecord.id.desc()).limit(1)
    )).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if last is not None and last.content_hash == h and last.expires_at - now > RENEW_BEFORE:
        return last

    issued = now.replace(microsecond=0)
    doc = build(c, manifest_id=uuid7(), previous=last.manifest_id if last else None, issued_at=issued)
    envelope = _cose.sign_manifest_cose(doc, _keypair(key))
    rec = AgentManifestRecord(
        manifest_id=doc["manifest_id"], org_id=agent.org_id, agent_id=agent.id,
        previous_manifest_id=doc.get("previous_manifest_id"), content_hash=h, payload=doc,
        envelope=envelope, key_fingerprint=key.fingerprint, issued_at=issued,
        expires_at=issued + VALIDITY, issued_by=user_id,
    )
    db.add(rec)
    await db.flush()
    from app.services.audit_service import AuditService

    await AuditService(db).log(agent.org_id, user_id, "agent", agent.id, "agent_manifest_issued", {
        "manifest_id": rec.manifest_id, "previous_manifest_id": rec.previous_manifest_id,
        "envelope_sha256": hashlib.sha256(envelope).hexdigest(), "key_fingerprint": key.fingerprint,
        "unbound": c["unbound_artifacts"],
    })
    return rec


def out(rec: AgentManifestRecord, key) -> Dict[str, Any]:
    return {
        "manifest_id": rec.manifest_id,
        "previous_manifest_id": rec.previous_manifest_id,
        "issued_at": ac.format_ts(rec.issued_at),
        "expires_at": ac.format_ts(rec.expires_at),
        "key_fingerprint": rec.key_fingerprint,
        "manifest": rec.payload,
        "envelope": base64.b64encode(rec.envelope).decode(),
        "envelope_sha256": hashlib.sha256(rec.envelope).hexdigest(),
        # the keys that signed it, for convenience: a verifier should take them
        # from Settings -> Audit keys (or the organization) rather than from here
        "trusted_keys": trusted_keys_of(key) if key is not None else {},
    }


async def signing_key_of(db: AsyncSession, rec: AgentManifestRecord):
    from app.models.audit_log import AuditSigningKey

    return (await db.execute(select(AuditSigningKey).where(
        AuditSigningKey.org_id.is_(None) | (AuditSigningKey.org_id == rec.org_id),
        AuditSigningKey.fingerprint == rec.key_fingerprint,
    ).limit(1))).scalar_one_or_none()

