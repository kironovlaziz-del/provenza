# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
TRACE v0.2 export of PVP records (docs/pvp/spec.md, section 5.3).

TRACE (Trust, Runtime Attestation and Compliance Evidence; OPAQUE, hosted by
the Linux Foundation, v0.2 developer preview) defines one signed artifact, the
Trust Record: an EAT claim set, here a JWT signed EdDSA by the organization's
audit key, its public key in cnf.jwk. One record covers one action (a
receipt) or one delegation chain (a run).

Stated honestly - every claim says what Provenza actually knows:

  level 0         software signing. Level 1+ needs a key generated inside a
                  hardware TEE; Provenza claims no level it cannot prove
  origin          "third-party-control-plane": Provenza governed and recorded
                  the agent's actions; it is not the agent (which forces
                  runtime.platform "software-only", per the schema)
  runtime         measurement = hash of what Provenza did verify about the
                  agent's identity: its key fingerprint and current workload
                  attestation (k8s service account) - not a platform measurement
  model           "unobserved": the actions were governed, not the model behind
                  them (an LLM call through the gateway is a separate record)
  policy          bundle_hash = hash of the verdicts applied (the checks), not
                  of policy text; "enforce" only when Provenza executed every
                  call itself (MCP / A2A gateway), else "advisory" - an agent
                  that reports its own actions could have ignored a denial
  build           SLSA 0 (no build provenance); digest = hash of the Tool
                  Registry pins of the tools used
  appraisal       Provenza's own verification of the receipts:
                  affirming / warning (gateway-witnessed, no agent signature) /
                  contraindicated (a receipt does not verify)
  transparency    omitted: Provenza's signed Merkle checkpoints are not a SCITT
                  log; they are listed under references instead
  hybrid keys     TRACE has no place for ML-DSA: the export envelope carries the
                  ML-DSA-65 signature over the same JWS signing input beside the JWT

The JWT payload is the JCS form of the claims (RFC 8785, app/pvp/jcs.py).
"""

import base64
import hashlib
import time
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import agent_signing as sig
from app.models.agent import Agent
from app.models.tool_registry import ToolRegistryEntry
from app.pvp import jcs
from app.pvp.model import PVPReceipt
from app.services import audit_proofs

PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
EXPORT_FORMAT = "provenza.trace-export/1"
VERIFIER = "urn:provenza:pvp:verifier:1"
LEVEL = 0
MAX_CHAIN_ACTIONS = 500


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def digest(value: Any) -> str:
    """"sha256:<hex>" of the JCS form of a JSON value."""
    return "sha256:" + hashlib.sha256(jcs.canonicalize(value)).hexdigest()


def appraisal_status(receipts: List[PVPReceipt]) -> str:
    if any(r.problems() for r in receipts):
        return "contraindicated"
    if any(r.action.signed_by is None for r in receipts):
        return "warning"
    return "affirming"


async def _pins(db: AsyncSession, org_id: int, tools: List[str]) -> List[Dict[str, Any]]:
    rows = (await db.execute(select(ToolRegistryEntry.pattern, ToolRegistryEntry.pinned_digest, ToolRegistryEntry.status)
                             .where(ToolRegistryEntry.org_id == org_id, ToolRegistryEntry.pattern.in_(tools)))).all()
    found = {r[0]: {"tool": r[0], "pinned_digest": r[1], "status": r[2]} for r in rows}
    return [found.get(t, {"tool": t, "pinned_digest": None, "status": "unregistered"}) for t in sorted(set(tools))]


async def _attestation(db: AsyncSession, agent: Agent) -> Optional[Dict[str, Any]]:
    """The agent's latest passed workload attestation, as far as it is
    evidence: what was attested, under which policy, until when."""
    from app.models.attestation import AgentAttestation

    row = (await db.execute(select(AgentAttestation).where(AgentAttestation.agent_id == agent.id,
                                                           AgentAttestation.ok.is_(True))
                            .order_by(AgentAttestation.id.desc()).limit(1))).scalar_one_or_none()
    if row is None:
        return None
    return {"kind": row.kind, "policy_id": row.policy_id, "evidence_sha256": row.evidence_sha256,
            "identity": row.identity, "signer_fingerprint": row.signer_fingerprint,
            "attested_at": row.created_at.isoformat() if row.created_at else None,
            "valid_until": row.valid_until.isoformat() if row.valid_until else None}


async def export(db: AsyncSession, org_id: int, agent: Agent, receipts: List[PVPReceipt],
                 base_url: str = "", resolver: Optional[str] = None) -> Dict[str, Any]:
    """A signed Trust Record for these receipts (one action, or one chain),
    wrapped with what an auditor needs to check it offline."""
    if not receipts:
        raise ValueError("a trust record needs at least one action")
    now = int(time.time())
    actions = [r.action for r in receipts]
    key = await audit_proofs.current_key(db, org_id)
    priv = audit_proofs.private_keys(key)
    fingerprint = key.fingerprint

    claims: Dict[str, Any] = {
        "eat_profile": PROFILE,
        "iat": now,
        # not a resolvable DID method: the identity proof is the agent's key fingerprint (runtime.measurement)
        "subject": f"did:provenza:org-{org_id}:agent-{agent.id}",
        "origin": {"kind": "third-party-control-plane", "producer": "provenza",
                   "ingested_at": max(1700000000, min(a.recorded_at for a in actions))},
        "model": {"provider": "unobserved", "model_id": "unobserved"},
        "runtime": {"platform": "software-only", "measurement": digest({
            "agent_key_fingerprint": sig.key_fingerprint(agent.public_key, agent.pq_public_key),
            "attestation": await _attestation(db, agent)})},
        "policy": {
            "bundle_hash": digest([{"action_id": a.action_id, "decision": a.decision, "policy_id": a.policy_id,
                                    "reason": a.reason} for a in actions]),
            "enforcement_mode": "enforce" if all(a.executed_by for a in actions) else "advisory",
            "version": "pvp/1",
        },
        "data_class": "unclassified",
        "tool_transcript": {"hash": digest([a.model_dump(mode="json") for a in actions]), "call_count": len(actions)},
        "build_provenance": {"slsa_level": 0, "digest": digest(await _pins(db, org_id, [a.tool_name for a in actions])),
                             "provenance_depth": "surface"},
        "appraisal": {"status": appraisal_status(receipts), "verifier": VERIFIER, "timestamp": now},
        "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519",
                        "x": b64url(base64.b64decode(key.public_key)), "kid": fingerprint}},
        "references": [
            {"rel": "pvp-receipt", "id": str(r.action.action_id),
             "resolver": f"{base_url}/api/v1/pvp/receipts/{r.action.action_id}",
             "digest": digest(r.model_dump(mode="json"))} for r in receipts
        ] + [
            {"rel": "audit-checkpoint", "id": f"org-{org_id}:tree-{cp.tree_size}",
             "resolver": f"{base_url}/api/v1/audit-logs/checkpoints", "digest": "sha256:" + cp.root_hash}
            for cp in {r.checkpoint.tree_size: r.checkpoint for r in receipts if r.checkpoint}.values()
        ],
    }
    if resolver:
        claims["tool_transcript"]["transcript_uri"] = resolver

    header = {"alg": "EdDSA", "typ": "JWT", "kid": fingerprint}
    signing_input = f"{b64url(jcs.canonicalize(header))}.{b64url(jcs.canonicalize(claims))}".encode("ascii")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signature = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv["ed"])).sign(signing_input)
    pq_signature = None
    if priv["pq"]:
        pq = sig._mldsa().MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(priv["pq"]))
        pq_signature = base64.b64encode(pq.sign(signing_input)).decode()
    return {
        "format": EXPORT_FORMAT,
        "profile": PROFILE,
        "level": LEVEL,
        "jwt": signing_input.decode() + "." + b64url(signature),
        "claims": claims,
        "key": {"fingerprint": fingerprint, "algorithm": key.algorithm, "public_key": key.public_key,
                "pq_public_key": key.pq_public_key},
        # ML-DSA-65 over the JWS signing input (hybrid audit keys); TRACE itself has no field for it
        "pq_signature": pq_signature,
        "receipts": [r.model_dump(mode="json") for r in receipts],
    }
