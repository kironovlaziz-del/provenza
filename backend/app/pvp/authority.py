# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Proof of Authority - one file that shows, for one agent action, the chain of
authority behind it, every link signed (docs/proof-of-authority.md):

    administrators' passkeys ──sign──► the policy release in force
                                         (its bundle lists the agent's rights,
                                          its manifest the agent's key)
    the delegating agents' keys ─sign─► each hop of the delegation chain
    the agent's key ─────────sign─────► the request for this very call
    a person's passkey ──────certify──► the approval, when one let it run
    the audit key ───────────sign─────► the checkpoint the action is sealed under

tools/provenza_audit.py authority checks every link offline; nothing in the
file has to be taken on this server's word except what the verifier names
as such (an organization that never signed a release; a keyless agent).

The file holds what the receipt holds (ids, hashes, signatures - never the
input or output of the call) plus the signed releases and the delegation
hops.
"""

import time
from typing import Any, Dict, List, Optional

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import api_error
from app.models.delegation import DelegationChain, DelegationHop
from app.models.policy_release import PolicyRelease
from app.pvp import receipt as receipts
from app.pvp.model import signature_of

TYPE = "authority"
V = 1
MAX_RELEASES = 1000
MAX_HOPS = 200


async def release_chain(db: AsyncSession, org_id: int, number: int, bundle_sha256: str) -> List[Dict[str, Any]]:
    """The signed releases from the organization's first one up to the release
    with this number and bundle, each as GET /policy-releases/{id} gives it.
    Empty when no signed release has that number and bundle."""
    from app.services import policy_release

    head = (await db.execute(select(PolicyRelease).where(
        PolicyRelease.org_id == org_id, PolicyRelease.number == number,
        PolicyRelease.bundle_sha256 == bundle_sha256,
        PolicyRelease.status.in_(("in_force", "superseded"))))).scalar_one_or_none()
    out: List[Dict[str, Any]] = []
    r = head
    while r is not None and len(out) < MAX_RELEASES:
        out.append(await policy_release.document(db, org_id, r.id))
        r = await db.get(PolicyRelease, r.governed_by_id) if r.governed_by_id else None
    if r is not None:
        raise api_error(status.HTTP_409_CONFLICT, "pvp.release_history_too_long", max=MAX_RELEASES)
    out.reverse()
    return out


def hop_out(h: DelegationHop) -> Dict[str, Any]:
    sig = signature_of(h.signature, h.pq_signature, h.signer_public_key, h.signer_pq_public_key)
    return {"hop_id": h.id, "chain_id": h.chain_id, "from_agent_id": h.from_agent_id, "to_agent_id": h.to_agent_id,
            "depth": h.depth, "signed_payload": h.signed_payload if sig else None,
            "signed_by": sig.model_dump(mode="json") if sig else None}


async def delegation(db: AsyncSession, org_id: int, chain_id: int) -> Optional[Dict[str, Any]]:
    chain = (await db.execute(select(DelegationChain).where(
        DelegationChain.id == chain_id, DelegationChain.org_id == org_id))).scalar_one_or_none()
    if chain is None:
        return None
    hops = list((await db.execute(select(DelegationHop).where(
        DelegationHop.chain_id == chain_id, DelegationHop.org_id == org_id)
        .order_by(DelegationHop.id).limit(MAX_HOPS + 1))).scalars())
    if len(hops) > MAX_HOPS:
        raise api_error(status.HTTP_409_CONFLICT, "pvp.chain_too_long", max=MAX_HOPS)
    return {"chain_id": chain.id, "root_agent_id": chain.root_agent_id, "hops": [hop_out(h) for h in hops]}


async def build(db: AsyncSession, org_id: int, action_id: int) -> Dict[str, Any]:
    r = await receipts.build(db, org_id, action_id)
    receipt = r.model_dump(mode="json")
    action = receipt["action"]
    rel = action.get("release")
    releases = await release_chain(db, org_id, rel["number"], rel["bundle_sha256"]) if rel else []
    chain = await delegation(db, org_id, action["chain_id"]) if action.get("chain_id") else None
    return {"pvp": "pvp/1", "type": TYPE, "v": V, "org_id": org_id, "action_id": action_id,
            "issued_at": int(time.time()), "receipt": receipt, "releases": releases, "delegation": chain}
