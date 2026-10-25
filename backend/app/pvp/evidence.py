# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
An agent action as PVP evidence (docs/pvp/spec.md, section 3.4).

The evidence of an action is its PVPAction as it stood when it was
recorded, serialized with model_dump(mode="json") and kept on the row
(agent_actions.evidence). It holds ids, hashes and signatures - never the
input or output themselves - so retention, which blanks content after a
while, leaves it intact, and it is never changed afterwards: a later human
approval is a record of its own, not an edit of this one.

    evidence_sha256 = SHA-256(canonical_bytes(evidence))     (hex)

is the leaf a seal commits to (app/pvp/seal.py).
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.agent_signing import canonical_bytes, content_hash
from app.pvp.model import PVPAction, signature_of


def _unix(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def action_view(action, check_token: Optional[str] = None) -> PVPAction:
    """A stored action as PVP (current state). The check token is taken from
    the signed payload (where the agent put it) unless given."""
    payload = action.signed_payload
    token = check_token or (payload or {}).get("check_id")
    return PVPAction(
        action_id=action.id, agent_id=action.agent_id, chain_id=action.chain_id,
        action_type=action.action_type, tool_name=action.tool_name, check_id=token,
        decision=action.policy_check_result, reason=action.reason or "", policy_id=action.policy_id,
        input_sha256=content_hash(action.input_data or {}), output_sha256=content_hash(action.output_data),
        duration_ms=action.duration_ms, recorded_at=_unix(action.created_at),
        signed_payload=payload if action.signature else None,
        signed_by=signature_of(action.signature, action.pq_signature,
                               action.signer_public_key, action.signer_pq_public_key),
        executed_by=action.executed_by,
        witness=action.witness,
    )


def evidence_hash(evidence: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(evidence)).hexdigest()


def stamp(action, check_token: Optional[str] = None) -> None:
    """Fix the evidence of a just-recorded action (it must have its id and
    created_at). Called once, at record time."""
    evidence = action_view(action, check_token).model_dump(mode="json")
    action.evidence, action.evidence_sha256 = evidence, evidence_hash(evidence)
