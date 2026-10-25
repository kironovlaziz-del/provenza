# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
What an enforcement point signs about an action it handled
(docs/pvp/edge.md, section 4) - today the egress proxy (proxy/internal/egress).

The proxy holds an Ed25519 key it generated on its host and registered once.
For every request it forwarded, or refused under the signed policy, it signs

    {"type": "provenza.proxy.receipt", "v": 1,
     "check_id", "agent_id", "chain_id", "action_type", "tool_name",
     "input_sha256", "output_sha256", "decision",        <- the action, as recorded
     "agent_signature": "verified" | "not_presented",    <- did IT verify the agent's key
     "policy": {"release", "bundle_sha256"} | null,      <- the signed policy it judged by
     "log": {"seq", "prev"},                             <- its own hash-chained log
     "issued_at"}

and keeps the same line in its own log. The server accepts the receipt only
when it names exactly the action it records and the signature verifies with
the proxy's registered key; the receipt is then part of the action's
evidence (PVPAction.witness), sealed with it, and verifiable offline
(tools/provenza_audit.py receipt --proxy-fingerprint).
"""

from typing import Any, Dict, Optional

from app.core.agent_signing import key_fingerprint, verify_payload

TYPE = "provenza.proxy.receipt"
V = 1
ACTION_FIELDS = ("check_id", "agent_id", "chain_id", "action_type", "tool_name", "input_sha256", "output_sha256",
                 "decision")
AGENT_SIGNATURE = ("verified", "not_presented")
EXTRA = ("type", "v", "agent_signature", "policy", "log", "issued_at")


def problems(statement: Any, action: Dict[str, Any]) -> list:
    """What does not hold in a receipt statement for this action (its fields
    as the evidence states them)."""
    if not isinstance(statement, dict):
        return ["not_a_statement"]
    out = []
    if set(statement) != set(ACTION_FIELDS) | set(EXTRA):
        out.append("fields")
    if statement.get("type") != TYPE or statement.get("v") != V:
        out.append("type")
    if statement.get("agent_signature") not in AGENT_SIGNATURE:
        out.append("agent_signature")
    pol = statement.get("policy")
    if pol is not None and (not isinstance(pol, dict) or set(pol) != {"release", "bundle_sha256"}):
        out.append("policy")
    log = statement.get("log")
    if not isinstance(log, dict) or set(log) != {"seq", "prev"}:
        out.append("log")
    out += [f"mismatch:{k}" for k in ACTION_FIELDS if statement.get(k) != action.get(k)]
    return out


def make(statement: Any, signature: Any, public_key: str, action: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The witness to keep with the action, or None when the receipt does not
    name this action or its signature does not verify with the proxy's key."""
    if problems(statement, action) or not isinstance(signature, str) or not public_key:
        return None
    if not verify_payload(statement, signature, public_key):
        return None
    return {"by": "egress_proxy", "key_fingerprint": key_fingerprint(public_key), "public_key": public_key,
            "statement": statement, "signature": signature}
