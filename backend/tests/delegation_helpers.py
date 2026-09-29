"""
Builds a signed /delegate request body exactly the way a real agent must:
canonical payload (incl. nonce + issued_at) signed with the agent's
Ed25519 private key. Mirrors signed_payload in app/api/agents.py.
"""

import secrets
import time

from app.core.agent_signing import sign_payload


def delegation_body(from_agent, to_agent_id, task, caps, *, chain_id=None,
                    expires_in=None, nonce=None, issued_at=None):
    """from_agent is the dict returned by /agents/register (has id + private_key)."""
    nonce = nonce or secrets.token_hex(16)
    issued_at = int(time.time()) if issued_at is None else issued_at
    payload = {
        "from_agent_id": from_agent["id"],
        "to_agent_id": to_agent_id,
        "task": task,
        "delegated_capabilities": sorted(caps),
        "chain_id": chain_id,
        "expires_in": expires_in,
        "nonce": nonce,
        "issued_at": issued_at,
    }
    return {
        "to_agent_id": to_agent_id,
        "task": task,
        "delegated_capabilities": caps,
        "chain_id": chain_id,
        "expires_in": expires_in,
        "nonce": nonce,
        "issued_at": issued_at,
        "signature": sign_payload(payload, from_agent["private_key"]),
    }
