"""
Builds a signed /delegate request body exactly the way a real agent must:
canonical payload (incl. nonce + issued_at) signed with the agent's
Ed25519 private key. Mirrors signed_payload in app/api/agents.py.
"""

import secrets
import time

from app.core.agent_signing import content_hash, sign_payload


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


def action_record_body(agent, check_id, tool_name, input_data, *, output=None,
                       chain_id=None, action_type="tool_call", duration_ms=None):
    """Signed /actions/record body, bound to a check_id. Mirrors
    signed_payload in record_action_endpoint."""
    payload = {
        "check_id": check_id,
        "agent_id": agent["id"],
        "chain_id": chain_id,
        "action_type": action_type,
        "tool_name": tool_name,
        "input_sha256": content_hash(input_data),
        "output_sha256": content_hash(output),
    }
    return {
        "agent_id": agent["id"],
        "chain_id": chain_id,
        "action_type": action_type,
        "tool_name": tool_name,
        "input": input_data,
        "output": output,
        "duration_ms": duration_ms,
        "check_id": check_id,
        "signature": sign_payload(payload, agent["private_key"]),
    }
