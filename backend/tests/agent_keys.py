"""Agents for tests that use the registry directly: the agent makes its own
signing key, as in production (the server never generates one)."""

from app.core.agent_signing import generate_keypair
from app.schemas.agent import AgentCreate

_PRIVATE: dict = {}


def agent_create(**fields) -> AgentCreate:
    """AgentCreate with a freshly made key; the private half is kept for register()."""
    private_key, public_key = generate_keypair()
    data = AgentCreate(public_key=public_key, **fields)
    _PRIVATE[data.public_key] = private_key
    return data


async def register(reg, org_id, created_by, data: AgentCreate):
    """(agent, raw API key, private signing key) - what the tests used to get back."""
    agent, raw_key = await reg.register(org_id, created_by, data)
    return agent, raw_key, _PRIVATE.get(data.public_key)
