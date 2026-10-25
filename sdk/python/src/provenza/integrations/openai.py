# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
OpenAI-compatible clients through Provenza's LLM gateway (pip install 'provenza[openai]').

    from provenza.integrations.openai import gateway_client
    client = gateway_client(agent)                       # an openai.OpenAI
    client.chat.completions.create(model="gpt-4o-mini", messages=[...])

    client = wrap(existing_client, agent)                # the same, from a client you already configured
    client = gateway_client(agent, chain_id=chain)       # calls made inside a delegation chain

Not a monkeypatch: the client's base URL becomes the gateway's and its key the
agent's own, so every call is a PVP action of the agent ("model_call" on
"llm.<model>"), decided by the server like any other action - allowed models
and providers, agent policies, the delegation chain, quarantine, the breaker,
limits - and the provider key never reaches the agent. Models of any provider the
organization routed (OpenAI, Anthropic, Azure, ...) are reached through this
one OpenAI-compatible endpoint. The gateway does not stream yet (stream=False).
"""

from typing import Any, Optional

GATEWAY_PATH = "/api/v1/gateway/v1"
CHAIN_HEADER = "X-Provenza-Chain-Id"


def _settings(agent, chain_id: Optional[int] = None, headers: Optional[dict] = None) -> dict:
    c = agent.credentials()
    out = {"base_url": c["server_url"] + GATEWAY_PATH, "api_key": c["api_key"]}
    if chain_id is not None:
        if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id < 1:
            raise ValueError("chain_id must be a positive integer")
        out["default_headers"] = {**(headers or {}), CHAIN_HEADER: str(chain_id)}
    return out


def gateway_client(agent, chain_id: Optional[int] = None, **kwargs: Any):
    import openai

    s = _settings(agent, chain_id, kwargs.pop("default_headers", None))
    return openai.OpenAI(**s, **kwargs)


def async_gateway_client(agent, chain_id: Optional[int] = None, **kwargs: Any):
    import openai

    s = _settings(agent, chain_id, kwargs.pop("default_headers", None))
    return openai.AsyncOpenAI(**s, **kwargs)


def wrap(client, agent, chain_id: Optional[int] = None):
    """A copy of an openai.OpenAI / AsyncOpenAI client that goes through the
    gateway (the original is left as it was)."""
    return client.with_options(**_settings(agent, chain_id))
