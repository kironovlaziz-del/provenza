# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
OpenAI-compatible clients through Provenza's LLM gateway (pip install 'provenza[openai]').

    from provenza.integrations.openai import gateway_client
    client = gateway_client(agent)                       # an openai.OpenAI
    client.chat.completions.create(model="gpt-4o-mini", messages=[...])

    client = wrap(existing_client, agent)                # the same, from a client you already configured

Not a monkeypatch: the client's base URL becomes the gateway's and its key the
agent's own, so every call is checked by the server - allowed models, limits,
the Prompt Firewall (PII masked, blocked terms), injection in and out - and
the provider key never reaches the agent. Models of any provider the
organization routed (OpenAI, Anthropic, Azure, ...) are reached through this
one OpenAI-compatible endpoint. The gateway does not stream yet (stream=False).
"""

from typing import Any

GATEWAY_PATH = "/api/v1/gateway/v1"


def _settings(agent) -> dict:
    c = agent.credentials()
    return {"base_url": c["server_url"] + GATEWAY_PATH, "api_key": c["api_key"]}


def gateway_client(agent, **kwargs: Any):
    import openai

    return openai.OpenAI(**_settings(agent), **kwargs)


def async_gateway_client(agent, **kwargs: Any):
    import openai

    return openai.AsyncOpenAI(**_settings(agent), **kwargs)


def wrap(client, agent):
    """A copy of an openai.OpenAI / AsyncOpenAI client that goes through the
    gateway (the original is left as it was)."""
    return client.with_options(**_settings(agent))
