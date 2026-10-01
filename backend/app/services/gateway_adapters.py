# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Multi-message chat calls for the gateway.

provider_adapters.call_provider sends a single prompt; the gateway forwards
a whole conversation (system / user / assistant / tool messages) and the
sampling parameters. Same provider types, same base URLs and headers, same
shared httpx client and ProviderCallError as provider_adapters.
"""

from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.services.provider_adapters import ProviderCallError, _get_client

DEFAULT_BASE = {
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "anthropic": "https://api.anthropic.com/v1",
}
PASS_PARAMS = ("temperature", "top_p", "max_tokens", "stop")


def _text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type", "text") == "text")
    return str(content)


async def _post(url: str, headers: Dict[str, str], body: Dict[str, Any]) -> Dict[str, Any]:
    try:
        resp = await _get_client().post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise ProviderCallError(f"Network error calling provider: {exc}") from exc
    if resp.status_code >= 400:
        raise ProviderCallError(f"Provider returned {resp.status_code}: {resp.text[:300]}")
    try:
        return resp.json()
    except ValueError as exc:
        raise ProviderCallError("Provider returned a non-JSON response.") from exc


async def chat(provider_type: str, api_key: Optional[str], base_url: Optional[str], model: str,
               messages: List[Dict[str, Any]], params: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any], Dict[str, int]]:
    """Returns (text, finish_reason, raw_response, usage{prompt_tokens, completion_tokens})."""
    if not api_key:
        raise ProviderCallError("No API key is configured for this connection.")
    params = {k: v for k, v in params.items() if k in PASS_PARAMS and v is not None}

    if provider_type in ("openai", "groq", "azure_openai"):
        if provider_type == "azure_openai" and not base_url:
            raise ProviderCallError("Azure OpenAI connections require a base_url (your resource's endpoint).")
        url = (base_url or DEFAULT_BASE[provider_type]).rstrip("/") + "/chat/completions"
        headers = {"api-key": api_key} if provider_type == "azure_openai" else {"Authorization": f"Bearer {api_key}"}
        msgs = [{k: v for k, v in m.items() if k in ("role", "content", "name", "tool_call_id") and v is not None}
                for m in messages]
        data = await _post(url, headers, {"model": model, "messages": msgs, **params})
        try:
            choice = data["choices"][0]
            text = _text(choice["message"].get("content"))
            finish = choice.get("finish_reason") or "stop"
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise ProviderCallError("Unexpected response shape from provider.") from exc
        u = data.get("usage") or {}
        return text, finish, data, {"prompt_tokens": u.get("prompt_tokens"), "completion_tokens": u.get("completion_tokens")}

    if provider_type == "anthropic":
        system = "\n\n".join(_text(m.get("content")) for m in messages if m["role"] in ("system", "developer"))
        conv: List[Dict[str, Any]] = []
        for m in messages:
            if m["role"] in ("system", "developer"):
                continue
            role = "assistant" if m["role"] == "assistant" else "user"
            text = _text(m.get("content"))
            if m["role"] in ("tool", "function"):
                text = f"[tool output]\n{text}"
            if conv and conv[-1]["role"] == role:          # Anthropic requires alternating roles
                conv[-1]["content"] += "\n\n" + text
            else:
                conv.append({"role": role, "content": text})
        body: Dict[str, Any] = {"model": model, "messages": conv, "max_tokens": params.pop("max_tokens", 1024)}
        if system:
            body["system"] = system
        if "stop" in params:
            stop = params.pop("stop")
            body["stop_sequences"] = [stop] if isinstance(stop, str) else stop
        body.update(params)
        url = (base_url or DEFAULT_BASE["anthropic"]).rstrip("/") + "/messages"
        data = await _post(url, {"x-api-key": api_key, "anthropic-version": "2023-06-01"}, body)
        try:
            text = "".join(b.get("text", "") for b in data.get("content", []))
        except (AttributeError, TypeError) as exc:
            raise ProviderCallError("Unexpected response shape from provider.") from exc
        finish = {"end_turn": "stop", "max_tokens": "length", "stop_sequence": "stop"}.get(data.get("stop_reason"), "stop")
        u = data.get("usage") or {}
        return text, finish, data, {"prompt_tokens": u.get("input_tokens"), "completion_tokens": u.get("output_tokens")}

    # custom: the provider_adapters contract ({"prompt"} -> {"response"|"text"}), plus the messages
    if not base_url:
        raise ProviderCallError("Custom connections require a base_url pointing at the inference endpoint.")
    prompt = "\n\n".join(f"{m['role']}: {_text(m.get('content'))}" for m in messages)
    data = await _post(base_url, {"Authorization": f"Bearer {api_key}"},
                       {"prompt": prompt, "messages": messages, "model": model, **params})
    text = data["response"] if "response" in data else data["text"] if "text" in data else str(data)
    return str(text), "stop", data, {"prompt_tokens": None, "completion_tokens": None}
