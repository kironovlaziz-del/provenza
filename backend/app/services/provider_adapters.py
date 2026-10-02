"""
Provider adapters: the actual outbound HTTP calls to AI providers.

Kept deliberately separate from RequestService so the request/policy/audit
flow doesn't need to know the wire format of any given provider. Add a new
`type` branch here to support another provider without touching anything
else in the request pipeline.

A single long-lived AsyncClient is shared across requests so TCP
connections and TLS sessions are reused. httpx's connection pool handles
concurrency internally.
"""

from typing import Any, Dict, Optional, Tuple

import httpx

from app.core.outbound import error_detail, guarded_async_client

DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=10.0)

# One shared client for the lifetime of the process. httpx.AsyncClient is
# safe to use concurrently and pools connections by (scheme, host, port).
_http_client: Optional[httpx.AsyncClient] = None


def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        # Guarded: base URLs are admin-supplied, so private/internal targets
        # are refused at connect time (core/outbound.py).
        _http_client = guarded_async_client(
            timeout=DEFAULT_TIMEOUT,
            limits=httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
            ),
        )
    return _http_client


class ProviderCallError(Exception):
    """Raised for any failure calling out to a provider - network, auth, or
    an error response. The message is safe to surface to the end user."""


async def call_provider(
    provider_type: str,
    api_key: Optional[str],
    base_url: Optional[str],
    default_model: Optional[str],
    prompt: str,
) -> Tuple[str, Dict[str, Any]]:
    if not api_key:
        raise ProviderCallError(
            "No API key is configured for this connection. Add one from "
            "Connections before sending live requests."
        )

    if provider_type == "openai":
        return await _call_openai_compatible(
            api_key,
            base_url or "https://api.openai.com/v1",
            default_model or "gpt-4o-mini",
            prompt,
        )
    if provider_type == "azure_openai":
        if not base_url:
            raise ProviderCallError(
                "Azure OpenAI connections require a base_url (your resource's endpoint)."
            )
        return await _call_openai_compatible(
            api_key, base_url, default_model or "gpt-4o-mini", prompt, azure=True
        )
    if provider_type == "groq":
        return await _call_openai_compatible(
            api_key,
            base_url or "https://api.groq.com/openai/v1",
            default_model or "llama-3.3-70b-versatile",
            prompt,
        )
    if provider_type == "anthropic":
        return await _call_anthropic(
            api_key,
            base_url or "https://api.anthropic.com/v1",
            default_model or "claude-3-5-haiku-20241022",
            prompt,
        )

    if not base_url:
        raise ProviderCallError(
            "Custom connections require a base_url pointing at the inference endpoint."
        )
    return await _call_custom(api_key, base_url, prompt)


async def _call_openai_compatible(
    api_key: str, base_url: str, model: str, prompt: str, azure: bool = False
) -> Tuple[str, Dict[str, Any]]:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {"api-key": api_key} if azure else {"Authorization": f"Bearer {api_key}"}
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }
    client = _get_client()
    try:
        resp = await client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise ProviderCallError(f"Network error calling provider: {exc}") from exc

    if resp.status_code >= 400:
        raise ProviderCallError(f"Provider returned {error_detail(resp)}")

    data = resp.json()
    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderCallError("Unexpected response shape from provider.") from exc
    return text, data


async def _call_anthropic(
    api_key: str, base_url: str, model: str, prompt: str
) -> Tuple[str, Dict[str, Any]]:
    url = base_url.rstrip("/") + "/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    body = {
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    client = _get_client()
    try:
        resp = await client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise ProviderCallError(f"Network error calling provider: {exc}") from exc

    if resp.status_code >= 400:
        raise ProviderCallError(f"Provider returned {error_detail(resp)}")

    data = resp.json()
    try:
        text = "".join(block.get("text", "") for block in data.get("content", []))
    except (AttributeError, TypeError) as exc:
        raise ProviderCallError("Unexpected response shape from provider.") from exc
    return text, data


async def _call_custom(api_key: str, base_url: str, prompt: str) -> Tuple[str, Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    client = _get_client()
    try:
        resp = await client.post(base_url, headers=headers, json={"prompt": prompt})
    except httpx.HTTPError as exc:
        raise ProviderCallError(f"Network error calling provider: {exc}") from exc

    if resp.status_code >= 400:
        raise ProviderCallError(f"Provider returned {error_detail(resp)}")

    data = resp.json()
    # Note: values like 0 or "" are valid responses - do not use `or`,
    # which would skip them and fall through to str(data).
    if "response" in data:
        text = data["response"]
    elif "text" in data:
        text = data["text"]
    else:
        text = str(data)
    return text, data
