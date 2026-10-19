"""
The shared outbound HTTP client for AI providers, and the error every
provider call raises. The wire formats live in services/gateway_adapters.py.

A single long-lived AsyncClient is shared across requests so TCP
connections and TLS sessions are reused. httpx's connection pool handles
concurrency internally.
"""

from typing import Optional

import httpx

from app.core.outbound import guarded_async_client
from app.services import provider_policy

DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=10.0)

# One shared client for the lifetime of the process. httpx.AsyncClient is
# safe to use concurrently and pools connections by (scheme, host, port).
_http_client: Optional[httpx.AsyncClient] = None


_internal_client: Optional[httpx.AsyncClient] = None


def _get_client() -> httpx.AsyncClient:
    """The shared client - the internal-only one while the organization's
    policy allows only self-hosted providers (services/provider_policy.py)."""
    global _http_client, _internal_client
    if provider_policy.self_hosted_only():
        if _internal_client is None:
            _internal_client = guarded_async_client(
                internal_only=True, timeout=DEFAULT_TIMEOUT,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
            )
        return _internal_client
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
