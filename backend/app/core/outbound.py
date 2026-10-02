# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Outbound HTTP to user-configured addresses: AI providers, the gateway's
upstreams, Vault Transit, webhooks.

Any of these URLs is typed in by an org admin, so without a guard the
server can be pointed at its own network (127.0.0.1, 10.x, the cloud
metadata service at 169.254.169.254) and used as a proxy into it (SSRF).

The guard sits in the connection layer, not in front of the request: the
client resolves the host, checks EVERY address it resolves to, and then
connects to that same checked address. Checking first and connecting
later would let a hostname resolve to a public address for the check and
a private one for the connection (DNS rebinding). TLS still verifies the
certificate against the hostname - only the TCP connect uses the IP.

Policy:
  - always refused: link-local (incl. cloud metadata), unspecified,
    multicast;
  - every other non-global range (private, loopback, reserved, CGNAT
    100.64/10, ...) is refused unless the operator
    lists them in OUTBOUND_PRIVATE_ALLOWLIST (comma-separated hostnames,
    IPs or CIDRs) - e.g. an in-house Vault or a local Ollama:
        OUTBOUND_PRIVATE_ALLOWLIST=vault.corp.local,10.20.0.0/16
  - redirects are never followed and HTTP(S)_PROXY from the environment
    is ignored, so the checked address is the one actually contacted;
  - where outbound traffic must go through a proxy, set OUTBOUND_PROXY:
    the target is then resolved and checked before the request is sent,
    and the proxy connects. The proxy resolves the name again, so DNS
    rebinding protection is weaker there - restrict the proxy's own
    egress to the internet if you rely on it.

Error messages say that a target was refused, never which address a name
resolved to.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, List, Optional, Union
from urllib.parse import urlparse

import anyio
import httpcore
import httpx

from app.core.config import settings

IP = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

BLOCKED_MESSAGE = (
    "Outbound connection refused: the target resolves to a private or internal "
    "address. If this is your own service (for example an in-house Vault or a "
    "local model server), the server operator can allow it with "
    "OUTBOUND_PRIVATE_ALLOWLIST."
)


class OutboundBlocked(httpcore.ConnectError):
    """The target is not allowed. Subclasses httpcore.ConnectError so httpx
    reports it as httpx.ConnectError and existing network-error handling
    applies unchanged."""


def _allowlist() -> tuple[set[str], list]:
    hosts: set[str] = set()
    nets: list = []
    for item in (settings.OUTBOUND_PRIVATE_ALLOWLIST or "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            hosts.add(item.rstrip("."))
    return hosts, nets


# IPv6 prefixes that carry an IPv4 address in their low 32 bits and reach it
# through a translator (NAT64, SIIT): 64:ff9b::a00:5 is 10.0.0.5.
_V4_EMBEDDING_NETS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("::ffff:0:0:0/96"),
)
# Deprecated IPv4-compatible addresses (::a.b.c.d) - never a real target.
_V4_COMPATIBLE = ipaddress.ip_network("::/96")


def _effective(ip: IP) -> List[IP]:
    """The address itself plus every IPv4 address it actually leads to."""
    out: List[IP] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            out.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            out.append(ip.sixtofour)
        if ip.teredo is not None:
            out.extend(ip.teredo)
        for net in _V4_EMBEDDING_NETS:
            if ip in net:
                out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def _one_allowed(ip: IP, hosts: set, nets: list, host: Optional[str]) -> bool:
    if ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip in _V4_COMPATIBLE:
        return False
    if ip.is_global:
        return True
    # private, loopback, reserved, CGNAT 100.64/10, documentation ranges...
    if host and host.lower().rstrip(".") in hosts:
        return True
    return any(ip in net for net in nets)


def ip_allowed(ip: IP, host: Optional[str] = None) -> bool:
    """Whether a connection to `ip` (reached via name `host`) is allowed.
    An IPv6 address that embeds an IPv4 one (mapped, 6to4, Teredo, NAT64)
    is judged by both."""
    hosts, nets = _allowlist()
    candidates = _effective(ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        candidates = [ip.ipv4_mapped]  # ::ffff:a.b.c.d is just a.b.c.d
    return all(_one_allowed(c, hosts, nets, host) for c in candidates)


def check_addresses(host: str, addresses: Iterable[str]) -> List[str]:
    """Return the addresses if ALL of them are allowed, else raise."""
    out = []
    for a in addresses:
        try:
            ip = ipaddress.ip_address(a.split("%", 1)[0])
        except ValueError as exc:
            raise OutboundBlocked(BLOCKED_MESSAGE) from exc
        if not ip_allowed(ip, host):
            raise OutboundBlocked(BLOCKED_MESSAGE)
        out.append(a)
    if not out:
        raise OutboundBlocked(f"Could not resolve host '{host}'.")
    return out


def validate_url(url: str) -> str:
    """Create/update-time check of a user-supplied base URL (no DNS lookup):
    http(s) only, a host present, and not a literal blocked IP. Raises
    ValueError with a message fit for a 422."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("URL must include a host")
    if parsed.username or parsed.password:
        raise ValueError("URL must not contain credentials")
    try:
        ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return url
    if not ip_allowed(ip, parsed.hostname):
        raise ValueError(BLOCKED_MESSAGE)
    return url


# ---------------------------------------------------------------------------
# connection-layer guard
# ---------------------------------------------------------------------------

class _GuardedAsyncBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, inner: httpcore.AsyncNetworkBackend):
        self._inner = inner

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            ipaddress.ip_address(host)
            addrs = [host]
        except ValueError:
            try:
                infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise OutboundBlocked(f"Could not resolve host '{host}'.") from exc
            addrs = list(dict.fromkeys(str(i[4][0]) for i in infos))
        addrs = check_addresses(host, addrs)
        last: Optional[Exception] = None
        for addr in addrs:  # every address passed the check; try them in order
            try:
                return await self._inner.connect_tcp(addr, port, timeout=timeout,
                                                     local_address=local_address, socket_options=socket_options)
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last  # type: ignore[misc]

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
        raise OutboundBlocked("Unix sockets are not allowed for outbound calls.")

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


class _GuardedSyncBackend(httpcore.NetworkBackend):
    def __init__(self, inner: httpcore.NetworkBackend):
        self._inner = inner

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            ipaddress.ip_address(host)
            addrs = [host]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise OutboundBlocked(f"Could not resolve host '{host}'.") from exc
            addrs = list(dict.fromkeys(str(i[4][0]) for i in infos))
        addrs = check_addresses(host, addrs)
        last: Optional[Exception] = None
        for addr in addrs:
            try:
                return self._inner.connect_tcp(addr, port, timeout=timeout,
                                               local_address=local_address, socket_options=socket_options)
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        raise last  # type: ignore[misc]

    def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
        raise OutboundBlocked("Unix sockets are not allowed for outbound calls.")

    def sleep(self, seconds):
        self._inner.sleep(seconds)


def _guard_async(transport: httpx.AsyncHTTPTransport) -> httpx.AsyncHTTPTransport:
    pool = transport._pool  # httpx 0.28: the httpcore connection pool
    pool._network_backend = _GuardedAsyncBackend(pool._network_backend)
    return transport


def _guard_sync(transport: httpx.HTTPTransport) -> httpx.HTTPTransport:
    pool = transport._pool
    pool._network_backend = _GuardedSyncBackend(pool._network_backend)
    return transport


def _target_addresses(host: str, port: int) -> List[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OutboundBlocked(f"Could not resolve host '{host}'.") from exc
    return list(dict.fromkeys(str(i[4][0]) for i in infos))


def _precheck(request: httpx.Request) -> None:
    """Proxy mode: the proxy connects, so the target is checked here, by
    resolving it ourselves before the request leaves. Weaker than the
    connect-time guard (the proxy resolves again), hence documented."""
    url = request.url
    try:
        check_addresses(url.host, _target_addresses(url.host, url.port or (443 if url.scheme == "https" else 80)))
    except OutboundBlocked as exc:
        raise httpx.ConnectError(str(exc), request=request) from exc


async def _aprecheck(request: httpx.Request) -> None:
    await anyio.to_thread.run_sync(_precheck, request)


def guarded_async_client(**kwargs) -> httpx.AsyncClient:
    """httpx.AsyncClient for user-configured targets (see module docstring)."""
    limits = kwargs.pop("limits", httpx.Limits(max_keepalive_connections=20, max_connections=100))
    if settings.OUTBOUND_PROXY:
        return httpx.AsyncClient(proxy=settings.OUTBOUND_PROXY, limits=limits, follow_redirects=False,
                                 trust_env=False, event_hooks={"request": [_aprecheck]}, **kwargs)
    transport = _guard_async(httpx.AsyncHTTPTransport(limits=limits))
    return httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False, **kwargs)


def guarded_client(**kwargs) -> httpx.Client:
    """Synchronous counterpart of guarded_async_client."""
    if settings.OUTBOUND_PROXY:
        return httpx.Client(proxy=settings.OUTBOUND_PROXY, follow_redirects=False, trust_env=False,
                            event_hooks={"request": [_precheck]}, **kwargs)
    transport = _guard_sync(httpx.HTTPTransport())
    return httpx.Client(transport=transport, follow_redirects=False, trust_env=False, **kwargs)


def error_detail(resp: httpx.Response, limit: int = 200) -> str:
    """A short, safe description of an upstream error response: the status
    and, when the body is JSON, its error message field - never the raw
    body (which could be any page the target chose to return)."""
    msg = ""
    try:
        data = resp.json()
    except ValueError:
        data = None
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            msg = err.get("message") or ""
        elif isinstance(err, str):
            msg = err
        msg = msg or data.get("message") or ""
        if not msg and isinstance(data.get("errors"), list) and data["errors"]:
            msg = str(data["errors"][0])
    msg = str(msg).strip().replace("\n", " ")[:limit]
    return f"{resp.status_code}: {msg}" if msg else str(resp.status_code)
