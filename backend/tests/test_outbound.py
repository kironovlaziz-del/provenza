# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
SSRF guard for outbound calls to user-configured URLs (core/outbound.py).

The guard lives in the connection layer: these tests drive real httpx
clients at blocked addresses (nothing is sent - the connect is refused
before a socket opens) and fake the resolver for hostnames, so the suite
is hermetic.
"""

import ipaddress
import socket

import httpx
import pytest
from pydantic import ValidationError

from app.core import outbound
from app.core.config import settings
from app.schemas.byok import KeyConfigIn
from app.schemas.provider import ProviderCreate, ProviderUpdate


def ip(s):
    return ipaddress.ip_address(s)


@pytest.fixture
def allow(monkeypatch):
    def _set(value: str):
        monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", value)
    _set("")
    return _set


def fake_dns(monkeypatch, table):
    """Resolve names from `table` ({host: [ip, ...]}) for both backends."""
    def infos(host, port):
        if host not in table:
            raise socket.gaierror("unknown host")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in table[host]]

    async def agetaddrinfo(host, port, **kw):
        return infos(host, port)

    monkeypatch.setattr(outbound.anyio, "getaddrinfo", agetaddrinfo)
    monkeypatch.setattr(outbound.socket, "getaddrinfo", lambda host, port, **kw: infos(host, port))


class TestPolicy:
    @pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public_addresses_pass(self, allow, addr):
        assert outbound.ip_allowed(ip(addr))

    @pytest.mark.parametrize("addr", [
        "127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "100.64.0.1",
        "0.0.0.0", "169.254.169.254", "224.0.0.1", "::1", "fd00::1", "fe80::1",
        "::ffff:127.0.0.1", "::ffff:169.254.169.254",
        # IPv6 forms that lead to an internal IPv4 address
        "64:ff9b::a00:5", "64:ff9b::a9fe:a9fe", "::ffff:0:a9fe:a9fe", "::127.0.0.1", "2002:a00:1::1",
    ])
    def test_internal_addresses_blocked_by_default(self, allow, addr):
        assert not outbound.ip_allowed(ip(addr))

    def test_allowlist_cidr_and_hostname(self, allow):
        allow("10.20.0.0/16, vault.corp.local")
        assert outbound.ip_allowed(ip("10.20.1.1"))
        assert not outbound.ip_allowed(ip("10.21.0.1"))
        assert outbound.ip_allowed(ip("10.99.0.7"), host="vault.corp.local")
        assert outbound.ip_allowed(ip("10.99.0.7"), host="VAULT.corp.local.")

    def test_metadata_never_allowed_even_if_listed(self, allow):
        allow("169.254.0.0/16,169.254.169.254")
        assert not outbound.ip_allowed(ip("169.254.169.254"))


class TestValidateUrl:
    @pytest.mark.parametrize("url", ["https://api.example.com/v1", "http://llm.internal:8080",
                                     "https://10.20.0.4/v1"])
    def test_accepts(self, allow, url):
        allow("10.20.0.0/16")
        assert outbound.validate_url(url) == url

    @pytest.mark.parametrize("url", ["ftp://example.com", "example.com/v1", "https://user:pw@example.com",
                                     "http://127.0.0.1:11434", "http://169.254.169.254/latest",
                                     "http://[::1]/", "http://0.0.0.0/"])
    def test_rejects(self, allow, url):
        with pytest.raises(ValueError):
            outbound.validate_url(url)

    def test_provider_schema_rejects_internal_base_url(self, allow):
        with pytest.raises(ValidationError):
            ProviderCreate(name="x", type="custom", base_url="http://169.254.169.254/latest/meta-data")
        with pytest.raises(ValidationError):
            ProviderUpdate(base_url="http://127.0.0.1:6379")
        assert ProviderUpdate(base_url="").base_url is None
        assert ProviderCreate(name="x", type="openai", base_url="https://api.example.com/v1").base_url

    def test_vault_addr_rejects_internal_literal(self, allow):
        with pytest.raises(ValidationError):
            KeyConfigIn(provider="vault_transit", addr="http://127.0.0.1:8200", key_name="k", token="t")


class TestConnectGuard:
    async def test_async_client_refuses_loopback_before_connecting(self, allow):
        async with outbound.guarded_async_client(timeout=5) as c:
            with pytest.raises(httpx.ConnectError, match="Outbound connection refused"):
                await c.get("http://127.0.0.1:1/")

    def test_sync_client_refuses_metadata(self, allow):
        with outbound.guarded_client(timeout=5) as c:
            with pytest.raises(httpx.ConnectError, match="Outbound connection refused"):
                c.get("http://169.254.169.254/latest/meta-data/")

    async def test_hostname_resolving_inside_is_refused(self, allow, monkeypatch):
        # DNS rebinding: the name is only judged by what it resolves to at connect time.
        fake_dns(monkeypatch, {"rebind.example": ["10.0.0.9"]})
        async with outbound.guarded_async_client(timeout=5) as c:
            with pytest.raises(httpx.ConnectError, match="Outbound connection refused"):
                await c.post("https://rebind.example/v1/chat/completions", json={})

    async def test_any_internal_record_refuses_the_whole_name(self, allow, monkeypatch):
        fake_dns(monkeypatch, {"mixed.example": ["93.184.216.34", "127.0.0.1"]})
        async with outbound.guarded_async_client(timeout=5) as c:
            with pytest.raises(httpx.ConnectError):
                await c.get("https://mixed.example/")

    async def test_connects_to_the_address_it_checked(self, allow, monkeypatch):
        fake_dns(monkeypatch, {"api.example.com": ["93.184.216.34"]})
        seen = {}

        class Inner:
            async def connect_tcp(self, host, port, **kw):
                seen["host"], seen["port"] = host, port
                raise OSError("stop here")

        backend = outbound._GuardedAsyncBackend(Inner())
        with pytest.raises(OSError, match="stop here"):
            await backend.connect_tcp("api.example.com", 443)
        assert seen == {"host": "93.184.216.34", "port": 443}

    async def test_allowlisted_internal_host_passes_the_guard(self, allow, monkeypatch):
        allow("vault.corp.local")
        fake_dns(monkeypatch, {"vault.corp.local": ["10.1.2.3"]})
        seen = {}

        class Inner:
            def connect_tcp(self, host, port, **kw):
                seen["host"] = host
                raise OSError("stop here")

        backend = outbound._GuardedSyncBackend(Inner())
        with pytest.raises(OSError, match="stop here"):
            backend.connect_tcp("vault.corp.local", 8200)
        assert seen["host"] == "10.1.2.3"

    def test_redirects_and_env_proxies_are_off(self):
        c = outbound.guarded_client()
        assert c.follow_redirects is False and c.trust_env is False
        c.close()


class TestErrorDetail:
    def test_json_error_message_is_kept(self):
        r = httpx.Response(401, json={"error": {"message": "Invalid API key"}})
        assert outbound.error_detail(r) == "401: Invalid API key"

    def test_raw_body_is_never_echoed(self):
        r = httpx.Response(500, text="<html>internal admin panel secrets</html>")
        assert outbound.error_detail(r) == "500"


def test_proxy_mode_still_refuses_internal_targets(allow, monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PROXY", "http://proxy.corp.local:3128")
    with outbound.guarded_client(timeout=5) as c:
        with pytest.raises(httpx.ConnectError, match="Outbound connection refused"):
            c.get("http://169.254.169.254/latest/meta-data/")
