"""
Per-IP rate limiting must not be bypassable by forging forwarding headers.
Headers are trusted only when the TCP peer is our reverse proxy.
"""

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.core import rate_limit


def _req(peer, headers=None):
    return Request({
        "type": "http", "method": "POST", "path": "/api/v1/auth/login", "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": (peer, 40000) if peer else None,
    })


class TestClientIp:
    def test_direct_client_cannot_spoof_x_forwarded_for(self):
        assert rate_limit._client_ip(_req("203.0.113.9", {"X-Forwarded-For": "1.2.3.4"})) == "203.0.113.9"

    def test_direct_client_cannot_spoof_x_real_ip(self):
        assert rate_limit._client_ip(_req("203.0.113.9", {"X-Real-IP": "1.2.3.4"})) == "203.0.113.9"

    def test_trusted_proxy_x_real_ip_is_used(self):
        assert rate_limit._client_ip(_req("127.0.0.1", {"X-Real-IP": "198.51.100.7"})) == "198.51.100.7"

    def test_trusted_proxy_uses_last_forwarded_entry_not_first(self):
        # client sent "X-Forwarded-For: 1.2.3.4"; nginx appended the real peer
        req = _req("127.0.0.1", {"X-Forwarded-For": "1.2.3.4, 198.51.100.7"})
        assert rate_limit._client_ip(req) == "198.51.100.7"

    def test_no_peer_info(self):
        assert rate_limit._client_ip(_req(None)) == "unknown"


def test_rotating_forged_headers_still_hit_the_limit():
    # attacker talks to uvicorn directly and changes X-Forwarded-For every time
    for i in range(3):
        rate_limit.enforce(_req("203.0.113.9", {"X-Forwarded-For": f"10.0.0.{i}"}),
                           scope="login", limit=3, window_seconds=60)
    with pytest.raises(HTTPException) as exc:
        rate_limit.enforce(_req("203.0.113.9", {"X-Forwarded-For": "10.0.0.99"}),
                           scope="login", limit=3, window_seconds=60)
    assert exc.value.status_code == 429
