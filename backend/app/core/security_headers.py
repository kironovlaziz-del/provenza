"""
Security headers on every API response, whatever proxy is in front (the
Caddyfile in deploy/ sets most of them too; a bare nginx sets none).

A pure ASGI middleware, so streamed responses (the gateways' Server-Sent
Events) pass through unbuffered. Headers the endpoint set itself are kept.
"""

from typing import List, Tuple

from app.core.config import settings

_BASE: List[Tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cross-origin-resource-policy", b"same-site"),
]
# JSON is not a page: nothing may run in it or frame it. /docs (dev only) needs scripts.
_API_CSP = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")
_HSTS = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
_DOCS = ("/docs", "/redoc")


def headers_for(path: str, production: bool) -> List[Tuple[bytes, bytes]]:
    out = list(_BASE)
    if not path.startswith(_DOCS):
        out.append(_API_CSP)
    if production:
        out.append(_HSTS)
    return out


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app
        self.production = settings.ENVIRONMENT == "production"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        extra = headers_for(scope.get("path", ""), self.production)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                present = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [
                    (k, v) for k, v in extra if k not in present]
            await send(message)

        await self.app(scope, receive, send_with_headers)
