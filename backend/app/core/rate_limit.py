"""
Redis-backed rate limiter.

A sliding-window counter is not required for our use case - fixed windows
keyed by the current time bucket are simpler and behave predictably under
bursts. Each key stores an INCR counter with a TTL equal to the window
length, so the counter is automatically cleaned up by Redis.

Used by /auth/login to slow down brute-force attempts both from a single
IP and against a single email (in case the attacker rotates IPs).
"""

import os

from fastapi import HTTPException, Request, status
from redis import Redis
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.errors import api_error


def _get_redis() -> Redis:
    """Synchronous Redis client - rate-limit checks happen on the request
    hot path, and a single INCR call is fast enough that an async client
    would be overkill. Falls back to a lazy connection."""
    return Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD or None,
        socket_connect_timeout=1,
        socket_timeout=1,
        decode_responses=True,
    )


# Peers whose forwarding headers we believe: the reverse proxy (nginx) that
# sits in front of uvicorn. Anything else could set X-Forwarded-For /
# X-Real-IP to any value and walk around the per-IP limit.
_TRUSTED_PROXIES = {
    p.strip() for p in os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if p.strip()
}


def _client_ip(request: Request) -> str:
    """The client address used for per-IP rate limiting.

    Forwarding headers are honoured ONLY when the TCP peer is a trusted
    proxy. nginx sets X-Real-IP to $remote_addr, which the client cannot
    influence; as a fallback we take the LAST X-Forwarded-For entry (the
    one appended by our proxy), never the first (client-controlled)."""
    peer = request.client.host if request.client else "unknown"
    if peer in _TRUSTED_PROXIES:
        real_ip = (request.headers.get("x-real-ip") or "").strip()
        if real_ip:
            return real_ip
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[-1].strip()
    return peer


def enforce(
    request: Request,
    *,
    scope: str,
    limit: int,
    window_seconds: int,
    extra_key: str | None = None,
) -> None:
    """
    Increment the counter for the given scope (per-IP, optionally also per
    extra_key, e.g. an email) and raise 429 if the limit is exceeded.

    Fail-open on Redis errors: if Redis is down, requests still go through
    (an attacker who can DoS Redis has bigger problems), but a warning
    would normally be logged here.
    """
    keys: list[str] = []
    ip = _client_ip(request)
    keys.append(f"rl:{scope}:ip:{ip}")
    if extra_key:
        keys.append(f"rl:{scope}:key:{extra_key.lower()}")

    try:
        client = _get_redis()
    except RedisError:
        return

    try:
        for key in keys:
            pipe = client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)
            count, _ = pipe.execute()
            if int(count) > limit:
                err = api_error(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "auth.rate_limited",
                    retry_after=window_seconds,
                )
                err.headers = {"Retry-After": str(window_seconds)}
                raise err
    except HTTPException:
        raise
    except RedisError:
        # Fail-open: log in a real deployment, but don't block logins
        # because the cache is unreachable.
        return
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


def reset(*, scope: str, extra_key: str, ip: str | None = None) -> None:
    """
    Clear counters after a successful login. We drop both the per-IP and
    per-email counters for this scope, so a legitimate user who mistyped
    their password a few times is not penalised after a success.
    """
    keys = [f"rl:{scope}:key:{extra_key.lower()}"]
    if ip:
        keys.append(f"rl:{scope}:ip:{ip}")
    try:
        client = _get_redis()
        client.delete(*keys)
        client.close()
    except RedisError:
        pass
