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
    Increment ONE counter for the given scope and raise 429 if it exceeds
    `limit`: the client IP's counter, or - when extra_key is given (e.g. one
    account) - that key's counter instead. Each limit applies only to its
    own counter: a per-account check must not also bump and judge the IP
    counter against the (smaller) per-account limit.

    Fail-open on Redis errors: if Redis is down, requests still go through
    (an attacker who can DoS Redis has bigger problems), but a warning
    would normally be logged here.
    """
    if extra_key:
        keys = [f"rl:{scope}:key:{extra_key.lower()}"]
    else:
        keys = [f"rl:{scope}:ip:{_client_ip(request)}"]

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


def refund(request: Request, *, scope: str) -> None:
    """
    Give back the one attempt THIS request spent on the per-IP counter.

    Used after a successful login, so legitimate sign-ins never use up an
    IP's budget. It undoes only its own increment - never clears the
    counter - so knowing one valid password does not reset the limit for
    guesses against other accounts. A counter that already expired is
    not recreated (DECR on a missing key would leave a negative value with
    no TTL, i.e. permanent extra budget).
    """
    key = f"rl:{scope}:ip:{_client_ip(request)}"
    try:
        client = _get_redis()
    except RedisError:
        return
    try:
        if int(client.decr(key)) <= 0:
            client.delete(key)
    except RedisError:
        pass
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


def reset_key(*, scope: str, extra_key: str) -> None:
    """Clear the per-key counter (e.g. one account) after that account
    signed in successfully. The per-IP counter is never cleared."""
    try:
        client = _get_redis()
        client.delete(f"rl:{scope}:key:{extra_key.lower()}")
        client.close()
    except RedisError:
        pass
