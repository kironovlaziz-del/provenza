"""
Ending user sessions before their JWT expires.

  logout           the token's id (jti) is revoked in Redis until the token
                   would have expired anyway
  password change  users.sessions_valid_after: every token issued before it
                   stops working, on every device

Redis down: a revoked token keeps working until it expires (at most
ACCESS_TOKEN_EXPIRE_MINUTES) - the same fail-open choice as the rate limiter;
sessions_valid_after does not depend on Redis.
"""

import time
from typing import Optional

from redis.exceptions import RedisError

from app.core import rate_limit

_PREFIX = "session:revoked:"


def revoke(jti: Optional[str], exp: Optional[int]) -> None:
    if not jti or not exp:
        return
    ttl = int(exp - time.time())
    if ttl <= 0:
        return
    try:
        client = rate_limit._get_redis()
        try:
            client.set(_PREFIX + jti, "1", ex=ttl)
        finally:
            client.close()
    except RedisError:
        return


def is_revoked(jti: Optional[str]) -> bool:
    if not jti:
        return False
    try:
        client = rate_limit._get_redis()
        try:
            return bool(client.exists(_PREFIX + jti))
        finally:
            client.close()
    except RedisError:
        return False
