"""Sign-in limits refuse when the counter store is down; others fail open."""

import pytest
from redis.exceptions import RedisError

from app.core import rate_limit


class _Down:
    def pipeline(self):
        raise RedisError("down")

    def close(self):
        pass


class _Req:
    headers = {}
    client = type("C", (), {"host": "203.0.113.9"})()


def test_login_limit_refuses_when_redis_is_down(monkeypatch):
    monkeypatch.setattr(rate_limit, "_get_redis", lambda: _Down())
    with pytest.raises(Exception) as exc:
        rate_limit.enforce(_Req(), scope="login", limit=5, window_seconds=60)
    assert getattr(exc.value, "status_code", None) == 503


def test_other_limits_fail_open(monkeypatch):
    monkeypatch.setattr(rate_limit, "_get_redis", lambda: _Down())
    rate_limit.enforce(_Req(), scope="egress_beacon", limit=5, window_seconds=60)
