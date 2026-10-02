"""
JWT access tokens (PyJWT): string "sub", expiry, signature, the "none"
algorithm, and tokens issued before the switch from python-jose.
"""

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.core.config import settings
from app.core.security import create_access_token
from tests.conftest import auth_headers

URL = "/api/v1/compliance/catalog"


def _payload(token):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], options={"verify_sub": False})


def _sign(payload, key=None, alg=None):
    return jwt.encode(payload, settings.SECRET_KEY if key is None else key, algorithm=alg or settings.ALGORITHM)


def test_sub_is_always_a_string():
    p = jwt.decode(create_access_token({"sub": 5}), settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert p["sub"] == "5" and p["exp"] > datetime.now(timezone.utc).timestamp()


class TestAccessTokens:
    @pytest.mark.asyncio
    async def test_valid_token_works(self, client, admin_token):
        assert (await client.get(URL, headers=auth_headers(admin_token))).status_code == 200

    @pytest.mark.asyncio
    async def test_legacy_numeric_sub_still_accepted(self, client, admin_token):
        p = _payload(admin_token)
        legacy = _sign({**p, "sub": int(p["sub"])})
        assert (await client.get(URL, headers=auth_headers(legacy))).status_code == 200

    @pytest.mark.asyncio
    async def test_rejected_tokens(self, client, admin_token):
        p = _payload(admin_token)
        cases = {
            "expired": _sign({**p, "exp": int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp())}),
            "wrong key": _sign(p, key="x" * 64),
            "alg none": jwt.encode(p, None, algorithm="none"),
            "no sub": _sign({k: v for k, v in p.items() if k != "sub"}),
            "non-numeric sub": _sign({**p, "sub": "admin"}),
            "garbage": "not.a.jwt",
        }
        for name, token in cases.items():
            r = await client.get(URL, headers=auth_headers(token))
            assert r.status_code == 401, (name, r.status_code, r.text)
