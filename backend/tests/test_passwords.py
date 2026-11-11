# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Passwords on bcrypt itself (app/core/security.py), after passlib:

  - every hash passlib wrote still verifies - nothing to migrate - including a
    password longer than 72 bytes, which passlib cut there silently;
  - a new password over 72 bytes is refused where it is set, not cut;
  - a missing or malformed hash is a wrong password, never an error;
  - a sign-in for an unknown organization or user does one bcrypt check, as a
    wrong password does, so its timing does not tell who has an account.
"""

import bcrypt
import pytest
from sqlalchemy import select

from app.core import security
from app.core.security import get_password_hash, verify_password
from app.models import User
from tests.conftest import auth_headers

# made by passlib 1.7.4 with bcrypt 4.0.1 (CryptContext(schemes=["bcrypt"]), 4 rounds)
PASSLIB_HASH = "$2b$04$phtcD7HPezn0tgv47zpUFuhc3Wr98FrnLXa7B5WJwZdB3VXe2ioY2"          # Correct-horse-42
LONG = "ß" * 40 + "tail-beyond-72"                                                     # 94 bytes
PASSLIB_LONG_HASH = "$2b$04$UQmRkJ4d4aK2g59YkhWfPuW7Ft8vBlG8pixV8NiT6mdtEBvTBqrqa"     # LONG, cut to 72


def test_hashes_passlib_wrote_still_verify():
    assert verify_password("Correct-horse-42", PASSLIB_HASH)
    assert not verify_password("Correct-horse-43", PASSLIB_HASH)


def test_a_long_password_passlib_cut_still_signs_in():
    assert verify_password(LONG, PASSLIB_LONG_HASH)
    # what passlib hashed: the first 72 bytes, so anything after them did not count
    assert verify_password("ß" * 36 + "anything", PASSLIB_LONG_HASH)
    assert not verify_password("ß" * 35, PASSLIB_LONG_HASH)


def test_new_hash_round_trip_at_the_configured_cost():
    h = get_password_hash("Correct-horse-42")
    assert h.startswith(f"$2b${security.BCRYPT_ROUNDS:02d}$")
    assert verify_password("Correct-horse-42", h)
    assert not verify_password("correct-horse-42", h)


@pytest.mark.parametrize("password", ["x" * 73, "ß" * 37, "🔑" * 19])   # 73, 74, 76 bytes
def test_a_new_password_over_72_bytes_is_refused_not_cut(password):
    assert security.password_problem(password)
    with pytest.raises(ValueError, match="72 bytes"):
        get_password_hash(password)


def test_exactly_72_bytes_is_fine():
    h = get_password_hash("ß" * 36)
    assert verify_password("ß" * 36, h)


@pytest.mark.parametrize("stored", [None, "", "not-a-hash", "$2b$04$short", "$2b$04$" + "é" * 53])
def test_a_missing_or_malformed_hash_is_a_wrong_password(stored):
    assert verify_password("Correct-horse-42", stored) is False


def _count_checks(monkeypatch) -> list:
    calls = []
    real = bcrypt.checkpw

    def spy(secret, hashed):
        calls.append(hashed[:7])
        return real(secret, hashed)

    monkeypatch.setattr(security.bcrypt, "checkpw", spy)
    return calls


def test_no_hash_still_costs_one_check(monkeypatch):
    calls = _count_checks(monkeypatch)
    assert verify_password("whatever", None) is False
    assert calls == [f"$2b${security.BCRYPT_ROUNDS:02d}$".encode()]


@pytest.mark.asyncio
async def test_sign_in_does_one_check_whoever_it_is_for(client, org_and_users, monkeypatch):
    calls = _count_checks(monkeypatch)
    org, admin = org_and_users["org"], org_and_users["admin"]
    cases = [
        (org.slug, admin.email, "wrong-password-1"),            # a user, a wrong password
        (org.slug, "nobody@example.com", "wrong-password-1"),   # no such user
        ("no-such-org", admin.email, "wrong-password-1"),       # no such organization
    ]
    for slug, email, password in cases:
        calls.clear()
        r = await client.post("/api/v1/auth/login", json={"org_slug": slug, "email": email, "password": password})
        assert r.status_code == 401 and "auth.invalid_credentials" in r.text, r.text
        assert len(calls) == 1, (slug, email, calls)


@pytest.mark.asyncio
async def test_the_api_refuses_a_password_over_72_bytes(client, admin_token, org_and_users):
    long = "Aa1!" * 19   # 76 bytes
    r = await client.post("/api/v1/users/invite", headers=auth_headers(admin_token),
                          json={"email": "long@example.com", "name": "Long", "password": long})
    assert r.status_code == 422 and "72 bytes" in r.text
    r = await client.post("/api/v1/users/me/password", headers=auth_headers(admin_token),
                          json={"current_password": org_and_users["password"], "new_password": long})
    assert r.status_code == 422 and "72 bytes" in r.text


@pytest.mark.asyncio
async def test_an_account_with_a_passlib_hash_signs_in(client, org_and_users, db_session):
    admin = (await db_session.execute(select(User).where(User.id == org_and_users["admin"].id))).scalar_one()
    admin.hashed_password = PASSLIB_LONG_HASH
    await db_session.commit()
    r = await client.post("/api/v1/auth/login", json={"org_slug": org_and_users["org"].slug,
                                                      "email": admin.email, "password": LONG})
    assert r.status_code == 200, r.text
