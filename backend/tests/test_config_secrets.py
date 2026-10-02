# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Production refuses to start with a JWT key that is known or guessable."""

import secrets

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.core.config import Settings, secret_key_problems

PLACEHOLDERS = [
    "your-secret-key-change-in-production",               # the old code default
    "your-super-secret-key-change-this-in-production",    # the old backend/.env.example
    "change-me-generate-a-random-key",                    # the current backend/.env.example
    "test-secret-key-do-not-use-in-production-1234567890",
    "ci-test-secret-key-not-for-production-0123456789abcdef",
]


@pytest.mark.parametrize("key", PLACEHOLDERS)
def test_placeholders_are_rejected(key):
    assert secret_key_problems(key)


@pytest.mark.parametrize("key", ["a" * 64, "01" * 20, "too-short"])
def test_weak_keys_are_rejected(key):
    assert secret_key_problems(key)


def test_generated_keys_pass():
    for _ in range(50):
        assert secret_key_problems(secrets.token_urlsafe(48)) == []
        assert secret_key_problems(secrets.token_hex(32)) == []
        assert secret_key_problems(secrets.token_hex(16)) == []


def _prod(**over):
    values = dict(
        ENVIRONMENT="production",
        SECRET_KEY=secrets.token_urlsafe(48),
        ENCRYPTION_KEY=Fernet.generate_key().decode(),
        POSTGRES_PASSWORD=secrets.token_urlsafe(16),
        REDIS_PASSWORD=secrets.token_urlsafe(16),
    )
    values.update(over)
    return Settings(_env_file=None, **values)


def test_production_starts_with_real_secrets():
    assert _prod().ENVIRONMENT == "production"


def test_production_refuses_the_example_file_key():
    with pytest.raises(ValidationError, match="placeholder"):
        _prod(SECRET_KEY="your-super-secret-key-change-this-in-production")


def test_development_is_not_blocked():
    s = Settings(_env_file=None, ENVIRONMENT="development", SECRET_KEY="dev")
    assert s.SECRET_KEY == "dev"
