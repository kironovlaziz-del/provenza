"""
Credential encryption for Connections.

Provider API keys are encrypted at rest with Fernet (symmetric,
authenticated encryption) using settings.ENCRYPTION_KEY.

In production the key is enforced by config.py, so this module can rely on
it being present. In development, an empty ENCRYPTION_KEY falls back to a
fixed local-only key so a fresh checkout still runs - this is NOT safe for
real credentials and a warning is raised on every encryption call.
"""

import warnings
from typing import Optional
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

_DEV_FALLBACK_KEY = b"KyU3v0Q8yv8dGtj9mZ1cQvV1r7hFZQyq5W3f9pTz9pk="  # local dev only


@lru_cache
def _get_fernet() -> Fernet:
    key = settings.ENCRYPTION_KEY.strip()
    if not key:
        if settings.ENVIRONMENT == "production":
            # config.py should have refused to start, but be defensive.
            raise RuntimeError(
                "ENCRYPTION_KEY is required in production but is empty."
            )
        warnings.warn(
            "ENCRYPTION_KEY is not set - falling back to an insecure "
            "development key. Set ENCRYPTION_KEY in backend/.env before "
            "storing any real provider API keys.",
            stacklevel=2,
        )
        return Fernet(_DEV_FALLBACK_KEY)
    return Fernet(key.encode())


def encrypt_secret(plaintext: str, org_id: Optional[int] = None) -> str:
    """With org_id, an organization that enabled BYOK gets its own data key
    (app/core/keyring.py); otherwise the server key, as before."""
    if org_id is not None:
        from app.core import keyring

        key_id = keyring.active_key_for(org_id)
        if key_id is not None:
            return keyring.encrypt_for_key(key_id, plaintext)
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    if ciphertext.startswith("pvz2:"):  # organization key (BYOK)
        from app.core import keyring

        return keyring.decrypt_v2(ciphertext)
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError(
            "Could not decrypt stored credential - ENCRYPTION_KEY may have "
            "changed since it was saved."
        ) from exc
