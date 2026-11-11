import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import hmac
import secrets
import bcrypt
import jwt
from app.core.config import settings

# ---------------------------------------------------------------------------
# Passwords: bcrypt, called directly (passlib, which wrapped it, is no longer
# maintained and breaks with bcrypt 4.1+).
#
# bcrypt reads at most 72 bytes of a password. passlib cut longer ones there
# silently, and bcrypt 5 refuses them instead. So:
#   - a new password longer than 72 bytes (UTF-8) is refused where it is set
#     (password_problem, the schemas, create_admin);
#   - a password is checked against a stored hash by its first 72 bytes, as
#     passlib made those hashes - an old long password still signs in.
# The hashes passlib wrote ($2b$, 12 rounds) are plain bcrypt: nothing to
# migrate.
# ---------------------------------------------------------------------------

BCRYPT_ROUNDS = 12          # ~0.25 s a hash; tests lower it (tests/conftest.py)
MAX_PASSWORD_BYTES = 72     # all bcrypt reads

# Checked when there is no stored hash to check against (an unknown user or
# organization): the answer then takes as long as a wrong password does, so
# its timing does not tell which accounts exist. Made once, on first use.
_dummy_hash: Optional[bytes] = None


def password_problem(password: str) -> Optional[str]:
    """Why a new password cannot be set (None: it can)."""
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"password must be at most {MAX_PASSWORD_BYTES} bytes (UTF-8)"
    return None


def verify_password(plain_password: str, hashed_password: Optional[str]) -> bool:
    """Whether the password matches the stored bcrypt hash. Never raises: a
    missing or malformed hash is a wrong password. Without a hash (None) it
    still does the work of one check, so it takes as long."""
    secret = (plain_password or "").encode("utf-8")[:MAX_PASSWORD_BYTES]
    if not hashed_password:
        bcrypt.checkpw(secret, _dummy())
        return False
    try:
        return bcrypt.checkpw(secret, hashed_password.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return False


def get_password_hash(password: str) -> str:
    problem = password_problem(password)
    if problem:
        raise ValueError(problem)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def _dummy() -> bytes:
    global _dummy_hash
    if _dummy_hash is None or _dummy_hash[4:6] != f"{BCRYPT_ROUNDS:02d}".encode():
        _dummy_hash = bcrypt.hashpw(secrets.token_bytes(16).hex().encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
    return _dummy_hash

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    # iat: compared with users.sessions_valid_after; jti: what logout revokes (app/core/sessions.py)
    to_encode.update({"exp": expire, "iat": round(time.time(), 3), "jti": uuid.uuid4().hex})
    if "sub" in to_encode:  # RFC 7519: "sub" is a string; PyJWT enforces it
        to_encode["sub"] = str(to_encode["sub"])
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


# ---------------------------------------------------------------------------
# API keys for machine identities (IngestionSource, and any future
# service-to-service credential). Deliberately NOT bcrypt: bcrypt is
# designed to slow down brute-forcing a low-entropy human password, and
# also silently truncates input at 72 bytes. These keys are generated
# with 32 bytes of real randomness (256 bits), so offline brute force is
# infeasible regardless of hash speed - a fast, unbounded-length digest
# (SHA-256) is the standard, correct choice here (this is how GitHub/
# Stripe-style API tokens are verified).
# ---------------------------------------------------------------------------

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)

def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

def verify_api_key(raw_key: str, hashed_key: str) -> bool:
    return hmac.compare_digest(hash_api_key(raw_key), hashed_key)
