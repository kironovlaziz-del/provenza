from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import hmac
import secrets
import jwt
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
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
