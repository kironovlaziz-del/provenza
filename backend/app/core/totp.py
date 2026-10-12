"""
Time-based one-time passwords (RFC 6238; HMAC-SHA1, 30 s, 6 digits) - what
every authenticator app speaks - and recovery codes. Standard library only.

A code is accepted for the current 30-second step and one step either side
(clock drift), and only once: the step it matched is remembered, so a code
seen over someone's shoulder cannot be replayed.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional, Tuple
from urllib.parse import quote, urlencode

STEP = 30
DIGITS = 6
WINDOW = 1
RECOVERY_CODES = 10


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)


def code_at(secret: str, counter: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def verify(secret: str, code: str, last_counter: Optional[int], now: Optional[float] = None) -> Optional[int]:
    """The time step the code belongs to, or None. A step at or before
    last_counter is refused (already used)."""
    code = "".join(code.split())
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for counter in range(current - WINDOW, current + WINDOW + 1):
        if last_counter is not None and counter <= last_counter:
            continue
        if hmac.compare_digest(code_at(secret, counter), code):
            return counter
    return None


def otpauth_uri(secret: str, account: str, issuer: str = "Provenza") -> str:
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?" + urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                                                    "digits": DIGITS, "period": STEP})


def _hash(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").lower().encode()).hexdigest()


def new_recovery_codes() -> Tuple[List[str], List[str]]:
    """(codes to show once, their hashes to store)."""
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(RECOVERY_CODES)]
    return codes, [_hash(c) for c in codes]


def use_recovery_code(hashes: List[str], code: str) -> Optional[List[str]]:
    """The remaining hashes if the code is one of them (it is used up), else None."""
    h = _hash("".join(code.split()))
    for stored in hashes:
        if hmac.compare_digest(stored, h):
            return [x for x in hashes if x != stored]
    return None
