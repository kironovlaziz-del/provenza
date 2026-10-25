# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The keys people sign with (docs/pvp/edge.md, section 2): their passkeys,
and the session each sign-in of an administrator or approver opens.
"""

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.core.database import Base


class UserPasskey(Base):
    """A WebAuthn credential of a person. Only the public key is here; the
    private key stays on the person's device, unlocked by its PIN."""

    __tablename__ = "user_passkeys"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    credential_id = Column(String(1400), nullable=False, unique=True)     # base64url
    public_key = Column(Text, nullable=False)                             # base64url COSE_Key
    alg = Column(Integer, nullable=False)                                 # COSE: -7, -8, -257
    sign_count = Column(BigInteger, nullable=False, default=0)
    label = Column(String(100), nullable=False)
    # a person who already had a passkey adds another only with it
    vouched_by_passkey_id = Column(Integer, ForeignKey("user_passkeys.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))


class SigningSession(Base):
    """One sign-in of a person who signs (an administrator or approver).

    status   active    may act; at most one per person at a time
             blocked   a second sign-in while one was active: it can do
                       nothing until the active session lets it in with the
                       passkey, or it ends the other one with its own passkey
             ended     signed out, ended by the other session, or replaced

    The session key is generated in the browser, non-extractable; the
    passkey certifies its public key for the session's lifetime
    (certificate). The server holds no private key."""

    __tablename__ = "signing_sessions"

    id = Column(String(32), primary_key=True)                             # the JWT's "sid"
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(10), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    ended_at = Column(DateTime(timezone=True))
    end_reason = Column(String(40))
    ip = Column(String(64))
    user_agent = Column(String(300))
    public_key = Column(String(100))                                      # Ed25519, base64url
    certificate = Column(JSONB)          # {"statement", "passkey_id", "credential_id", "assertion"}
    certified_at = Column(DateTime(timezone=True))
    admitted_by = Column(String(32), ForeignKey("signing_sessions.id", ondelete="SET NULL"))
    admission = Column(JSONB)            # the passkey's (or password's) consent to let it in
    revocation = Column(JSONB)           # signed out: {"statement", "signature"} by the session key
