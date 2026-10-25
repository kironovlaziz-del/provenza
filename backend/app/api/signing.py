# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Passkeys and signing sessions (app/services/signing_sessions.py).

  /auth/session                state of this sign-in: active or blocked, the
                               sessions waiting for it / open elsewhere
  /auth/session/challenge      a statement for the passkey to confirm
  /auth/session/certificate    the passkey certifies this session's key
  /auth/session/admit|refuse   the open session lets a blocked one in / ends it
  /auth/session/takeover       a blocked session ends the others (passkey only)
  /users/me/passkeys           list, register (options + attestation), remove
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core import rate_limit, webauthn
from app.core.database import get_db
from app.core.errors import api_error
from app.models.user import User
from app.services import signing_sessions as ss
from app.services.audit_service import AuditService

session_router = APIRouter()
passkey_router = APIRouter()


def _session(user: User):
    return getattr(user, "_signing_session", None)


def _signer(user: User):
    s = _session(user)
    if s is None:
        raise api_error(status.HTTP_409_CONFLICT, "session.not_signing")
    return s


def _limit(request: Request, user: User, scope: str) -> None:
    rate_limit.enforce(request, scope=scope, limit=20, window_seconds=300, extra_key=f"user-{user.id}")


class ChallengeIn(BaseModel):
    purpose: str = Field(max_length=40)
    params: Dict[str, Any] = Field(default_factory=dict)


class Assertion(BaseModel):
    credential_id: str = Field(max_length=1400)
    client_data_json: str = Field(max_length=10_000)
    authenticator_data: str = Field(max_length=10_000)
    signature: str = Field(max_length=2_000)


class CertificateIn(BaseModel):
    public_key: str = Field(max_length=100)
    statement: Dict[str, Any]
    assertion: Assertion


class AdmitIn(BaseModel):
    blocked_session_id: str = Field(min_length=32, max_length=32)
    statement: Optional[Dict[str, Any]] = None
    assertion: Optional[Assertion] = None
    password: Optional[str] = Field(default=None, max_length=200)


class RefuseIn(BaseModel):
    blocked_session_id: str = Field(min_length=32, max_length=32)


class TakeoverIn(BaseModel):
    statement: Dict[str, Any]
    assertion: Assertion


# ---------------------------------------------------------------- sessions

@session_router.get("")
async def session_state(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    return await ss.state(db, user, _session(user))


@session_router.post("/challenge")
async def statement_challenge(data: ChallengeIn, request: Request, db: AsyncSession = Depends(get_db),
                              user: User = Depends(get_current_user)):
    s = _session(user)
    if s is not None and s.status == "blocked" and data.purpose != "session.takeover":
        raise api_error(status.HTTP_403_FORBIDDEN, "auth.session_blocked")
    _limit(request, user, "passkey_challenge")
    return await ss.challenge(db, user, s, data.purpose, data.params)


@session_router.post("/certificate", status_code=status.HTTP_204_NO_CONTENT)
async def certify(data: CertificateIn, request: Request, db: AsyncSession = Depends(get_db),
                  user: User = Depends(get_current_user)):
    s = _signer(user)
    _limit(request, user, "passkey_assert")
    org_id, uid, sid = user.org_id, user.id, s.id
    await ss.certify(db, user, s, {"public_key": data.public_key}, data.statement, data.assertion.model_dump())
    await AuditService(db).log(org_id, uid, "user", uid, "session_certified", {"session_id": sid})


@session_router.post("/admit", status_code=status.HTTP_204_NO_CONTENT)
async def admit(data: AdmitIn, request: Request, db: AsyncSession = Depends(get_db),
                user: User = Depends(get_current_user)):
    s = _signer(user)
    _limit(request, user, "passkey_assert")
    org_id, uid, sid = user.org_id, user.id, s.id
    await ss.admit(db, user, s, data.blocked_session_id, statement=data.statement,
                   assertion=data.assertion.model_dump() if data.assertion else None, password=data.password)
    await AuditService(db).log(org_id, uid, "user", uid, "session_admitted",
                               {"session_id": data.blocked_session_id, "by_session_id": sid})


@session_router.post("/refuse", status_code=status.HTTP_204_NO_CONTENT)
async def refuse(data: RefuseIn, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    s = _signer(user)
    org_id, uid, sid = user.org_id, user.id, s.id
    await ss.refuse(db, user, s, data.blocked_session_id)
    await AuditService(db).log(org_id, uid, "user", uid, "session_refused",
                               {"session_id": data.blocked_session_id, "by_session_id": sid})


@session_router.post("/takeover", status_code=status.HTTP_204_NO_CONTENT)
async def takeover(data: TakeoverIn, request: Request, db: AsyncSession = Depends(get_db),
                   user: User = Depends(get_current_user)):
    s = _signer(user)
    _limit(request, user, "passkey_assert")
    org_id, uid, sid = user.org_id, user.id, s.id
    await ss.takeover(db, user, s, data.statement, data.assertion.model_dump())
    await AuditService(db).log(org_id, uid, "user", uid, "session_takeover", {"session_id": sid})


# ---------------------------------------------------------------- passkeys

class RegisterIn(BaseModel):
    label: str = Field(default="passkey", max_length=100)
    client_data_json: str = Field(max_length=10_000)
    attestation_object: str = Field(max_length=20_000)
    password: str = Field(max_length=200)
    vouch: Optional[Dict[str, Any]] = None


class RemoveIn(BaseModel):
    password: str = Field(max_length=200)
    statement: Dict[str, Any]
    assertion: Assertion


def _out(k) -> Dict[str, Any]:
    return {"id": k.id, "label": k.label, "created_at": k.created_at, "last_used_at": k.last_used_at,
            "algorithm": {-7: "ES256", -8: "EdDSA", -257: "RS256"}.get(k.alg, str(k.alg)),
            # what tools/provenza_audit.py receipt --approver-passkey pins
            "fingerprint": webauthn.passkey_fingerprint(k.public_key)}


@passkey_router.get("")
async def list_passkeys(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    return [_out(k) for k in await ss.passkeys_of(db, user.id)]


@passkey_router.post("/options")
async def registration_options(request: Request, db: AsyncSession = Depends(get_db),
                               user: User = Depends(get_current_user)):
    _limit(request, user, "passkey_register")
    return await ss.registration_options(db, user)


@passkey_router.post("")
async def register_passkey(data: RegisterIn, request: Request, db: AsyncSession = Depends(get_db),
                           user: User = Depends(get_current_user)):
    _limit(request, user, "passkey_register")
    org_id, uid = user.org_id, user.id
    key = await ss.register(db, user, label=data.label, client_data_json=data.client_data_json,
                            attestation_object=data.attestation_object, password=data.password, vouch=data.vouch)
    out = _out(key)
    await AuditService(db).log(org_id, uid, "user", uid, "passkey_added",
                               {"passkey_id": key.id, "label": key.label, "vouched_by": key.vouched_by_passkey_id})
    return out


@passkey_router.post("/{passkey_id}/remove", status_code=status.HTTP_204_NO_CONTENT)
async def remove_passkey(passkey_id: int, data: RemoveIn, request: Request, db: AsyncSession = Depends(get_db),
                         user: User = Depends(get_current_user)):
    _limit(request, user, "passkey_register")
    org_id, uid = user.org_id, user.id
    await ss.remove(db, user, passkey_id, data.password, data.statement, data.assertion.model_dump())
    await AuditService(db).log(org_id, uid, "user", uid, "passkey_removed", {"passkey_id": passkey_id})
