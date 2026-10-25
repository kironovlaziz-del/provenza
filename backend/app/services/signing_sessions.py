# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Passkeys and signing sessions of the people who sign: administrators and
approvers (docs/pvp/edge.md, section 2).

Sessions
  Each sign-in of a signer opens a session (the token's "sid"). At most one
  session of a person is "active" unless that session lets another in: a
  second sign-in while one is active is "blocked" - it can do nothing but
  wait, and the open session is told at once (an incident and a
  notification). The open session lets it in only with the person's passkey
  (or the password, for a person who has no passkey yet), or ends it. The
  blocked session may end the other one itself, but only with the passkey:
  someone who knows the password and holds no passkey can neither get in
  nor push the owner out.

Session keys
  The browser generates an Ed25519 key for the session (non-extractable),
  and the passkey certifies its public key for the session's lifetime - one
  PIN prompt per sign-in. Signing out ends the session; the key is deleted
  in the browser, and its revocation, signed by the key, is kept.

Statements
  Everything a passkey confirms is a statement {"type", "v", "org_id",
  "user_id", ..., "issued_at"}; the passkey signs SHA-256 of its canonical
  JSON (app/core/webauthn.statement_challenge). The server builds the
  statement, the browser has it signed, the server checks that what came back
  is exactly what it expects and fresh.

Signed decisions
  What a person decides in a session - an approval of a held agent action
  (provenza.approval) - is signed by the session key, without a PIN prompt:
  the passkey already certified the key for this session. The decision keeps
  its proof: the statement, the signature, the session's certificate and the
  passkey's public key - enough to check it without the server.
"""

import hashlib
import hmac
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import webauthn
from app.core.agent_signing import normalize_public_key, verify_payload
from app.core.config import settings
from app.core.errors import api_error
from app.models.ai_incident import AIIncident
from app.models.signing import SigningSession, UserPasskey
from app.models.user import User, UserRole

SIGNING_ROLES = (UserRole.admin.value, UserRole.approver.value)
STATEMENT_V = 1
STATEMENT_MAX_AGE = 300             # seconds a statement may wait for its passkey
REGISTRATION_TTL = 300
CONFLICT_INCIDENT = "session_conflict"
NOTIFY_EVENT = "session_conflict"
# what a blocked session may still call
BLOCKED_PATHS = ("/auth/session", "/auth/session/challenge", "/auth/session/takeover", "/auth/logout")

KINDS = {
    "session.certificate": "provenza.session.certificate",
    "session.admit": "provenza.session.admit",
    "session.takeover": "provenza.session.takeover",
    "passkey.add": "provenza.passkey.add",
    "passkey.remove": "provenza.passkey.remove",
}


APPROVAL = "provenza.approval"
APPROVAL_DECISIONS = ("approved", "denied")


def signs(user: User) -> bool:
    return user.role in SIGNING_ROLES


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _client(request: Optional[Request]) -> Dict[str, Optional[str]]:
    if request is None:
        return {"ip": None, "user_agent": None}
    from app.core.rate_limit import _client_ip

    return {"ip": _client_ip(request)[:64], "user_agent": (request.headers.get("user-agent") or "")[:300] or None}


def _live(user_id: int, *states: str):
    return (SigningSession.user_id == user_id, SigningSession.status.in_(states),
            SigningSession.expires_at > _now())


# ---------------------------------------------------------------------- sessions

async def open_session(db: AsyncSession, user: User, request: Optional[Request], lifetime: timedelta) -> str:
    """A new session for a signer: active, or blocked while another is
    active (incident + notification). Returns its id; commits."""
    org_id, user_id, email = user.org_id, user.id, user.email
    await db.execute(update(SigningSession).where(
        SigningSession.user_id == user_id, SigningSession.status.in_(("active", "blocked")),
        SigningSession.expires_at <= _now()).values(status="ended", ended_at=_now(), end_reason="expired"))
    others = (await db.execute(select(SigningSession).where(*_live(user_id, "active")))).scalars().all()
    sid = uuid.uuid4().hex
    who = _client(request)
    db.add(SigningSession(id=sid, org_id=org_id, user_id=user_id, status="blocked" if others else "active",
                          expires_at=_now() + lifetime, **who))
    if others:
        db.add(AIIncident(
            org_id=org_id, severity="high", category=CONFLICT_INCIDENT, status="open",
            summary=f"A second sign-in of {email} while a session is open - blocked until the open session "
                    f"lets it in with the passkey",
            impact=f"address {who['ip'] or '?'}, browser {who['user_agent'] or '?'}"))
    await db.commit()
    if others:
        from app.services import notification_service
        from app.services.audit_service import AuditService

        await AuditService(db).log(org_id, user_id, "user", user_id, "session_blocked",
                                   {"session_id": sid, **who})
        await notification_service.notify(
            db, org_id, NOTIFY_EVENT, "Second sign-in blocked",
            f"{email} signed in again while a session was open. The new session waits until the open one "
            f"lets it in with the passkey.", {"user_id": user_id, "session_id": sid, **who})
    return sid


async def issue_token(db: AsyncSession, user: User, request: Optional[Request],
                      claims: Optional[Dict[str, Any]] = None) -> str:
    """The access token of a sign-in: with a signing session for a signer."""
    from app.core.security import create_access_token

    lifetime = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    data = {"sub": str(user.id), **(claims or {})}
    if signs(user):
        data["sid"] = await open_session(db, user, request, lifetime)
    return create_access_token(data=data, expires_delta=lifetime)


async def check(db: AsyncSession, user: User, payload: Dict[str, Any]) -> Optional[SigningSession]:
    """The session of a token (None for a person who does not sign). A signer's
    token without a live session - signed out, ended, expired, or issued before
    sessions existed - is refused."""
    sid = payload.get("sid")
    if not signs(user):
        return None
    if not isinstance(sid, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="auth.invalid_token",
                            headers={"WWW-Authenticate": "Bearer"})
    s = await db.get(SigningSession, sid)
    if s is None or s.user_id != user.id or s.status == "ended" or _aware(s.expires_at) <= _now():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="auth.session_ended",
                            headers={"WWW-Authenticate": "Bearer"})
    return s


def blocked_path_allowed(path: str) -> bool:
    p = path.rstrip("/")
    return p.endswith(BLOCKED_PATHS)


async def end(db: AsyncSession, s: SigningSession, reason: str) -> None:
    s.status, s.ended_at, s.end_reason = "ended", _now(), reason[:40]
    await db.commit()


async def end_all(db: AsyncSession, user_id: int, reason: str) -> None:
    await db.execute(update(SigningSession).where(
        SigningSession.user_id == user_id, SigningSession.status != "ended")
        .values(status="ended", ended_at=_now(), end_reason=reason[:40]))
    await db.commit()


async def state(db: AsyncSession, user: User, s: Optional[SigningSession]) -> Dict[str, Any]:
    has_passkey = bool((await db.execute(select(UserPasskey.id).where(
        UserPasskey.user_id == user.id, UserPasskey.revoked_at.is_(None)).limit(1))).first())
    if s is None:
        return {"signing": False, "session_id": None, "status": "active", "has_passkey": has_passkey}

    def view(x: SigningSession) -> Dict[str, Any]:
        return {"session_id": x.id, "created_at": x.created_at, "ip": x.ip, "user_agent": x.user_agent}

    waiting = elsewhere = []
    if s.status == "active":
        waiting = [view(x) for x in (await db.execute(select(SigningSession).where(
            *_live(user.id, "blocked")).order_by(SigningSession.created_at))).scalars()]
    else:
        elsewhere = [view(x) for x in (await db.execute(select(SigningSession).where(
            *_live(user.id, "active"), SigningSession.id != s.id).order_by(SigningSession.created_at))).scalars()]
    return {"signing": True, "session_id": s.id, "status": s.status, "expires_at": s.expires_at,
            "certified": s.certificate is not None, "public_key": s.public_key, "has_passkey": has_passkey,
            "waiting": waiting, "active_elsewhere": elsewhere}


# ---------------------------------------------------------------------- statements

def build_statement(kind: str, user: User, s: Optional[SigningSession], params: Dict[str, Any]) -> Dict[str, Any]:
    """The statement a passkey is asked to confirm, built here from trusted
    values only. params come from the browser and are checked per kind."""
    if kind not in KINDS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "passkey.unknown_purpose")
    st: Dict[str, Any] = {"type": KINDS[kind], "v": STATEMENT_V, "org_id": user.org_id, "user_id": user.id,
                          "issued_at": int(time.time())}
    if kind.startswith("session."):
        if s is None:
            raise api_error(status.HTTP_409_CONFLICT, "session.not_signing")
        st["session_id"] = s.id
    if kind == "session.certificate":
        try:
            key = normalize_public_key(str(params.get("public_key") or ""))
        except ValueError:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "session.bad_public_key")
        st.update(public_key=key, not_before=int(_aware(s.created_at).timestamp()),
                  not_after=int(_aware(s.expires_at).timestamp()))
    elif kind == "session.admit":
        target = params.get("blocked_session_id")
        if not isinstance(target, str) or len(target) != 32:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "session.not_found")
        st["admits"] = target
    elif kind == "passkey.add":
        cred = params.get("credential_id")
        if not isinstance(cred, str) or not 1 <= len(cred) <= 1400:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "passkey.bad_credential")
        st["credential_id"] = cred
    elif kind == "passkey.remove":
        pid = params.get("passkey_id")
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "passkey.not_found")
        st["passkey_id"] = pid
    return st


async def passkeys_of(db: AsyncSession, user_id: int) -> List[UserPasskey]:
    return list((await db.execute(select(UserPasskey).where(
        UserPasskey.user_id == user_id, UserPasskey.revoked_at.is_(None)).order_by(UserPasskey.id))).scalars())


async def challenge(db: AsyncSession, user: User, s: Optional[SigningSession], kind: str,
                    params: Dict[str, Any]) -> Dict[str, Any]:
    """What the browser passes to navigator.credentials.get()."""
    return await challenge_for(db, user, build_statement(kind, user, s, params))


async def challenge_for(db: AsyncSession, user: User, st: Dict[str, Any],
                        credential_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """The WebAuthn request for one statement; `credential_ids` limits the
    passkeys that may answer it."""
    keys = [k for k in await passkeys_of(db, user.id) if credential_ids is None or k.credential_id in credential_ids]
    if not keys:
        raise api_error(status.HTTP_409_CONFLICT, "passkey.none")
    return {"statement": st, "challenge": webauthn.b64url(webauthn.statement_challenge(st)),
            "rp_id": webauthn.rp_id(), "user_verification": "required", "timeout": STATEMENT_MAX_AGE * 1000,
            "allow_credentials": [{"type": "public-key", "id": k.credential_id} for k in keys]}


async def confirm(db: AsyncSession, user: User, s: Optional[SigningSession], kind: str,
                  params: Dict[str, Any], statement: Dict[str, Any], assertion: Dict[str, Any]) -> UserPasskey:
    """Check that `statement` is exactly the statement of `kind` for these
    params (only issued_at is taken from it, and must be fresh), and that one
    of the person's passkeys signed it with user verification. Updates the
    passkey's counter. Raises 4xx."""
    if not isinstance(statement, dict) or not isinstance(assertion, dict):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "passkey.bad_assertion")
    return await confirm_expected(db, user, build_statement(kind, user, s, params), statement, assertion)


async def confirm_expected(db: AsyncSession, user: User, expected: Dict[str, Any], statement: Any,
                           assertion: Any, credential_ids: Optional[List[str]] = None) -> UserPasskey:
    """confirm() for a statement built elsewhere: `expected` with issued_at
    taken from `statement`. `credential_ids` limits the passkeys that count."""
    if not isinstance(statement, dict) or not isinstance(assertion, dict):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "passkey.bad_assertion")
    expected = dict(expected)
    issued = statement.get("issued_at")
    if isinstance(issued, bool) or not isinstance(issued, int) or not 0 <= time.time() - issued <= STATEMENT_MAX_AGE:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "passkey.statement_stale")
    expected["issued_at"] = issued
    if statement != expected:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "passkey.statement_mismatch")
    cred = assertion.get("credential_id")
    key = next((k for k in await passkeys_of(db, user.id) if k.credential_id == cred
                and (credential_ids is None or cred in credential_ids)), None)
    if key is None:
        raise api_error(status.HTTP_403_FORBIDDEN, "passkey.unknown")
    try:
        count = webauthn.verify_assertion(
            public_key_cose=key.public_key, stored_sign_count=int(key.sign_count or 0),
            client_data_json=str(assertion.get("client_data_json") or ""),
            authenticator_data=str(assertion.get("authenticator_data") or ""),
            signature=str(assertion.get("signature") or ""), challenge=webauthn.statement_challenge(statement))
    except webauthn.WebAuthnError as exc:
        raise api_error(status.HTTP_403_FORBIDDEN, exc.code)
    key.sign_count, key.last_used_at = count, _now()
    await db.flush()
    return key


def _evidence(statement: Dict[str, Any], key: UserPasskey, assertion: Dict[str, Any]) -> Dict[str, Any]:
    """Everything a verifier needs, without the server: the statement, which
    passkey, and the assertion as the authenticator produced it."""
    return {"statement": statement, "passkey_id": key.id, "credential_id": key.credential_id,
            "assertion": {k: assertion.get(k) for k in ("client_data_json", "authenticator_data", "signature")}}


async def certify(db: AsyncSession, user: User, s: SigningSession, params: Dict[str, Any],
                  statement: Dict[str, Any], assertion: Dict[str, Any]) -> None:
    if s.status != "active":
        raise api_error(status.HTTP_403_FORBIDDEN, "auth.session_blocked")
    if s.certificate is not None:
        raise api_error(status.HTTP_409_CONFLICT, "session.already_certified")
    key = await confirm(db, user, s, "session.certificate", params, statement, assertion)
    s.public_key, s.certificate, s.certified_at = statement["public_key"], _evidence(statement, key, assertion), _now()
    await db.commit()


async def _blocked(db: AsyncSession, user: User, sid: Any) -> SigningSession:
    t = await db.get(SigningSession, sid) if isinstance(sid, str) else None
    if t is None or t.user_id != user.id or t.status != "blocked" or _aware(t.expires_at) <= _now():
        raise api_error(status.HTTP_404_NOT_FOUND, "session.not_found")
    return t


async def admit(db: AsyncSession, user: User, s: SigningSession, blocked_id: Any, *,
                statement: Optional[Dict[str, Any]] = None, assertion: Optional[Dict[str, Any]] = None,
                password: Optional[str] = None) -> None:
    """The open session lets a blocked one in: with the passkey, or - only for
    a person who has no passkey yet - by typing the password."""
    if s.status != "active":
        raise api_error(status.HTTP_403_FORBIDDEN, "auth.session_blocked")
    target = await _blocked(db, user, blocked_id)
    if await passkeys_of(db, user.id):
        key = await confirm(db, user, s, "session.admit", {"blocked_session_id": target.id},
                            statement or {}, assertion or {})
        consent = _evidence(statement, key, assertion)
    else:
        from app.core.security import verify_password

        if not password or not verify_password(password, user.hashed_password):
            raise api_error(status.HTTP_403_FORBIDDEN, "auth.password_incorrect")
        consent = {"method": "password", "at": int(time.time())}
    target.status, target.admitted_by, target.admission = "active", s.id, consent
    await db.commit()


async def refuse(db: AsyncSession, user: User, s: SigningSession, blocked_id: Any) -> None:
    """The open session ends a blocked one. Refusing needs no passkey."""
    if s.status != "active":
        raise api_error(status.HTTP_403_FORBIDDEN, "auth.session_blocked")
    await end(db, await _blocked(db, user, blocked_id), "refused")


async def takeover(db: AsyncSession, user: User, s: SigningSession, statement: Dict[str, Any],
                   assertion: Dict[str, Any]) -> None:
    """A blocked session ends the person's other sessions - only with the
    passkey (the open device may be gone: closed, lost, out of reach)."""
    if s.status != "blocked":
        raise api_error(status.HTTP_409_CONFLICT, "session.not_blocked")
    key = await confirm(db, user, s, "session.takeover", {}, statement, assertion)
    await db.execute(update(SigningSession).where(
        SigningSession.user_id == user.id, SigningSession.id != s.id, SigningSession.status != "ended")
        .values(status="ended", ended_at=_now(), end_reason="taken_over"))
    s.status, s.admission = "active", _evidence(statement, key, assertion)
    db.add(AIIncident(org_id=user.org_id, severity="high", category=CONFLICT_INCIDENT, status="open",
                      summary=f"{user.email} ended the other open session with the passkey from a new sign-in",
                      impact=f"address {s.ip or '?'}, browser {s.user_agent or '?'}"))
    await db.commit()


async def sign_out(db: AsyncSession, s: Optional[SigningSession], revocation: Optional[Dict[str, Any]]) -> None:
    """Signing out ends the session. A revocation signed by the session key
    is kept when it verifies: {"statement": {"type": "provenza.session.revoke",
    "v", "session_id", "issued_at"}, "signature": base64 Ed25519}."""
    if s is None or s.status == "ended":
        return
    if isinstance(revocation, dict) and s.public_key:
        st, sig = revocation.get("statement"), revocation.get("signature")
        if (isinstance(st, dict) and st.get("type") == "provenza.session.revoke" and st.get("session_id") == s.id
                and isinstance(sig, str) and verify_payload(st, sig, s.public_key)):
            s.revocation = {"statement": st, "signature": sig}
    await end(db, s, "signed_out")


# ---------------------------------------------------------------------- signed decisions

def approval_statement(user: User, s: SigningSession, action, input_sha256: str, decision: str) -> Dict[str, Any]:
    """What a reviewer signs to decide a held action: exactly the call
    (agent, chain, action type, tool, input hash) and the decision."""
    if decision not in APPROVAL_DECISIONS:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "approval.bad_decision")
    return {"type": APPROVAL, "v": STATEMENT_V, "org_id": user.org_id, "user_id": user.id, "session_id": s.id,
            "action_id": action.id, "agent_id": action.agent_id, "chain_id": action.chain_id,
            "action_type": action.action_type, "tool_name": action.tool_name, "input_sha256": input_sha256,
            "decision": decision, "issued_at": int(time.time())}


def require_certified(s: Optional[SigningSession]) -> SigningSession:
    """A session that can sign: active, live, its key certified by a passkey."""
    if s is None:
        raise api_error(status.HTTP_403_FORBIDDEN, "session.not_signing")
    if s.status != "active":
        raise api_error(status.HTTP_403_FORBIDDEN, "auth.session_blocked")
    if s.certificate is None or not s.public_key:
        raise api_error(status.HTTP_403_FORBIDDEN, "session.not_certified")
    return s


async def verify_signed(db: AsyncSession, s: Optional[SigningSession], expected: Dict[str, Any], statement: Any,
                        signature: Any) -> Dict[str, Any]:
    """Check that the session key signed exactly `expected` (only issued_at
    is taken from what came back, and must be fresh and inside the session's
    certificate). Returns the proof that is kept with the decision. Raises 4xx."""
    s = require_certified(s)
    if not isinstance(statement, dict) or not isinstance(signature, str):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "session.signature_required")
    issued = statement.get("issued_at")
    if isinstance(issued, bool) or not isinstance(issued, int) or not 0 <= time.time() - issued <= STATEMENT_MAX_AGE:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "session.statement_stale")
    if statement != dict(expected, issued_at=issued):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "session.statement_mismatch")
    key = await db.get(UserPasskey, s.certificate.get("passkey_id"))
    if key is None or not valid_signature(s.public_key, s.certificate, statement, signature):
        raise api_error(status.HTTP_403_FORBIDDEN, "session.bad_signature")
    return {"statement": statement, "signature": signature, "session_public_key": s.public_key,
            "certificate": {"statement": s.certificate["statement"], "credential_id": s.certificate["credential_id"],
                            "assertion": s.certificate["assertion"]},
            "passkey": {"id": key.id, "alg": key.alg, "public_key": webauthn.spki(key.public_key)}}


def valid_signature(public_key: Optional[str], certificate: Optional[Dict[str, Any]], statement: Dict[str, Any],
                    signature: Any) -> bool:
    """The certified session key signed this statement, by the person the
    certificate names, inside the certificate's validity."""
    cert = (certificate or {}).get("statement") or {}
    issued = statement.get("issued_at")
    return (bool(public_key) and isinstance(signature, str) and cert.get("public_key") == public_key
            and statement.get("session_id") == cert.get("session_id")
            and statement.get("user_id") == cert.get("user_id") and statement.get("org_id") == cert.get("org_id")
            and isinstance(issued, int) and not isinstance(issued, bool)
            and int(cert.get("not_before", 0)) <= issued <= int(cert.get("not_after", 0))
            and verify_payload(statement, signature, public_key))


def proof_holds(proof: Any) -> bool:
    """A kept proof's session signature still verifies against its certificate
    (the passkey's assertion was checked when the session was certified)."""
    return (isinstance(proof, dict) and isinstance(proof.get("statement"), dict)
            and valid_signature(proof.get("session_public_key"), proof.get("certificate"),
                                proof["statement"], proof.get("signature")))


# ---------------------------------------------------------------------- passkeys

def _registration_challenge(user_id: int, at: Optional[int] = None) -> bytes:
    at = int(time.time()) if at is None else at
    mac = hmac.new(settings.SECRET_KEY.encode(), f"passkey-registration|{user_id}|{at}".encode(),
                   hashlib.sha256).digest()
    return at.to_bytes(8, "big") + mac


def _registration_challenge_ok(user_id: int, raw: bytes) -> bool:
    if len(raw) != 40:
        return False
    at = int.from_bytes(raw[:8], "big")
    if not 0 <= time.time() - at <= REGISTRATION_TTL:
        return False
    return hmac.compare_digest(raw, _registration_challenge(user_id, at))


async def registration_options(db: AsyncSession, user: User) -> Dict[str, Any]:
    keys = await passkeys_of(db, user.id)
    handle = hashlib.sha256(f"{settings.SECRET_KEY}|user-handle|{user.id}".encode()).digest()[:16]
    return {
        "challenge": webauthn.b64url(_registration_challenge(user.id)),
        "rp": {"id": webauthn.rp_id(), "name": "Provenza"},
        "user": {"id": webauthn.b64url(handle), "name": user.email, "displayName": user.name or user.email},
        "pubKeyCredParams": [{"type": "public-key", "alg": a} for a in webauthn.ALGS],
        "timeout": REGISTRATION_TTL * 1000,
        "attestation": "none",
        "authenticatorSelection": {"userVerification": "required", "residentKey": "preferred"},
        "excludeCredentials": [{"type": "public-key", "id": k.credential_id} for k in keys],
        "vouch_required": bool(keys),
    }


async def register(db: AsyncSession, user: User, *, label: str, client_data_json: str, attestation_object: str,
                   password: str, vouch: Optional[Dict[str, Any]]) -> UserPasskey:
    """Add a passkey. The password is asked again; a person who already has
    a passkey also confirms the new one with an existing one (vouch: a
    "passkey.add" statement for the new credential id and its assertion), so
    a stolen password alone cannot plant a passkey."""
    from app.core.security import verify_password

    if not verify_password(password or "", user.hashed_password):
        raise api_error(status.HTTP_403_FORBIDDEN, "auth.password_incorrect")
    try:
        import json

        cd = json.loads(webauthn.b64url_decode(client_data_json).decode("utf-8"))
        raw_challenge = webauthn.b64url_decode(str(cd.get("challenge") or ""))
    except (webauthn.WebAuthnError, ValueError, UnicodeDecodeError, AttributeError):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "webauthn.bad_client_data")
    if not _registration_challenge_ok(user.id, raw_challenge):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "webauthn.challenge_mismatch")
    try:
        reg = webauthn.verify_registration(client_data_json, attestation_object, raw_challenge)
    except webauthn.WebAuthnError as exc:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.code)
    taken = (await db.execute(select(UserPasskey.id).where(UserPasskey.credential_id == reg.credential_id))).first()
    if taken:
        raise api_error(status.HTTP_409_CONFLICT, "passkey.exists")
    voucher = None
    if await passkeys_of(db, user.id):
        v = vouch or {}
        voucher = await confirm(db, user, None, "passkey.add", {"credential_id": reg.credential_id},
                                v.get("statement") or {}, v.get("assertion") or {})
    key = UserPasskey(org_id=user.org_id, user_id=user.id, credential_id=reg.credential_id,
                      public_key=reg.public_key, alg=reg.alg, sign_count=reg.sign_count,
                      label=(label or "").strip()[:100] or "passkey",
                      vouched_by_passkey_id=voucher.id if voucher else None)
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return key


async def remove(db: AsyncSession, user: User, passkey_id: int, password: str, statement: Dict[str, Any],
                 assertion: Dict[str, Any]) -> None:
    """Remove a passkey: the password and a passkey of the person (it may be
    the one removed) confirm it."""
    from app.core.security import verify_password

    if not verify_password(password or "", user.hashed_password):
        raise api_error(status.HTTP_403_FORBIDDEN, "auth.password_incorrect")
    target = next((k for k in await passkeys_of(db, user.id) if k.id == passkey_id), None)
    if target is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "passkey.not_found")
    await confirm(db, user, None, "passkey.remove", {"passkey_id": passkey_id}, statement, assertion)
    target.revoked_at = _now()
    await db.commit()
