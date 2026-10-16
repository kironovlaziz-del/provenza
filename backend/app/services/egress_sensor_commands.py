# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""
Commands for egress sensors: signing, queueing, delivery, acks.

A command is issued by an admin through the API, signed with the
organization's Ed25519 signing key, delivered to the sensor on its next
heartbeat, and acked by the sensor when it has started or finished. The
sensor verifies the signature, the organization, its own sensor id, the
command kind and the expiry before doing anything; nothing here trusts
the transport.

This is deliberately not a generic channel: three kinds are accepted, and
the only behaviour each triggers on the sensor is fixed. A stolen control
plane key can at worst detach, restart or dump-state a host - not run
arbitrary code.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import (
    canonical_text,
    generate_keypair,
    key_fingerprint,
    sign_payload,
    verify_payload,
)
from app.core.crypto import decrypt_secret, encrypt_secret
from app.models.egress_sensor import (
    EgressSensor,
    EgressSensorCommand,
    EgressSensorSigningKey,
)

log = logging.getLogger(__name__)

# Kinds the sensor understands. A payload with anything else is refused by
# the sensor before execution, but we also reject it here so an admin gets
# an immediate, clear error instead of a command that silently does nothing.
ALLOWED_KINDS = {"detach", "restart", "dump-state"}

# A command is valid for this long. Short enough that a leaked payload
# cannot be replayed much later; long enough that a sensor polling every
# few minutes still sees it.
COMMAND_TTL = timedelta(minutes=5)

# Statuses that count as "still actionable": a sensor that already acked
# will not see the command again, but a delivered-not-acked command is
# re-sent - the sensor may have crashed between receiving and acking.
ACTIVE_STATUSES = ("pending", "delivered", "executing")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    """ISO 8601 in UTC with a Z suffix, matching what the sensor sees from
    every other date field on the API. Go parses this with time.RFC3339.
    """
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- signing key

async def signing_key_for(
    db: AsyncSession, org_id: int, actor_user_id: Optional[int] = None
) -> EgressSensorSigningKey:
    """The organization's command signing key, created on first use.

    Creating it here, rather than at organization signup, keeps the key
    out of databases that never issue a command and gives the first admin
    who does issue one the chance to be recorded as created_by.
    """
    row = (await db.execute(
        select(EgressSensorSigningKey).where(EgressSensorSigningKey.org_id == org_id)
    )).scalar_one_or_none()
    if row is not None:
        return row

    private_b64, public_b64 = generate_keypair()
    row = EgressSensorSigningKey(
        org_id=org_id,
        public_key=public_b64,
        private_key_encrypted=encrypt_secret(private_b64, org_id),
        fingerprint=key_fingerprint(public_b64) or "",
        created_by=actor_user_id,
    )
    db.add(row)
    await db.flush()
    log.info("created egress sensor signing key for org %d", org_id)
    return row


def sign_payload_with(key: EgressSensorSigningKey, payload: Dict[str, Any]) -> str:
    """Sign one command payload with the organization's private key.

    The private key is decrypted only for the duration of this call; it is
    never held on a model instance or returned from this module.
    """
    private_b64 = decrypt_secret(key.private_key_encrypted)
    return sign_payload(payload, private_b64)


# ---------------------------------------------------------------- commands

class CommandError(Exception):
    """Base class for the errors this module raises. .code is a stable
    machine-readable string the API turns into an HTTP detail."""

    code = "egress_command.error"

    def __init__(self, message: str, **context: Any):
        super().__init__(message)
        self.context = context


class UnknownKind(CommandError):
    code = "egress_command.unknown_kind"


class NotFound(CommandError):
    code = "egress_command.not_found"


def _build_payload(
    command_id: int, sensor: EgressSensor, kind: str, now: datetime, expires: datetime
) -> Dict[str, Any]:
    """The exact dictionary the sensor will canonicalize and verify.

    Kept in one place so the signature is over a shape both ends agree on:
    a change to the fields here would invalidate every stored signature.
    """
    return {
        "id": command_id,
        "kind": kind,
        "org_id": sensor.org_id,
        "sensor_id": sensor.id,
        "issued_at": _iso(now),
        "expires_at": _iso(expires),
    }


async def create_command(
    db: AsyncSession, sensor: EgressSensor, kind: str, actor_user_id: int
) -> EgressSensorCommand:
    """Queue a command for one sensor. The sensor sees it on its next
    heartbeat (within refresh_seconds), verifies it, and acks."""
    if kind not in ALLOWED_KINDS:
        raise UnknownKind(f"unknown command kind: {kind}", kind=kind)

    key = await signing_key_for(db, sensor.org_id, actor_user_id)
    now = _utcnow()
    expires = now + COMMAND_TTL

    # Two flushes: the first gets the id, the second stores the payload
    # that names the id. Both are inside the caller's transaction, so an
    # error after the first flush leaves no trace.
    row = EgressSensorCommand(
        org_id=sensor.org_id,
        sensor_id=sensor.id,
        kind=kind,
        payload={},
        signature="",
        issued_by=actor_user_id,
        issued_at=now,
        expires_at=expires,
        status="pending",
    )
    db.add(row)
    await db.flush()

    payload = _build_payload(row.id, sensor, kind, now, expires)
    row.payload = payload
    row.signature = sign_payload_with(key, payload)
    await db.flush()
    return row


async def pending_for_sensor(db: AsyncSession, sensor_id: int) -> List[EgressSensorCommand]:
    """Commands to deliver to a sensor on this heartbeat: not yet acked,
    not yet expired, oldest first. Ordering matters for the sensor, which
    executes them in the order given."""
    now = _utcnow()
    rows = (await db.execute(
        select(EgressSensorCommand).where(
            EgressSensorCommand.sensor_id == sensor_id,
            EgressSensorCommand.status.in_(ACTIVE_STATUSES),
            EgressSensorCommand.expires_at > now,
        ).order_by(EgressSensorCommand.issued_at.asc())
    )).scalars().all()
    return list(rows)


async def mark_delivered(db: AsyncSession, command_ids: List[int]) -> None:
    """Record that the heartbeat that is being answered carried these
    commands. Status stays 'pending' until the sensor acks - re-delivery
    on the next heartbeat is intentional, and 'delivered_at' just marks
    when the last attempt happened."""
    if not command_ids:
        return
    await db.execute(
        update(EgressSensorCommand)
        .where(EgressSensorCommand.id.in_(command_ids))
        .values(delivered_at=_utcnow())
    )


async def ack_command(
    db: AsyncSession,
    sensor_id: int,
    command_id: int,
    status: str,
    result: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> EgressSensorCommand:
    """Record an ack from a sensor. The sensor owns the status string and
    must have verified the command before sending this: we only check that
    the ack names this sensor's own command and a known status."""
    if status not in ("executing", "done", "failed"):
        raise CommandError(f"invalid ack status: {status}", status=status)

    row = (await db.execute(
        select(EgressSensorCommand).where(
            EgressSensorCommand.id == command_id,
            EgressSensorCommand.sensor_id == sensor_id,
        )
    )).scalar_one_or_none()
    if row is None:
        raise NotFound(f"command {command_id} not found for this sensor", id=command_id)

    row.status = status
    row.acked_at = _utcnow()
    if result is not None:
        row.result = result
    if error:
        row.error = error[:500]
    await db.flush()
    return row


async def expire_old_commands(db: AsyncSession) -> int:
    """Mark pending/delivered commands whose TTL has passed as expired.
    Called from a Celery beat task; returns the number of rows touched."""
    r = await db.execute(
        update(EgressSensorCommand)
        .where(
            EgressSensorCommand.status.in_(("pending", "delivered")),
            EgressSensorCommand.expires_at < _utcnow(),
        )
        .values(status="expired")
    )
    return r.rowcount or 0


# ---------------------------------------------------------------- verification

def verify_command_signature(
    public_key_b64: str, payload: Dict[str, Any], signature_b64: str
) -> bool:
    """Verify a command signature. Used by tests and by the sensor (the
    sensor has its own copy of this in Go - the algorithm and the
    canonicalization must stay identical)."""
    return verify_payload(payload, signature_b64, public_key_b64)


def canonical_bytes_for(payload: Dict[str, Any]) -> bytes:
    """The bytes that are signed. Exposed so a test can prove the sensor
    side reproduces them exactly."""
    return canonical_text(payload).encode("utf-8")
