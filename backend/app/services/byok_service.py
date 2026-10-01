# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
BYOK management: enable (first key), rotate (new data key, maybe a new KEK
provider), disable (back to the server key), shred (crypto-shredding),
health check, and the re-encryption that moves an organization's existing
secrets onto the target key. See app/core/keyring.py for the format.

Covered columns: ai_providers.api_key_encrypted,
ai_requests.input_text_encrypted, service_connections.bind_password_encrypted.
"""

import asyncio
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from cryptography.fernet import Fernet
from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import keyring
from app.core.crypto import _get_fernet, decrypt_secret
from app.models.ai_provider import AIProvider
from app.models.ai_request import AIRequest
from app.models.org_key import ByokJob, OrgKey

INLINE_LIMIT = 2000
BATCH = 200
SHRED_WORD = "SHRED"


def _targets() -> List[Tuple[type, str]]:
    out = [(AIProvider, "api_key_encrypted"), (AIRequest, "input_text_encrypted")]
    try:
        from app.models.service_connection import ServiceConnection
        out.append((ServiceConnection, "bind_password_encrypted"))
    except ImportError:
        pass
    return out


def _on_target(ciphertext: str, key_id: Optional[int]) -> bool:
    if key_id is None:
        return not ciphertext.startswith(keyring.PREFIX)
    return ciphertext.startswith(f"{keyring.PREFIX}{key_id}:")


def _encrypt_to(plaintext: str, key_id: Optional[int]) -> str:
    if key_id is None:
        return _get_fernet().encrypt(plaintext.encode()).decode()
    return keyring.encrypt_for_key(key_id, plaintext)


class ByokService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _active(self, org_id: int) -> Optional[OrgKey]:
        return (await self.db.execute(
            select(OrgKey).where(OrgKey.org_id == org_id, OrgKey.status == "active")
        )).scalar_one_or_none()

    # ------------------------------------------------------------------ keys
    async def new_key(self, org_id: int, provider: str, config: dict, user_id: int) -> Tuple[OrgKey, ByokJob]:
        """Enable BYOK, or rotate to a fresh data key (optionally under another KEK)."""
        if provider == "aws_kms" and not keyring.aws_available():
            raise HTTPException(status_code=400, detail="AWS KMS needs boto3 on the server (pip install boto3)")
        dek = Fernet.generate_key()
        public, sealed = keyring.seal_config(provider, config)
        try:
            wrapped = await asyncio.to_thread(keyring.wrap, provider, public, sealed, org_id, dek)
            back = await asyncio.to_thread(keyring.unwrap, provider, public, sealed, org_id, wrapped)
        except keyring.KeyUnavailable as exc:
            raise HTTPException(status_code=400, detail=f"Key provider check failed: {exc}")
        if back != dek:
            raise HTTPException(status_code=400, detail="Key provider check failed: unwrap returned a different key")

        current = await self._active(org_id)
        now = datetime.now(timezone.utc)
        if current is not None:
            current.status = "retired"
            current.retired_at = now
        version = ((await self.db.execute(
            select(func.max(OrgKey.version)).where(OrgKey.org_id == org_id)
        )).scalar_one() or 0) + 1
        key = OrgKey(org_id=org_id, version=version, provider=provider, config_public=public,
                     config_secret_encrypted=sealed, wrapped_dek=wrapped, status="active",
                     last_check_at=now, last_check_ok=True, created_by=user_id)
        self.db.add(key)
        await self.db.flush()
        job = ByokJob(org_id=org_id, kind="rotate" if current else "enable", target_key_id=key.id,
                      status="queued", created_by=user_id)
        self.db.add(job)
        await self.db.commit()
        keyring.remember(key.id, dek)
        keyring.remember_active(org_id, key.id)
        return key, job

    async def disable(self, org_id: int, user_id: int) -> ByokJob:
        current = await self._active(org_id)
        if current is None:
            raise HTTPException(status_code=409, detail="BYOK is not enabled for this organization")
        current.status = "retired"
        current.retired_at = datetime.now(timezone.utc)
        job = ByokJob(org_id=org_id, kind="disable", target_key_id=None, status="queued", created_by=user_id)
        self.db.add(job)
        await self.db.commit()
        keyring.remember_active(org_id, None)
        return job

    async def shred(self, org_id: int, confirm: str) -> dict:
        if confirm != SHRED_WORD:
            raise HTTPException(status_code=422, detail=f'Type "{SHRED_WORD}" to confirm')
        keys = (await self.db.execute(
            select(OrgKey).where(OrgKey.org_id == org_id, OrgKey.status != "shredded")
        )).scalars().all()
        if not keys:
            raise HTTPException(status_code=409, detail="No organization key to shred")
        now = datetime.now(timezone.utc)
        for k in keys:
            k.wrapped_dek = None
            k.config_secret_encrypted = None
            k.status = "shredded"
            k.shredded_at = now
            keyring.forget(key_id=k.id)
        await self.db.commit()
        keyring.remember_active(org_id, None)
        return {"shredded_keys": len(keys)}

    async def check(self, org_id: int) -> dict:
        key = await self._active(org_id)
        if key is None:
            raise HTTPException(status_code=409, detail="BYOK is not enabled for this organization")
        key.last_check_at = datetime.now(timezone.utc)
        try:
            dek = await asyncio.to_thread(keyring.unwrap, key.provider, key.config_public,
                                          key.config_secret_encrypted, org_id, key.wrapped_dek)
            keyring.remember(key.id, dek)
            key.last_check_ok, key.last_error = True, None
        except keyring.KeyUnavailable as exc:
            keyring.forget(key_id=key.id)
            key.last_check_ok, key.last_error = False, str(exc)[:500]
        await self.db.commit()
        return {"key_id": key.id, "ok": key.last_check_ok, "error": key.last_error}

    # ------------------------------------------------------------------ re-encryption
    async def pending_rows(self, org_id: int, key_id: Optional[int]) -> int:
        n = 0
        for model, col in _targets():
            c = getattr(model, col)
            cond = [model.org_id == org_id, c.is_not(None)]
            cond.append(c.like(f"{keyring.PREFIX}%") if key_id is None
                        else ~c.like(f"{keyring.PREFIX}{key_id}:%"))
            n += (await self.db.execute(select(func.count()).select_from(model).where(*cond))).scalar_one()
        return n

    async def reencrypt(self, job_id: int) -> ByokJob:
        job = await self.db.get(ByokJob, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        org_id, key_id = job.org_id, job.target_key_id
        job.status = "running"
        job.total = await self.pending_rows(org_id, key_id)
        await self.db.commit()
        done = failed = 0
        last_error = None
        for model, col in _targets():
            c = getattr(model, col)
            last_id = 0
            while True:
                rows = (await self.db.execute(
                    select(model.id, c).where(model.org_id == org_id, c.is_not(None), model.id > last_id)
                    .order_by(model.id).limit(BATCH)
                )).all()
                if not rows:
                    break
                for row_id, value in rows:
                    last_id = row_id
                    if _on_target(value, key_id):
                        continue
                    try:
                        new_value = _encrypt_to(decrypt_secret(value), key_id)
                    except Exception as exc:  # noqa: BLE001 - one unreadable value must not stop the job
                        failed += 1
                        last_error = f"{model.__tablename__}#{row_id}: {exc}"[:500]
                        continue
                    await self.db.execute(update(model).where(model.id == row_id).values({col: new_value}))
                    done += 1
                job.done, job.failed = done, failed
                await self.db.commit()
        job.status = "done" if not failed else "failed"
        job.error = last_error
        job.finished_at = datetime.now(timezone.utc)
        await self.db.commit()
        return job

    async def start(self, job: ByokJob) -> dict:
        """Small organizations are re-encrypted right away, large ones by a worker."""
        pending = await self.pending_rows(job.org_id, job.target_key_id)
        if pending <= INLINE_LIMIT:
            job = await self.reencrypt(job.id)
            return {"job_id": job.id, "status": job.status, "done": job.done, "failed": job.failed,
                    "inline": True}
        from app.core.celery_app import celery_app
        celery_app.send_task("byok.reencrypt", args=[job.id])
        return {"job_id": job.id, "status": "queued", "pending": pending, "inline": False}

    # ------------------------------------------------------------------ overview
    async def overview(self, org_id: int) -> dict:
        keys = (await self.db.execute(
            select(OrgKey).where(OrgKey.org_id == org_id).order_by(OrgKey.version.desc())
        )).scalars().all()
        active = next((k for k in keys if k.status == "active"), None)
        data = []
        for model, col in _targets():
            c = getattr(model, col)
            base = [model.org_id == org_id, c.is_not(None)]
            total = (await self.db.execute(select(func.count()).select_from(model).where(*base))).scalar_one()
            legacy = (await self.db.execute(select(func.count()).select_from(model)
                                            .where(*base, ~c.like(f"{keyring.PREFIX}%")))).scalar_one()
            on_active = 0 if active is None else (await self.db.execute(
                select(func.count()).select_from(model).where(*base, c.like(f"{keyring.PREFIX}{active.id}:%"))
            )).scalar_one()
            data.append({"table": model.__tablename__, "column": col, "total": total, "server_key": legacy,
                         "active_key": on_active, "older_keys": total - legacy - on_active})
        jobs = (await self.db.execute(
            select(ByokJob).where(ByokJob.org_id == org_id).order_by(ByokJob.created_at.desc()).limit(20)
        )).scalars().all()
        return {
            "enabled": active is not None,
            "aws_available": keyring.aws_available(),
            "keys": [{"id": k.id, "version": k.version, "provider": k.provider, "config": k.config_public,
                      "has_secret": bool(k.config_secret_encrypted), "status": k.status,
                      "last_check_at": k.last_check_at, "last_check_ok": k.last_check_ok, "last_error": k.last_error,
                      "created_at": k.created_at, "retired_at": k.retired_at, "shredded_at": k.shredded_at}
                     for k in keys],
            "data": data,
            "jobs": [{"id": j.id, "kind": j.kind, "target_key_id": j.target_key_id, "status": j.status,
                      "total": j.total, "done": j.done, "failed": j.failed, "error": j.error,
                      "created_at": j.created_at, "finished_at": j.finished_at} for j in jobs],
        }
