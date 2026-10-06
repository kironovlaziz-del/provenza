from typing import Any, Dict, List, Optional

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit_chain
from app.models.audit_log import AIAuditLog


class AuditService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        org_id: int,
        actor_user_id: Optional[int],
        entity_type: str,
        entity_id: Optional[int],
        action: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AIAuditLog:
        """Append one record to the organization's hash chain and commit.

        Appends of one organization are serialized by a transaction-level
        advisory lock, held until the commit below, so the record read as
        "last" is really the last one and committed records always form an
        unbroken prefix 1..n (the unique (org_id, seq) constraint backs this
        up). Organizations do not wait for each other.

        The caller's pending changes are flushed BEFORE the lock is taken:
        flushing them under the lock could wait on a row another transaction
        holds while that transaction waits for this lock - a deadlock."""
        await self.db.flush()
        await self.db.execute(
            text("SELECT pg_advisory_xact_lock(:ns, :org)"),
            {"ns": audit_chain.LOCK_APPEND, "org": int(org_id)},
        )
        last = (await self.db.execute(
            select(AIAuditLog.seq, AIAuditLog.record_hash)
            .where(AIAuditLog.org_id == org_id)
            .order_by(AIAuditLog.seq.desc())
            .limit(1)
        )).first()
        seq = (last.seq + 1) if last else 1
        prev_hash = last.record_hash if last else audit_chain.GENESIS_HASH
        meta = audit_chain.normalize_metadata(metadata)
        created_at = audit_chain.now_utc()
        payload = audit_chain.record_payload(
            org_id=org_id, seq=seq, prev_hash=prev_hash, created_at=created_at,
            actor_user_id=actor_user_id, entity_type=entity_type, entity_id=entity_id,
            action=action, metadata=meta,
        )
        entry = AIAuditLog(
            org_id=org_id,
            actor_user_id=actor_user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            metadata_json=meta,
            created_at=created_at,
            seq=seq,
            prev_hash=prev_hash,
            record_hash=audit_chain.record_hash(payload),
        )
        self.db.add(entry)
        await self.db.commit()
        await self.db.refresh(entry)
        return entry

    async def list_logs(
        self,
        org_id: int,
        entity_type: Optional[str] = None,
        entity_id: Optional[int] = None,
        actor_user_id: Optional[int] = None,
        skip: int = 0,
        limit: int = 300,
    ) -> List[AIAuditLog]:
        query = select(AIAuditLog).where(AIAuditLog.org_id == org_id)
        if entity_type:
            query = query.where(AIAuditLog.entity_type == entity_type)
        if entity_id is not None:
            query = query.where(AIAuditLog.entity_id == entity_id)
        if actor_user_id is not None:
            query = query.where(AIAuditLog.actor_user_id == actor_user_id)
        query = query.order_by(AIAuditLog.seq.desc()).offset(skip).limit(limit)
        result = await self.db.execute(query)
        return list(result.scalars().all())
