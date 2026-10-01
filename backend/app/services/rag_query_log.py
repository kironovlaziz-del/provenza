# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""Usage log of knowledge bases (RAG): who asked which collection, how much
was retrieved, how long it took. Feeds the AI Inventory metrics of rag_app
systems. The question text is never stored."""

import hashlib
import logging
import time
from typing import Any, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rag_query_log import RagQueryLog

logger = logging.getLogger("rag_query_log")


async def log_rag_query(db: AsyncSession, org_id: int, collection_id: int, user_id: Optional[int], kind: str,
                        question: str, matches: List[Any], started: float, top_k: Optional[int] = None,
                        provider_id: Optional[int] = None) -> None:
    """Best effort: a logging failure never breaks the answer."""
    try:
        scores = [float(m.score) for m in matches if getattr(m, "score", None) is not None]
        db.add(RagQueryLog(
            org_id=org_id, collection_id=collection_id, user_id=user_id, provider_id=provider_id, kind=kind,
            question_sha256=hashlib.sha256((question or "").encode("utf-8")).hexdigest(),
            question_chars=len(question or ""), top_k=top_k, matches=len(matches),
            top_score=max(scores) if scores else None,
            latency_ms=int((time.monotonic() - started) * 1000),
        ))
        await db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("could not log a RAG query")
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001
            pass
