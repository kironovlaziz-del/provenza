# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, func

from app.core.database import Base


class RagQueryLog(Base):
    """One question asked of a knowledge base. The question itself is not
    stored - only its SHA-256 and length - so the log carries no PII."""

    __tablename__ = "rag_query_logs"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    collection_id = Column(Integer, ForeignKey("document_collections.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    provider_id = Column(Integer, ForeignKey("ai_providers.id", ondelete="SET NULL"))
    kind = Column(String(10), nullable=False)        # query (retrieval only), chat (retrieval + LLM)
    question_sha256 = Column(String(64), nullable=False)
    question_chars = Column(Integer, nullable=False)
    top_k = Column(Integer)
    matches = Column(Integer, nullable=False)
    top_score = Column(Float)
    latency_ms = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
