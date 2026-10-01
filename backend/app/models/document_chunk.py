from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base


class DocumentChunk(Base):
    """
    One chunk of extracted text plus its embedding vector.

    embedding is stored as a plain JSONB array of floats rather than a
    pgvector column: at the expected scale for an internal knowledge base
    (hundreds to low thousands of chunks per org), brute-force cosine
    similarity in Python/numpy is sub-100ms and requires no Postgres
    extension or infra change. If a single org's collection grows past
    roughly 50k chunks, that is the trigger to introduce pgvector with
    an ANN index - noted here rather than silently assumed away.
    """

    __tablename__ = "document_chunks"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    collection_id = Column(
        Integer, ForeignKey("document_collections.id", ondelete="CASCADE"), nullable=False
    )
    document_id = Column(
        Integer, ForeignKey("rag_documents.id", ondelete="CASCADE"), nullable=False
    )
    chunk_index = Column(Integer, nullable=False)
    text = Column(Text, nullable=False)
    embedding = Column(JSONB, nullable=False)
    # ASI06: only "trusted" chunks are returned by retrieval
    trust_status = Column(String(20), nullable=False, default="trusted", server_default="trusted")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
