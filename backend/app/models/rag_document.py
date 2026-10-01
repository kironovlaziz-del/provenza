from sqlalchemy import Column, Integer, String, BigInteger, DateTime, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base


class Document(Base):
    """A single uploaded file (PDF/DOCX/TXT) within a DocumentCollection."""

    __tablename__ = "rag_documents"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    collection_id = Column(
        Integer, ForeignKey("document_collections.id", ondelete="CASCADE"), nullable=False
    )
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_type = Column(String(20), nullable=False)  # pdf, docx, txt
    size_bytes = Column(BigInteger, default=0)
    status = Column(String(20), nullable=False, default="processing")  # processing, ready, failed
    error_message = Column(Text)
    chunk_count = Column(Integer, nullable=False, default=0)
    uploaded_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # ASI06: trusted, quarantined (a poisoned chunk was found), revoked (by an admin)
    trust_status = Column(String(20), nullable=False, default="trusted", server_default="trusted")
    trust_details = Column(JSONB)
    trust_changed_by = Column(Integer, ForeignKey("users.id"))
    trust_changed_at = Column(DateTime(timezone=True))
