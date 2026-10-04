from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, func
from app.core.database import Base


class DocumentCollection(Base):
    """
    A named RAG knowledge base within an organization (e.g. "Support FAQ",
    "HR Policies"). Documents are uploaded into a collection; chat queries
    are asked against a collection.

    embedding_provider records which embedder produced every chunk vector
    currently stored for this collection ("tfidf" or "sentence_transformer")
    (RAG was removed; the table is kept). Chunks from different providers are
    not comparable, so if the provider available on this box changes
    later, existing collections keep using what they were built with
    until explicitly rebuilt, rather than silently returning garbage
    similarity scores.

    vectorizer_path is only used for "tfidf": scikit-learn's TfidfVectorizer
    must be fit on this collection's own corpus, so the fitted vectorizer
    (vocabulary + IDF weights) has to be persisted and reloaded for every
    query - unlike a pretrained neural embedder, it is not stateless.
    """

    __tablename__ = "document_collections"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    embedding_provider = Column(String(30), nullable=False, default="tfidf")
    vectorizer_path = Column(String(500))
    # Simple Mode wizard screen 7 ("Model personality"), converted to plain
    # text and stored here so it survives past the wizard session: any
    # future chat against this collection (from the wizard's own test
    # screen, the Simple Mode dashboard, or later an advanced-mode caller)
    # automatically gets the same personality, rather than callers having
    # to keep re-supplying it from client-side state that disappears the
    # moment the wizard tab closes.
    system_prompt = Column(Text)
    document_count = Column(Integer, nullable=False, default=0)
    chunk_count = Column(Integer, nullable=False, default=0)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
