from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from app.core.database import Base


class AIRequest(Base):
    __tablename__ = "ai_requests"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    use_case_id = Column(Integer, ForeignKey("ai_use_cases.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    provider_id = Column(Integer, ForeignKey("ai_providers.id"))

    # Fernet-encrypted raw prompt. Never returned by the API. Kept only for
    # compliance investigations (with an explicit reveal endpoint), never
    # for normal operator flow.
    input_text_encrypted = Column(Text)

    # Plaintext prompt with PII replaced by [MASKED:<TYPE>] placeholders.
    # This is what gets sent to the provider and what the UI displays.
    masked_input_text = Column(Text)

    purpose = Column(String(255))
    risk_level = Column(String(20), default="low")
    # pending, pending_approval, blocked, approved, rejected, completed, failed, stopped, rolled_back
    status = Column(String(50), default="pending")
    firewall_flags = Column(JSONB)  # e.g. ["masked:email", "blocked_term:foo"]

    # Optional auto-purge deadline for the encrypted raw text. NULL means
    # "keep indefinitely"; a background task can use this to wipe PII.
    retention_expires_at = Column(DateTime(timezone=True))

    # Populated when the provider call fails asynchronously (see
    # workers/request_tasks.py) so the UI can show what went wrong.
    error_message = Column(Text)

    # When the request was handed to the worker queue (creation or approval);
    # the queue TTL is measured from here - see app/services/queue_ttl.py
    enqueued_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), server_default=func.now())
