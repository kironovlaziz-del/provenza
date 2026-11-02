from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Index, func
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base


class AITelemetryEvent(Base):
    """
    Raw, append-only record of every event received from an ingestion
    source (Gateway/Endpoint agent/Browser extension) - kept even for
    "allowed" domain visits and for local-signal events that never go
    through domain classification at all.

    event_type distinguishes what kind of signal this is:
    - "domain_visit": an outbound domain was visited (extension, or a
      future network-level collector) - domain/matched_policy_status are
      meaningful here.
    - "process_detected" / "network_conn" / "local_model_found": the
      endpoint agent found a local AI tool running or installed - there
      is no domain to classify, so domain holds a fixed placeholder
      ("localhost", "local_filesystem", "localhost:<port>") and
      matched_policy_status stays NULL.

    Today's pipeline only acts on blocked/unknown domain matches and on
    every local signal, but future behavioral analysis and fingerprinting
    (Shadow AI Monitor roadmap stage 3) need the full history to work at
    all, and that history can't be reconstructed retroactively - it has
    to start accumulating from the first event this system ever receives.
    """

    __tablename__ = "ai_telemetry_events"
    # who used an AI service: the raw visits of its domain (Shadow AI, people per sighting)
    __table_args__ = (Index("ix_ai_telemetry_events_org_domain", "org_id", "domain", "event_type"),)

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    ingestion_source_id = Column(Integer, ForeignKey("ingestion_sources.id"), nullable=False)
    event_type = Column(String(50), nullable=False)
    domain = Column(String(255))
    agent_id = Column(String(255))
    user_hint = Column(String(255))
    risk_score = Column(Float)
    action_taken = Column(String(50))
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    matched_policy_status = Column(String(20))  # allowed, blocked, unknown - domain_visit only
    metadata_json = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
