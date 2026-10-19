from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, func
from app.core.database import Base

class AIIncident(Base):
    __tablename__ = "ai_incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    severity = Column(String(20), default="low")  # low, medium, high, critical
    category = Column(String(100))
    summary = Column(Text)
    impact = Column(Text)
    root_cause = Column(Text)
    status = Column(String(50), default="open")  # open, investigating, resolved
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))

