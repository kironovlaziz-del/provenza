from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base

class AIUseCase(Base):
    __tablename__ = "ai_use_cases"
    
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    owner_user_id = Column(Integer, ForeignKey("users.id"))
    risk_level = Column(String(20), default="low")  # low, medium, high, critical
    allowed_providers_json = Column(JSONB)
    status = Column(String(50), default="active")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

