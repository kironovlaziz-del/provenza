from sqlalchemy import Column, Integer, String, DateTime, func
from app.core.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    # URL-safe identifier used in the login form to disambiguate users
    # that share an email across organizations. Lowercase, [a-z0-9-],
    # 3-63 chars. Unique across the whole instance.
    slug = Column(String(63), unique=True, index=True, nullable=False)
    plan = Column(String(50), default="free")
    # who must sign in with a second factor: none | reviewers (admins and approvers) | all
    mfa_required = Column(String(10), nullable=False, default="none", server_default="none")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
