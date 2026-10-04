from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum


class UserRole(str, enum.Enum):
    """Role values are enforced at the API layer via Pydantic. In the
    database the column is a plain VARCHAR so that adding a new role does
    not require an ALTER TYPE on a PostgreSQL enum."""

    admin = "admin"
    approver = "approver"
    user = "user"


class User(Base):
    __tablename__ = "users"

    # The same email address can belong to multiple organizations. Identity
    # is the pair (org_id, email), which is what the login flow uses when
    # the user provides their org slug.
    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_users_org_email"),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), index=True, nullable=False)
    name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default=UserRole.user.value)
    status = Column(String(50), default="active")
    # Personal UI preference, deliberately independent of `role`: an admin
    # may still want the guided Simple Mode wizard for a quick task, and a
    # regular user may grow into wanting the full console. NULL means "not
    # chosen yet" - the frontend shows a one-time chooser after login and
    # persists the answer here, per the Simple Mode plan's own framing
    # (choice made at login) - it must be remembered, not re-asked every time.
    ui_mode = Column(String(20))  # unused since Simple Mode was removed; column kept
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    organization = relationship("Organization", backref="users")


