from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
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
    # Oversight roles: they read everything an admin or approver reads
    # (api/deps.py require_role). An auditor changes nothing; a compliance
    # officer also confirms compliance requirements (api/compliance.py)
    # and, like a user, may use the AI it governs.
    auditor = "auditor"
    compliance = "compliance"


# Read what admins and approvers read, on GET (deps.require_role).
OVERSIGHT_ROLES = (UserRole.auditor.value, UserRole.compliance.value)


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
    # tokens issued before this are refused (app/core/sessions.py): set on a
    # password change, so a stolen session ends with it
    sessions_valid_after = Column(DateTime(timezone=True))
    # Two-factor sign-in (app/core/totp.py): secrets encrypted with the
    # organization's key; recovery codes stored as hashes; the last time step a
    # code was accepted for, so a code cannot be used twice.
    totp_enabled = Column(Boolean, nullable=False, default=False, server_default="false")
    totp_secret_encrypted = Column(Text)
    totp_pending_encrypted = Column(Text)
    totp_last_counter = Column(BigInteger)
    mfa_recovery_hashes = Column(JSONB)
    mfa_enabled_at = Column(DateTime(timezone=True))
    # provisioned by the identity provider (SCIM, app/api/scim.py): its id for this user
    scim_external_id = Column(String(255))
    scim_managed = Column(Boolean, nullable=False, default=False, server_default="false")
    # single sign-on: "<iss> <sub>" of the IdP account bound by the first sign-in (app/services/sso.py)
    oidc_subject = Column(String(600))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    organization = relationship("Organization", backref="users")


