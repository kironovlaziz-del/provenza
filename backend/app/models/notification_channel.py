from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from app.core.database import Base


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    # A channel is uniquely identified by (org, type, target) - two
    # identical channels would deliver duplicate notifications.
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "channel_type",
            "target",
            name="uq_notification_channels_org_type_target",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    channel_type = Column(String(20), nullable=False)  # email, webhook
    target = Column(String(500), nullable=False)  # email address or webhook URL
    events_json = Column(JSONB, nullable=False)  # e.g. ["incident_created", "kill_switch"]
    enabled = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
