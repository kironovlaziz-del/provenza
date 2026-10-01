from pydantic import BaseModel, Field


class BreakerConfig(BaseModel):
    """Bounds mirror services/circuit_breaker.BOUNDS."""

    enabled: bool = True
    window_seconds: int = Field(ge=30, le=86400)
    max_attempts: int = Field(ge=10, le=100000)
    max_denials: int = Field(ge=2, le=10000)
    max_incidents: int = Field(ge=1, le=1000)


class OrgBreakerUpdate(BreakerConfig):
    # Turning the breaker off removes a safety net; the caller must say so explicitly.
    confirm_disable: bool = False
