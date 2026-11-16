from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class BehaviorSettingsIn(BaseModel):
    """Bounds mirror services/behavior_monitor.BOUNDS. The containment
    settings are optional: left out, they stay as they are."""

    mode: Literal["off", "monitor", "enforce"]
    threshold: int = Field(ge=15, le=200)
    min_samples: int = Field(ge=20, le=100000)
    baseline_days: int = Field(ge=3, le=90)
    containment_enabled: Optional[bool] = None
    containment_max_boundary: Optional[int] = Field(default=None, ge=1, le=100)
    containment_window_seconds: Optional[int] = Field(default=None, ge=60, le=86400)
    tripwire_tools: Optional[List[str]] = Field(default=None, max_length=50)


class SignedReleaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # the statement from POST .../release/statement with the session key's signature
    statement: dict
    signature: str = Field(max_length=200)
