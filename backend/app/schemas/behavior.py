from typing import Literal

from pydantic import BaseModel, Field


class BehaviorSettingsIn(BaseModel):
    """Bounds mirror services/behavior_monitor.BOUNDS."""

    mode: Literal["off", "monitor", "enforce"]
    threshold: int = Field(ge=15, le=200)
    min_samples: int = Field(ge=20, le=100000)
    baseline_days: int = Field(ge=3, le=90)
