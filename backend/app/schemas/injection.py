from typing import Literal

from pydantic import BaseModel, Field


class InjectionSettingsIn(BaseModel):
    """Bounds mirror services/injection_guard.BOUNDS."""

    mode: Literal["off", "monitor", "enforce"]
    threshold: int = Field(ge=40, le=100)


class InjectionScanIn(BaseModel):
    text: str = Field(min_length=1, max_length=100_000)
