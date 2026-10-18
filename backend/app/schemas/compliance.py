from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class AttestationIn(BaseModel):
    requirement_id: str = Field(min_length=1, max_length=60)
    system_id: Optional[int] = None
    status: Literal["met", "not_met", "not_applicable"]
    note: Optional[str] = Field(default=None, max_length=4000)
    evidence_url: Optional[str] = Field(default=None, max_length=500, pattern=r"^(https?://|/)\S+$")
    valid_days: Optional[int] = Field(default=365, ge=1, le=1825)

    @field_validator("note")
    @classmethod
    def _strip(cls, v):
        return (v or "").strip() or None


def _known_frameworks(v):
    from app.services.compliance_catalog import FRAMEWORKS
    if v is None:
        return v
    unknown = [f for f in v if f not in FRAMEWORKS]
    if unknown:
        raise ValueError(f"unknown framework(s): {', '.join(unknown)}")
    return [f for f in FRAMEWORKS if f in set(v)]


class ReportIn(BaseModel):
    # None: the organization's chosen frameworks
    frameworks: Optional[List[str]] = None

    @field_validator("frameworks")
    @classmethod
    def _v(cls, v):
        return _known_frameworks(v)


class FrameworksIn(BaseModel):
    frameworks: List[str] = Field(min_length=1)

    @field_validator("frameworks")
    @classmethod
    def _v(cls, v):
        return _known_frameworks(v)
