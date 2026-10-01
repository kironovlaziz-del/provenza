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


class ReportIn(BaseModel):
    frameworks: Optional[List[Literal["eu_ai_act", "gdpr", "iso42001", "nist_ai_rmf", "owasp_agentic"]]] = None
