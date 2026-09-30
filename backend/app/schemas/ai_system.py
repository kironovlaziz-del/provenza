from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.risk_classifier import DOMAINS, FLAGS

Kind = Literal["agent", "llm_provider", "model", "rag_app", "shadow", "other"]
Stage = Literal["idea", "development", "validation", "production", "retired"]
Tier = Literal["unacceptable", "high", "limited", "minimal"]


def _domain(v):
    if v is not None and v not in DOMAINS:
        raise ValueError(f"unknown domain '{v}'")
    return v


def _flags(v):
    if v is None:
        return v
    bad = sorted(set(v) - set(FLAGS))
    if bad:
        raise ValueError(f"unknown risk flags: {', '.join(bad)}")
    return sorted(set(v))


class AISystemCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    kind: Kind = "other"
    domain: str = "general"
    risk_flags: List[str] = Field(default_factory=list)
    owner_user_id: Optional[int] = None
    business_owner: Optional[str] = Field(default=None, max_length=255)
    use_case_id: Optional[int] = None
    # production is reachable only through the stage endpoint, after risk confirmation
    lifecycle_stage: Literal["idea", "development", "validation"] = "idea"

    @field_validator("domain")
    @classmethod
    def _v_domain(cls, v):
        return _domain(v)

    @field_validator("risk_flags")
    @classmethod
    def _v_flags(cls, v):
        return _flags(v)


class AISystemUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    domain: Optional[str] = None
    risk_flags: Optional[List[str]] = None
    owner_user_id: Optional[int] = None
    business_owner: Optional[str] = Field(default=None, max_length=255)
    use_case_id: Optional[int] = None

    @field_validator("domain")
    @classmethod
    def _v_domain(cls, v):
        return _domain(v)

    @field_validator("risk_flags")
    @classmethod
    def _v_flags(cls, v):
        return _flags(v)


class StageChange(BaseModel):
    stage: Stage


class RiskConfirm(BaseModel):
    tier: Tier
    justification: Optional[str] = Field(default=None, max_length=2000)


class DataLinkCreate(BaseModel):
    relation: Literal["trained_on", "accesses"]
    dataset_id: Optional[int] = None
    collection_id: Optional[int] = None
    external_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    contains_pii: bool = False
    notes: Optional[str] = None

    @model_validator(mode="after")
    def _exactly_one_target(self):
        targets = [self.dataset_id, self.collection_id, self.external_name]
        if sum(t is not None for t in targets) != 1:
            raise ValueError("specify exactly one of dataset_id, collection_id, external_name")
        return self


class DataLinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    relation: str
    dataset_id: Optional[int] = None
    collection_id: Optional[int] = None
    external_name: Optional[str] = None
    contains_pii: bool
    notes: Optional[str] = None
    created_at: Optional[datetime] = None


class AISystemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    org_id: int
    name: str
    description: Optional[str] = None
    kind: str
    source_key: Optional[str] = None
    agent_id: Optional[int] = None
    provider_id: Optional[int] = None
    deployment_id: Optional[int] = None
    use_case_id: Optional[int] = None
    shadow_tool: Optional[str] = None
    owner_user_id: Optional[int] = None
    business_owner: Optional[str] = None
    lifecycle_stage: str
    review_status: str
    domain: str
    risk_flags: List[str] = Field(default_factory=list)
    suggested_risk_tier: Optional[str] = None
    risk_assessment: Optional[Dict[str, Any]] = None
    confirmed_risk_tier: Optional[str] = None
    risk_justification: Optional[str] = None
    risk_confirmed_by: Optional[int] = None
    risk_confirmed_at: Optional[datetime] = None
    effective_risk_tier: Optional[str] = None
    attention: List[str] = Field(default_factory=list)
    data_protection_notes: List[str] = Field(default_factory=list)
    data_links: List[DataLinkOut] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
