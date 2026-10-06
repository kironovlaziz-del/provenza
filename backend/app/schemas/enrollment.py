# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.agent_signing import normalize_pq_public_key, normalize_public_key


def _names(v: Optional[List[str]]) -> List[str]:
    out = sorted({str(x).strip() for x in (v or []) if str(x).strip()})
    if len(out) > 100 or any(len(x) > 200 for x in out):
        raise ValueError("at most 100 entries of up to 200 characters")
    return out


class _Named(BaseModel):
    @field_validator("name", check_fields=False)
    @classmethod
    def _strip(cls, v):
        v = (v or "").strip()
        return v or None


class EnrollmentCreate(_Named):
    purpose: Literal["new", "rekey"] = "new"
    agent_id: Optional[int] = None          # rekey: the agent that gets a new key
    name: Optional[str] = Field(default=None, max_length=255)
    description: Optional[str] = Field(default=None, max_length=2000)
    agent_type: Optional[str] = Field(default=None, max_length=50)
    owner_team: Optional[str] = Field(default=None, max_length=100)
    team_id: Optional[int] = None           # the agent's team
    role_id: Optional[int] = None           # rights from this role template (other rights fields ignored)
    capabilities: List[str] = Field(default_factory=list)
    allowed_tools: List[str] = Field(default_factory=list)
    allowed_models: List[str] = Field(default_factory=list)
    max_delegation_depth: int = Field(default=3, ge=0, le=10)
    require_hybrid: bool = False
    ttl_hours: float = Field(default=24, ge=0.25, le=720)
    discovered_agent_id: Optional[int] = None

    @field_validator("capabilities", "allowed_tools", "allowed_models")
    @classmethod
    def _lists(cls, v):
        return _names(v)

    @model_validator(mode="after")
    def _purpose(self):
        if self.purpose == "rekey" and not self.agent_id:
            raise ValueError("a rekey enrollment needs agent_id")
        return self


class ChallengeIn(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class EnrollIn(_Named):
    # rights come from the token's template: an agent asking for capabilities,
    # tools or anything else is refused, not silently ignored
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=10, max_length=200)
    challenge: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_key: str
    pq_public_key: Optional[str] = None
    name: Optional[str] = Field(default=None, max_length=255)
    signature: str = Field(min_length=10, max_length=200)
    pq_signature: Optional[str] = Field(default=None, max_length=6000)

    @field_validator("public_key")
    @classmethod
    def _pk(cls, v: str) -> str:
        return normalize_public_key(v)

    @field_validator("pq_public_key")
    @classmethod
    def _pq(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else normalize_pq_public_key(v)


class RotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge: str = Field(pattern=r"^[0-9a-f]{64}$")
    new_public_key: str
    new_pq_public_key: Optional[str] = None
    old_signature: str = Field(min_length=10, max_length=200)
    old_pq_signature: Optional[str] = Field(default=None, max_length=6000)
    new_signature: str = Field(min_length=10, max_length=200)
    new_pq_signature: Optional[str] = Field(default=None, max_length=6000)

    @field_validator("new_public_key")
    @classmethod
    def _pk(cls, v: str) -> str:
        return normalize_public_key(v)

    @field_validator("new_pq_public_key")
    @classmethod
    def _pq(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else normalize_pq_public_key(v)


class AttestIn(BaseModel):
    """An agent's attestation: the evidence (a Kubernetes ServiceAccount token)
    and the agent's signature over {challenge, agent_id, kind, sha256(evidence)}."""
    model_config = ConfigDict(extra="forbid")

    challenge: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: str = Field(default="k8s_sa", pattern="^k8s_sa$")
    evidence: str = Field(min_length=10, max_length=16384)
    signature: str = Field(min_length=10, max_length=200)
    pq_signature: Optional[str] = Field(default=None, max_length=6000)
