# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _clean(v: Optional[str]) -> Optional[str]:
    v = (v or "").strip()
    return v or None


def _names(v: Optional[List[str]]) -> List[str]:
    out = sorted({str(x).strip() for x in (v or []) if str(x).strip()})
    if len(out) > 100 or any(len(x) > 200 for x in out):
        raise ValueError("at most 100 entries of up to 200 characters")
    return out


class TeamIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    parent_id: Optional[int] = None

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        v = _clean(v)
        if not v:
            raise ValueError("name is required")
        return v


class TeamUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)
    parent_id: Optional[int] = None


class RoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    team_id: Optional[int] = None          # None = org-wide role
    description: Optional[str] = Field(default=None, max_length=2000)
    capabilities: List[str] = Field(default_factory=list)
    allowed_tools: List[str] = Field(default_factory=list)
    allowed_models: List[str] = Field(default_factory=list)
    max_delegation_depth: int = Field(default=3, ge=0, le=10)
    require_hybrid: bool = False
    require_attestation: bool = False
    attestation_policy_id: Optional[int] = None  # required when require_attestation

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        v = _clean(v)
        if not v:
            raise ValueError("name is required")
        return v

    @field_validator("capabilities", "allowed_tools", "allowed_models")
    @classmethod
    def _lists(cls, v):
        return _names(v)


class RoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    team_id: Optional[int] = None
    description: Optional[str] = Field(default=None, max_length=2000)
    capabilities: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None
    allowed_models: Optional[List[str]] = None
    max_delegation_depth: Optional[int] = Field(default=None, ge=0, le=10)
    require_hybrid: Optional[bool] = None
    require_attestation: Optional[bool] = None
    attestation_policy_id: Optional[int] = None

    @field_validator("capabilities", "allowed_tools", "allowed_models")
    @classmethod
    def _lists(cls, v):
        return None if v is None else _names(v)
