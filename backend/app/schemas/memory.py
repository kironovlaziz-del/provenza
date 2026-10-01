import re
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

_GLOB = re.compile(r"^[A-Za-z0-9_.:\-/*?]{1,200}$")
_NS = re.compile(r"^[A-Za-z0-9_.:\-/]{1,200}$")


class MemorySettingsIn(BaseModel):
    mode: Literal["off", "monitor", "enforce"]
    shared_namespaces: List[str] = Field(max_length=50)
    default_ttl_days: int = Field(ge=1, le=365)

    @field_validator("shared_namespaces")
    @classmethod
    def _globs(cls, v: List[str]) -> List[str]:
        out = []
        for g in v:
            g = g.strip()
            if not _GLOB.match(g):
                raise ValueError(f"invalid namespace pattern: {g!r}")
            if g not in out:
                out.append(g)
        return out


class MemoryWriteIn(BaseModel):
    agent_id: int
    chain_id: Optional[int] = None
    namespace: str = Field(min_length=1, max_length=200)
    key: Optional[str] = Field(default=None, max_length=200)
    content: Any
    source: Literal["user", "tool_output", "document", "agent"]
    source_ref: Optional[str] = Field(default=None, max_length=300)
    ttl_days: Optional[int] = Field(default=None, ge=1, le=365)

    @field_validator("namespace")
    @classmethod
    def _ns(cls, v: str) -> str:
        if not _NS.match(v):
            raise ValueError("namespace: letters, digits and . _ : - / only")
        return v

    @model_validator(mode="after")
    def _content(self):
        if self.content is None or self.content == "":
            raise ValueError("content is required")
        if isinstance(self.content, str) and len(self.content) > 1_000_000:
            raise ValueError("content is longer than 1,000,000 characters")
        return self


class MemoryVerifyItem(BaseModel):
    entry_id: Optional[int] = None
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class MemoryVerifyIn(BaseModel):
    agent_id: int
    items: List[MemoryVerifyItem] = Field(min_length=1, max_length=200)
