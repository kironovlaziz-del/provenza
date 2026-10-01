from datetime import datetime
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

PATTERN_RE = r"^[A-Za-z0-9._:/*?\[\]-]+$"
DIGEST_RE = r"^(sha256:)?[A-Fa-f0-9]{64}$"


class SupplyChainMode(BaseModel):
    mode: Literal["off", "monitor", "enforce"]


class ToolEntryCreate(BaseModel):
    pattern: str = Field(min_length=1, max_length=200, pattern=PATTERN_RE)
    kind: Literal["tool", "mcp_server", "sdk"] = "tool"
    display_name: Optional[str] = Field(default=None, max_length=255)
    source: Optional[str] = Field(default=None, max_length=500)
    publisher: Optional[str] = Field(default=None, max_length=255)
    pinned_version: Optional[str] = Field(default=None, max_length=100)
    pinned_digest: Optional[str] = Field(default=None, pattern=DIGEST_RE)
    status: Literal["approved", "pending", "blocked"] = "approved"
    notes: Optional[str] = None


class ToolEntryUpdate(BaseModel):
    kind: Optional[Literal["tool", "mcp_server", "sdk"]] = None
    display_name: Optional[str] = Field(default=None, max_length=255)
    source: Optional[str] = Field(default=None, max_length=500)
    publisher: Optional[str] = Field(default=None, max_length=255)
    pinned_version: Optional[str] = Field(default=None, max_length=100)
    pinned_digest: Optional[str] = Field(default=None, pattern=DIGEST_RE)
    notes: Optional[str] = None


class ToolEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    pattern: str
    kind: str
    display_name: Optional[str] = None
    source: Optional[str] = None
    publisher: Optional[str] = None
    pinned_version: Optional[str] = None
    pinned_digest: Optional[str] = None
    status: str
    discovered: bool
    seen_count: int
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    approved_by: Optional[int] = None
    approved_at: Optional[datetime] = None
    drift_details: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    created_at: Optional[datetime] = None


class ManifestIn(BaseModel):
    manifest: Any
