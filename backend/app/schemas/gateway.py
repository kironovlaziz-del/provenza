from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


class GatewaySettingsIn(BaseModel):
    enabled: bool
    rpm_per_agent: int = Field(ge=1, le=6000)
    max_tokens_cap: int = Field(ge=16, le=200_000)
    scan_output: bool
    # moved to the Blocked terms page; refused rather than silently dropped
    blocked_terms: Optional[List[str]] = None

    @field_validator("blocked_terms")
    @classmethod
    def _terms(cls, v: Optional[List[str]]) -> None:
        if v and any((t or "").strip() for t in v):
            raise ValueError("blocked terms are kept on the Blocked terms page (/blocked-terms)")
        return None


class GatewayRouteIn(BaseModel):
    model: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:/*?\-]+$")
    provider_id: int
    upstream_model: Optional[str] = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9_.:/\-]+$")


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")
    role: str = Field(pattern=r"^(system|developer|user|assistant|tool|function)$")
    content: Optional[Union[str, List[Dict[str, Any]]]] = None
    name: Optional[str] = None


class ChatCompletionIn(BaseModel):
    """OpenAI chat.completions request (the subset the gateway forwards)."""

    model_config = ConfigDict(extra="allow")
    model: str = Field(min_length=1, max_length=200)
    messages: List[ChatMessage] = Field(min_length=1, max_length=500)
    temperature: Optional[float] = Field(default=None, ge=0, le=2)
    top_p: Optional[float] = Field(default=None, ge=0, le=1)
    max_tokens: Optional[int] = Field(default=None, ge=1)
    max_completion_tokens: Optional[int] = Field(default=None, ge=1)
    stop: Optional[Union[str, List[str]]] = None
    stream: Optional[bool] = False
    user: Optional[str] = None
