from typing import Any, Dict, Literal, Optional, Union

from pydantic import BaseModel, Field, model_validator


class A2ASettingsIn(BaseModel):
    mode: Literal["off", "monitor", "enforce"]
    allow_same_chain: bool
    max_age_seconds: int = Field(ge=30, le=3600)
    message_ttl_seconds: int = Field(ge=60, le=86400)


class A2AChannelIn(BaseModel):
    from_agent_id: int
    to_agent_id: int
    bidirectional: bool = False

    @model_validator(mode="after")
    def _distinct(self):
        if self.from_agent_id == self.to_agent_id:
            raise ValueError("an agent does not need a channel to itself")
        return self


class A2AEnvelope(BaseModel):
    """The signed part. The signature covers canonical_bytes() of this object
    exactly as sent (including "type": "a2a_message")."""

    type: Literal["a2a_message"]
    from_agent_id: int
    to_agent_id: int
    chain_id: Optional[int] = None
    message_type: str = Field(min_length=1, max_length=50, pattern=r"^[A-Za-z0-9_.:\-]+$")
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(min_length=16, max_length=128)
    issued_at: Union[str, int, float]


class A2ASendIn(BaseModel):
    # kept as the raw dict: the signature is verified over exactly what the
    # sender signed, not over a re-serialised model
    envelope: Dict[str, Any]
    signature: str = Field(min_length=1, max_length=200)
    payload: Any

    @model_validator(mode="after")
    def _check(self):
        A2AEnvelope(**self.envelope)  # field validation (422 on a malformed envelope)
        extra = set(self.envelope) - set(A2AEnvelope.model_fields)
        if extra:
            raise ValueError(f"unknown envelope fields: {sorted(extra)}")
        if self.payload is None:
            raise ValueError("payload is required (it is scanned, not stored)")
        return self


class A2AReceiveIn(BaseModel):
    agent_id: int
    message_id: int
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
