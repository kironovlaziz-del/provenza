from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


class KeyConfigIn(BaseModel):
    provider: Literal["local", "vault_transit", "aws_kms"]
    # vault_transit
    addr: Optional[str] = Field(default=None, max_length=300, pattern=r"^https?://[^\s]+$")
    mount: Optional[str] = Field(default=None, max_length=100, pattern=r"^[A-Za-z0-9_\-/]+$")
    key_name: Optional[str] = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9_\-.]+$")
    token: Optional[str] = Field(default=None, max_length=500)
    namespace: Optional[str] = Field(default=None, max_length=200)
    # aws_kms
    region: Optional[str] = Field(default=None, max_length=40, pattern=r"^[a-z0-9-]+$")
    key_id: Optional[str] = Field(default=None, max_length=300)
    access_key_id: Optional[str] = Field(default=None, max_length=128)
    secret_access_key: Optional[str] = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def _required(self):
        need = {"vault_transit": ("addr", "key_name", "token"), "aws_kms": ("region", "key_id")}.get(self.provider, ())
        missing = [f for f in need if not getattr(self, f)]
        if missing:
            raise ValueError(f"{self.provider} needs: {', '.join(missing)}")
        if self.provider == "aws_kms" and bool(self.access_key_id) != bool(self.secret_access_key):
            raise ValueError("give both access_key_id and secret_access_key, or neither (instance role)")
        return self

    def config(self) -> dict:
        fields = {"vault_transit": ("addr", "mount", "key_name", "token", "namespace"),
                  "aws_kms": ("region", "key_id", "access_key_id", "secret_access_key")}.get(self.provider, ())
        return {f: getattr(self, f) for f in fields if getattr(self, f)}


class ShredIn(BaseModel):
    confirm: str = Field(min_length=1, max_length=50)
