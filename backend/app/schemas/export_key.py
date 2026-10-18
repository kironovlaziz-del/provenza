# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ExportKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)


class ExportKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    scope: str
    key_prefix: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None


class ExportKeyCreated(ExportKeyOut):
    """Returned once, at creation: only the hash is stored."""

    api_key: str
