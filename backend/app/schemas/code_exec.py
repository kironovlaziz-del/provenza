import re
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

_TOOL_GLOB = re.compile(r"^[A-Za-z0-9_.*?\-:/]{1,100}$")


class CodeExecSettingsIn(BaseModel):
    mode: Literal["off", "monitor", "enforce"]
    code_tools: List[str] = Field(max_length=50)
    approve_code_tools: bool

    @field_validator("code_tools")
    @classmethod
    def _globs(cls, v: List[str]) -> List[str]:
        out = []
        for g in v:
            g = g.strip()
            if not _TOOL_GLOB.match(g):
                raise ValueError(f"invalid tool pattern: {g!r} (letters, digits, . _ - : / * ? only, up to 100)")
            if g not in out:
                out.append(g)
        return out


class CodeExecScanIn(BaseModel):
    tool_name: Optional[str] = Field(default=None, max_length=100)
    arguments: Any = None
    text: Optional[str] = Field(default=None, max_length=100_000)
