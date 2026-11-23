# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The caller's W3C trace context, kept with what an agent does.

An agent instrumented with OpenTelemetry sends `traceparent` with its
requests (W3C Trace Context, https://www.w3.org/TR/trace-context/): the trace
it is in and its current span. Provenza keeps the two ids on the policy
check, the recorded action and the LLM gateway call that request produced,
so the OpenTelemetry export (app/services/otel_export.py) puts Provenza's
decision inside the agent's own trace.

Where it comes from:
  - the `traceparent` header of any request (TraceContextMiddleware);
  - for MCP, `params._meta.traceparent` of the JSON-RPC request, which wins
    over the header (app/api/mcp.py) - the place MCP clients carry it.

It is correlation data sent by the caller, nothing more: never trusted for a
decision, never part of the signed evidence. A value that is not a valid
traceparent is ignored, so nothing but 32 + 16 lower-case hex characters is
ever stored. `tracestate` is not kept.
"""

import re
from contextvars import ContextVar
from typing import Optional, Tuple

# version-traceid-parentid-flags; a version above 00 may carry more fields
# after these, which are ignored (W3C Trace Context, section 3.2 and 4.3)
_TRACEPARENT = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?$")
_ZERO_TRACE, _ZERO_SPAN = "0" * 32, "0" * 16
MAX_LENGTH = 512

TraceIds = Tuple[str, str]   # (trace_id: 32 hex, span_id: 16 hex)

_current: ContextVar[Optional[TraceIds]] = ContextVar("provenza_trace_context", default=None)


def parse(value) -> Optional[TraceIds]:
    """(trace_id, span_id) of a traceparent value, or None when it is not valid."""
    if not isinstance(value, str) or len(value) > MAX_LENGTH:
        return None
    m = _TRACEPARENT.match(value.strip())
    if m is None:
        return None
    version, trace_id, span_id, _flags, rest = m.groups()
    if version == "ff" or (version == "00" and rest):
        return None
    if trace_id == _ZERO_TRACE or span_id == _ZERO_SPAN:
        return None
    return trace_id, span_id


def current() -> Optional[TraceIds]:
    return _current.get()


def use(ids: Optional[TraceIds]) -> None:
    """Make ids the trace context of the rest of this request (MCP's _meta)."""
    if ids is not None:
        _current.set(ids)


def columns() -> dict:
    """trace_id / span_id for a new row, from the current context."""
    ids = _current.get()
    return {"trace_id": ids[0], "span_id": ids[1]} if ids else {}


class TraceContextMiddleware:
    """Reads the `traceparent` header of every HTTP request into the context
    for that request only."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        values = [v for n, v in scope.get("headers") or () if n == b"traceparent"]
        # more than one traceparent is invalid (W3C Trace Context, 3.2)
        ids = parse(values[0].decode("latin-1")) if len(values) == 1 else None
        token = _current.set(ids)
        try:
            return await self.app(scope, receive, send)
        finally:
            _current.reset(token)
