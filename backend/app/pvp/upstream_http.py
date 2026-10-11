# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
HTTP to upstream servers for the PVP executors (MCP gateway, A2A gateway).

One place for what every upstream call needs:
  - core/outbound.guarded_async_client: the resolved address is checked at
    connect time (no private ranges, no DNS rebinding), redirects are not
    followed;
  - responses are read up to a byte limit - a hostile server cannot
    exhaust memory;
  - a JSON-RPC answer is taken from a JSON body or an SSE stream (the
    response to our id; notifications before it are skipped);
  - failures become UpstreamError with a stable code.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.outbound import guarded_async_client

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class UpstreamError(Exception):
    """The upstream server could not be used. `code` is a stable reason;
    the message is for the admin (never shown to an agent verbatim)."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


def _client(timeout: float) -> httpx.AsyncClient:
    """Overridden in tests with an in-process transport."""
    return guarded_async_client(timeout=timeout)


async def fetch(method: str, url: str, *, headers: Dict[str, str], timeout: float, body: Optional[bytes] = None,
                max_bytes: int = MAX_RESPONSE_BYTES) -> Tuple[int, Dict[str, str], bytes]:
    """(status, lower-cased headers, body) of one bounded request."""
    try:
        async with _client(timeout) as client:
            async with client.stream(method, url, content=body, headers=headers) as resp:
                raw = bytearray()
                async for chunk in resp.aiter_bytes():
                    raw += chunk
                    if len(raw) > max_bytes:
                        raise UpstreamError("upstream.response_too_large")
                return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, bytes(raw)
    except UpstreamError:
        raise
    except httpx.TimeoutException as exc:
        raise UpstreamError("upstream.timeout", str(exc)) from exc
    except httpx.HTTPError as exc:
        raise UpstreamError("upstream.unreachable", f"{type(exc).__name__}: {exc}") from exc


def _pick(messages: List[Any], rid: Any) -> Optional[dict]:
    for msg in messages:
        if isinstance(msg, dict) and msg.get("id") == rid and ("result" in msg or "error" in msg):
            return msg
    return None


def parse_body(content_type: str, raw: bytes, rid: Any) -> Optional[dict]:
    """The JSON-RPC response with id `rid` from a JSON body or an SSE stream."""
    text = raw.decode("utf-8", errors="replace")
    if "text/event-stream" in content_type:
        messages = []
        for event in re.split(r"\r?\n\r?\n", text):
            data = "\n".join(line[5:].lstrip() for line in re.split(r"\r?\n", event) if line.startswith("data:"))
            if data:
                try:
                    messages.append(json.loads(data))
                except ValueError:
                    continue
        return _pick(messages, rid)
    try:
        msg = json.loads(text) if text.strip() else None
    except ValueError:
        return None
    return _pick(msg if isinstance(msg, list) else [msg], rid)


async def jsonrpc(url: str, body: dict, *, headers: Dict[str, str], timeout: float,
                  max_bytes: int = MAX_RESPONSE_BYTES) -> Tuple[int, Dict[str, str], Optional[dict]]:
    """POST one JSON-RPC message. The parsed response is None for a
    notification or when the body holds no response to our id."""
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **headers}
    status, resp_headers, raw = await fetch("POST", url, headers=h, timeout=timeout,
                                            body=json.dumps(body).encode(), max_bytes=max_bytes)
    rid = body.get("id")
    msg = parse_body(resp_headers.get("content-type", ""), raw, rid) if rid is not None else None
    return status, resp_headers, msg


async def get_json(url: str, *, headers: Dict[str, str], timeout: float, max_bytes: int) -> Any:
    status, resp_headers, raw = await fetch("GET", url, headers={"Accept": "application/json", **headers},
                                            timeout=timeout, max_bytes=max_bytes)
    if status != 200:
        raise UpstreamError("upstream.http_error", f"HTTP {status}")
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise UpstreamError("upstream.bad_response", "not JSON") from exc
