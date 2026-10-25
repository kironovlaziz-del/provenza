# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Requests through the Provenza egress proxy in SDK mode (docs/pvp/spec.md, 5.5):
the agent checks the request itself and sends the check id; the proxy redeems
it and refuses anything other than exactly the checked request.

    chk = agent.proxy_check("stripe", "POST", "/v1/charges", body=payload)
    httpx.post("http://127.0.0.1:8443/stripe/v1/charges", content=payload, headers=chk.proxy_headers)

`path` and `query` are exactly what goes on the wire (percent-encoding kept),
`body` the exact bytes: the proxy hashes what it receives. The headers carry
the agent's signed request too: a proxy that enforces the signed policy
verifies the agent's signature itself (docs/pvp/edge.md, section 4).
"""

import base64
import hashlib
import json
from typing import Any, Dict, Optional, Union

ACTION_TYPE = "proxy"
HEADER = "X-Provenza-Check-Id"
# the agent's signed action.request, for a proxy that enforces the signed policy
REQUEST_HEADER = "X-Provenza-Request"
Bytes = Union[bytes, str, None]


def _raw(value: Bytes) -> bytes:
    if value is None:
        return b""
    return value.encode() if isinstance(value, str) else bytes(value)


def _sha(raw: bytes) -> Optional[str]:
    return hashlib.sha256(raw).hexdigest() if raw else None


def descriptor(route: str, method: str, path: str, *, query: Bytes = None, body: Bytes = None) -> Dict[str, Any]:
    """The checked input of a proxy request - hashes only, as the proxy computes it."""
    if not path.startswith("/"):
        raise ValueError("path must start with /")
    if "?" in path:
        raise ValueError("pass the query string as query=, not in path")
    raw_body, raw_query = _raw(body), _raw(query)
    return {"route": route, "method": method.upper(), "path": path, "query_sha256": _sha(raw_query),
            "body_sha256": _sha(raw_body), "body_bytes": len(raw_body)}


def tool_name(route: str) -> str:
    return "proxy." + route


def request_header(request: Dict[str, Any]) -> str:
    """base64url (unpadded) of the signed request's JSON."""
    raw = json.dumps(request, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
