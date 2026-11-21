"""A malformed signed-request header is refused with a fixed reason of ours;
the text of an arbitrary exception never reaches the caller (CodeQL py/stack-trace-exposure)."""
import base64
import json
import uuid
from types import SimpleNamespace

import pytest

from app.api import mcp


def _hdr(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


AGENT = SimpleNamespace(id=uuid.uuid4())


@pytest.mark.parametrize("header,reason", [
    ("%%%not-base64%%%", "the header is not base64url-encoded JSON"),
    (_hdr(b"\xff\xfe"), "the header is not base64url-encoded JSON"),
    (_hdr(b"{not json"), "the header is not base64url-encoded JSON"),
    (_hdr([1, 2]), "expected nonce, issued_at, signature, pq_signature and, optionally, mandate_id"),
    (_hdr({"nonce": "n", "extra": 1}), "expected nonce, issued_at, signature, pq_signature and, optionally, mandate_id"),
])
def test_unreadable_headers_get_a_fixed_reason(header, reason):
    with pytest.raises(mcp._MalformedSignedRequest) as err:
        mcp._signed_request(header, AGENT, "tool", {}, None)
    assert err.value.reason == reason


def test_a_field_error_names_the_field_only():
    with pytest.raises(mcp._MalformedSignedRequest) as err:
        mcp._signed_request(_hdr({"nonce": 5, "issued_at": "x", "signature": [], "pq_signature": {}}),
                            AGENT, "tool", {}, None)
    assert err.value.reason.startswith("invalid ")
    assert len(err.value.reason) <= 100
