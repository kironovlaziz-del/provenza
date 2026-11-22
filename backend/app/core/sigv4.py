# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
AWS Signature Version 4 for S3 requests (the Authorization header, payload
in one piece) - what Amazon S3 and S3-compatible stores (MinIO, Backblaze
B2, Wasabi, Ceph) accept. Only what Provenza sends needs it: no query
strings, no chunked uploads. Checked against the examples in Amazon's S3 API
reference (tests/test_sigv4.py).

The secret never leaves: a request carries only the access key ID and the
signature, which covers the method, the path, every header sent and the
SHA-256 of the body.
"""

import hashlib
import hmac
from datetime import datetime
from typing import Dict
from urllib.parse import quote

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def canonical_uri(path: str) -> str:
    """Each byte encoded but the unreserved characters and "/"; S3 paths are
    not normalized (no collapsing of "//" or "..")."""
    return quote(path, safe="/-_.~")


def sign(method: str, path: str, headers: Dict[str, str], payload_sha256: str, *, access_key: str,
         secret_key: str, region: str, when: datetime, service: str = "s3") -> str:
    """The Authorization header for this request. `headers` are the headers
    sent (Host included; x-amz-date and x-amz-content-sha256 must be among
    them, matching `when` and the body); all of them are signed."""
    amz_date = when.strftime("%Y%m%dT%H%M%SZ")
    day = amz_date[:8]
    lower = {k.strip().lower(): " ".join(str(v).strip().split()) for k, v in headers.items()}
    if lower.get("x-amz-content-sha256") != payload_sha256:
        raise ValueError("x-amz-content-sha256 must be the SHA-256 of the payload")
    if lower.get("x-amz-date") != amz_date and "date" not in lower:
        raise ValueError("x-amz-date must be the signing time")
    names = sorted(lower)
    canonical = "\n".join([
        method.upper(),
        canonical_uri(path),
        "",                                            # no query string
        "".join(f"{n}:{lower[n]}\n" for n in names),
        ";".join(names),
        payload_sha256,
    ])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join([ALGORITHM, amz_date, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode("utf-8"), day), region), service), "aws4_request")
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{ALGORITHM} Credential={access_key}/{scope},SignedHeaders={';'.join(names)},Signature={signature}"
