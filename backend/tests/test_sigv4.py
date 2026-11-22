# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""AWS Signature Version 4 (app/core/sigv4.py) against the examples in Amazon's
S3 API reference: "Signature Calculations for the Authorization Header:
Transferring Payload in a Single Chunk" (GET Object, PUT Object)."""

import hashlib
from datetime import datetime, timezone

import pytest

from app.core import sigv4

KEYS = {"access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1", "when": datetime(2013, 5, 24, tzinfo=timezone.utc)}


def test_get_object_example():
    auth = sigv4.sign("GET", "/test.txt", {
        "Host": "examplebucket.s3.amazonaws.com", "Range": "bytes=0-9",
        "x-amz-content-sha256": sigv4.EMPTY_SHA256, "x-amz-date": "20130524T000000Z"}, sigv4.EMPTY_SHA256, **KEYS)
    assert auth == ("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
                    "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
                    "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


def test_put_object_example():
    payload = hashlib.sha256(b"Welcome to Amazon S3.").hexdigest()
    assert payload == "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
    auth = sigv4.sign("PUT", "/test$file.text", {
        "Host": "examplebucket.s3.amazonaws.com", "Date": "Fri, 24 May 2013 00:00:00 GMT",
        "x-amz-date": "20130524T000000Z", "x-amz-storage-class": "REDUCED_REDUNDANCY",
        "x-amz-content-sha256": payload}, payload, **KEYS)
    assert auth.endswith("SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,"
                         "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")


def test_the_payload_hash_must_match():
    with pytest.raises(ValueError):
        sigv4.sign("PUT", "/k", {"Host": "h", "x-amz-date": "20130524T000000Z",
                                 "x-amz-content-sha256": sigv4.EMPTY_SHA256}, "0" * 64, **KEYS)
