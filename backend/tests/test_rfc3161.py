# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""RFC 3161 time-stamps (app/core/rfc3161.py): what passes and what does not."""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.core import rfc3161 as r
from tests.tsa_helpers import FakeTSA

DIGEST = hashlib.sha256(b"checkpoint statement").digest()


@pytest.fixture(scope="module")
def tsa():
    return FakeTSA()


def anchors(tsa):
    return r.load_anchors(tsa.ca_pem)


def test_a_granted_response_verifies(tsa):
    resp = tsa.respond(r.request(DIGEST, 42))
    tok = r.verify_response(resp, DIGEST, 42, anchors(tsa))
    assert tok.nonce == 42 and tok.serial == tsa.serial and tok.tsa_subject == "CN=Test TSA"
    assert abs((tok.gen_time - datetime.now(timezone.utc)).total_seconds()) < 5
    again = r.verify_token(tok.der, DIGEST, anchors(tsa))        # later, offline
    assert again.serial == tok.serial


def test_the_request_is_a_timestampreq(tsa):
    req = r.read_one(r.request(DIGEST, 7)).children()
    assert r.parse_int(req[0]) == 1 and req[1].children()[1].value == DIGEST and r.parse_int(req[2]) == 7
    assert req[3].tag == 0x01 and req[3].value == b"\xff"        # certReq


@pytest.mark.parametrize("case,code", [
    ("other_digest", "tsa.imprint_mismatch"),
    ("other_nonce", "tsa.nonce_mismatch"),
    ("tampered", "tsa.bad_token"),
    ("untrusted", "tsa.untrusted"),
    ("refused", "tsa.refused"),
    ("no_anchor", "tsa.no_trust_anchor"),
])
def test_what_does_not_verify(tsa, case, code):
    other = FakeTSA()
    resp = tsa.respond(r.request(DIGEST, 1), tamper=case == "tampered", status=2 if case == "refused" else 0)
    with pytest.raises(r.TimestampError) as e:
        r.verify_response(resp, hashlib.sha256(b"x").digest() if case == "other_digest" else DIGEST,
                          2 if case == "other_nonce" else 1,
                          [] if case == "no_anchor" else anchors(other if case == "untrusted" else tsa))
    assert e.value.code == code


@pytest.mark.parametrize("kw,code", [
    ({"eku": False}, "tsa.not_a_tsa_certificate"),
    ({"critical": False}, "tsa.not_a_tsa_certificate"),
    ({"days": 1, "start": datetime.now(timezone.utc) - timedelta(days=10)}, "tsa.certificate_expired"),
])
def test_the_signer_must_be_a_valid_tsa_certificate(kw, code):
    bad = FakeTSA(**kw)
    with pytest.raises(r.TimestampError) as e:
        r.verify_response(bad.respond(r.request(DIGEST, 1)), DIGEST, 1, anchors(bad))
    assert e.value.code == code


def test_garbage_is_refused_not_crashing():
    for junk in (b"", b"\x30", b"\x30\x00", b"\x30\x84\xff\xff\xff\xff", b"\x02\x01\x00\x00",
                 b"\x30\x03\x02\x01\x00", b"\x30\x05\x30\x03\x02\x01\x00"):
        with pytest.raises(r.TimestampError):
            r.verify_response(junk, DIGEST, 1, [])


def test_a_malformed_token_is_refused_not_crashing(tsa):
    for junk in (b"\x30\x00", b"\x30\x02\x06\x00", r.seq(r.oid(r.OID_SIGNED_DATA), r.tlv(0xA0, b"\x30\x00"))):
        with pytest.raises(r.TimestampError):
            r.verify_token(junk, DIGEST, anchors(tsa))
