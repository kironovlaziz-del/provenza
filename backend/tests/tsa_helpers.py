# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""A Time-Stamp Authority for tests: a CA, a TSA certificate under it, and
RFC 3161 responses built byte by byte (app/core/rfc3161.py's DER writer)."""

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.core import rfc3161 as r

OID_SHA256_RSA = "1.2.840.113549.1.1.11"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, key, signer, *, ca=False, eku=True, critical=True, days=365, start=None):
    start = start or datetime.now(timezone.utc) - timedelta(days=1)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if eku and not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=critical)
    return b.sign(signer, hashes.SHA256())


class FakeTSA:
    def __init__(self, **cert_kw):
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca = _cert("Test TSA Root", "Test TSA Root", self.ca_key, self.ca_key, ca=True)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cert = _cert("Test TSA", "Test TSA Root", self.key, self.ca_key, **cert_kw)
        self.serial = 1000
        self.requests = []

    @property
    def ca_pem(self) -> str:
        return self.ca.public_bytes(Encoding.PEM).decode()

    def token(self, digest: bytes, nonce=None, *, gen_time=None, tamper=False):
        self.serial += 1
        gen_time = gen_time or datetime.now(timezone.utc)
        imprint = r.seq(r.seq(r.oid(r.OID_SHA256), r.tlv(0x05, b"")), r.tlv(0x04, digest))
        fields = [r.der_int(1), r.oid("1.3.6.1.4.1.99999.1"), imprint, r.der_int(self.serial),
                  r.tlv(0x18, gen_time.strftime("%Y%m%d%H%M%SZ").encode())]
        if nonce is not None:
            fields.append(r.der_int(nonce))
        tst = r.seq(*fields)
        attrs = [
            r.seq(r.oid(r.OID_CONTENT_TYPE), r.tlv(0x31, r.oid(r.OID_TST_INFO))),
            r.seq(r.oid(r.OID_MESSAGE_DIGEST), r.tlv(0x31, r.tlv(0x04, hashlib.sha256(tst).digest()))),
        ]
        signed_attrs = r.tlv(0x31, b"".join(attrs))
        signature = self.key.sign(signed_attrs, padding.PKCS1v15(), hashes.SHA256())
        if tamper:   # the content changes after signing
            tst = tst.replace(r.der_int(self.serial), r.der_int(self.serial + 1))
        issuer_and_serial = r.seq(self.cert.issuer.public_bytes(), r.der_int(self.cert.serial_number))
        signer_info = r.seq(r.der_int(1), issuer_and_serial, r.seq(r.oid(r.OID_SHA256), r.tlv(0x05, b"")),
                            b"\xa0" + signed_attrs[1:], r.seq(r.oid(OID_SHA256_RSA), r.tlv(0x05, b"")),
                            r.tlv(0x04, signature))
        certs = r.tlv(0xA0, self.cert.public_bytes(Encoding.DER) + self.ca.public_bytes(Encoding.DER))
        signed_data = r.seq(r.der_int(3), r.tlv(0x31, r.seq(r.oid(r.OID_SHA256), r.tlv(0x05, b""))),
                            r.seq(r.oid(r.OID_TST_INFO), r.tlv(0xA0, r.tlv(0x04, tst))),
                            certs, r.tlv(0x31, signer_info))
        return r.seq(r.oid(r.OID_SIGNED_DATA), r.tlv(0xA0, signed_data))

    def respond(self, request_der: bytes, *, status=0, **kw) -> bytes:
        """Answer a TimeStampReq the way a TSA does."""
        self.requests.append(request_der)
        req = r.read_one(request_der).children()
        digest = req[1].children()[1].value
        nonce = r.parse_int(req[2]) if len(req) > 2 and req[2].tag == 0x02 else None
        status_info = r.seq(r.der_int(status))
        if status not in (0, 1):
            return r.seq(status_info)
        return r.seq(status_info, self.token(digest, nonce, **kw))
