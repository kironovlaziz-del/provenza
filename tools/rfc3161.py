# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
RFC 3161 time-stamps (pure functions): ask a Time-Stamp Authority to sign
the hash of some bytes, and verify what it answers - without any ASN.1
library, with a small DER reader/writer and `cryptography` for signatures.

    req = request(sha256_digest, nonce)           # application/timestamp-query
    tst = verify_response(resp_der, digest, nonce, trust_anchors)
    tst = verify_token(token_der, digest, trust_anchors)   # later, offline

What is checked: the response is "granted"; the token is CMS SignedData
over a TSTInfo whose messageImprint is our digest (and nonce, when asked);
the signed attributes carry that content type and the content's digest;
the signature verifies with the signer certificate named by the token; that
certificate is a time-stamping one (EKU id-kp-timeStamping), valid at the
stamped time, and chains - directly or through certificates the token
carries - to one of the trust anchors the operator configured.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

# ------------------------------------------------------------------ OIDs
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_RSA = "1.2.840.113549.1.1.1"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
_RSA_WITH = {"1.2.840.113549.1.1.11": OID_SHA256, "1.2.840.113549.1.1.12": OID_SHA384,
             "1.2.840.113549.1.1.13": OID_SHA512}
_ECDSA_WITH = {"1.2.840.10045.4.3.2": OID_SHA256, "1.2.840.10045.4.3.3": OID_SHA384,
               "1.2.840.10045.4.3.4": OID_SHA512}
_HASHES = {OID_SHA256: (hashes.SHA256, hashlib.sha256), OID_SHA384: (hashes.SHA384, hashlib.sha384),
           OID_SHA512: (hashes.SHA512, hashlib.sha512)}
MAX_CHAIN = 4
_DER = Encoding.DER


class TimestampError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


# ------------------------------------------------------------------ DER
@dataclass
class Node:
    tag: int
    value: bytes      # the contents
    raw: bytes        # the whole TLV

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> List["Node"]:
        return read_all(self.value)


def _read(data: bytes, pos: int) -> Tuple[Node, int]:
    if pos + 2 > len(data):
        raise TimestampError("tsa.bad_der", "truncated")
    start, tag = pos, data[pos]
    if tag & 0x1F == 0x1F:
        raise TimestampError("tsa.bad_der", "multi-byte tags are not used here")
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise TimestampError("tsa.bad_der", "bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise TimestampError("tsa.bad_der", "truncated value")
    return Node(tag, data[pos:pos + length], data[start:pos + length]), pos + length


def read_one(data: bytes) -> Node:
    node, end = _read(data, 0)
    if end != len(data):
        raise TimestampError("tsa.bad_der", "trailing bytes")
    return node


def read_all(data: bytes) -> List[Node]:
    out, pos = [], 0
    while pos < len(data):
        node, pos = _read(data, pos)
        out.append(node)
    return out


def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + value


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def der_int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, b)


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def parse_oid(node: Node) -> str:
    if node.tag != 0x06 or not node.value:
        raise TimestampError("tsa.bad_der", "expected an OID")
    first = node.value[0]
    parts = [first // 40 if first < 80 else 2, first % 40 if first < 80 else first - 80]
    n = 0
    for b in node.value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def parse_int(node: Node) -> int:
    if node.tag != 0x02:
        raise TimestampError("tsa.bad_der", "expected an INTEGER")
    return int.from_bytes(node.value, "big", signed=True)


def _expect(node: Node, tag: int, what: str) -> Node:
    if node.tag != tag:
        raise TimestampError("tsa.bad_der", f"{what}: tag {node.tag:#x}")
    return node


# ------------------------------------------------------------------ request
def request(digest: bytes, nonce: int, hash_oid: str = OID_SHA256) -> bytes:
    """TimeStampReq v1 for a digest; certReq true, so the token carries the
    signer certificate."""
    imprint = seq(seq(oid(hash_oid), tlv(0x05, b"")), tlv(0x04, digest))
    return seq(der_int(1), imprint, der_int(nonce), tlv(0x01, b"\xff"))


# ------------------------------------------------------------------ token
@dataclass
class Token:
    der: bytes                 # the TimeStampToken (ContentInfo), what is stored
    gen_time: datetime
    serial: int
    policy: str
    nonce: Optional[int]
    tsa_subject: str           # the signer certificate's subject
    hash_oid: str


def _gen_time(node: Node) -> datetime:
    _expect(node, 0x18, "genTime")
    text = node.value.decode("ascii")
    if not text.endswith("Z"):
        raise TimestampError("tsa.bad_token", "genTime is not UTC")
    main = text[:-1]
    frac = ""
    if "." in main:
        main, frac = main.split(".", 1)
    dt = datetime.strptime(main, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    return dt


def _tst_info(der: bytes):
    items = read_one(der).children()
    if len(items) < 5 or parse_int(items[0]) != 1:
        raise TimestampError("tsa.bad_token", "TSTInfo")
    policy = parse_oid(items[1])
    imprint = items[2].children()
    hash_oid = parse_oid(imprint[0].children()[0])
    hashed = _expect(imprint[1], 0x04, "hashedMessage").value
    serial = parse_int(items[3])
    gen_time = _gen_time(items[4])
    nonce = None
    for extra in items[5:]:
        if extra.tag == 0x02:
            nonce = parse_int(extra)
    return policy, hash_oid, hashed, serial, gen_time, nonce


def _signer_cert(certs: List[x509.Certificate], sid: Node) -> x509.Certificate:
    if sid.tag == 0x30:                      # issuerAndSerialNumber
        issuer_raw, serial_node = sid.children()[:2]
        serial = parse_int(serial_node)
        for c in certs:
            if c.serial_number == serial and c.issuer.public_bytes() == issuer_raw.raw:
                return c
    elif sid.tag == 0x80:                    # [0] subjectKeyIdentifier
        for c in certs:
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            except x509.ExtensionNotFound:
                continue
            if ski == sid.value:
                return c
    raise TimestampError("tsa.no_signer_certificate", "the token does not carry the signer's certificate")


def _verify_sig(cert: x509.Certificate, sig_alg: str, digest_oid: str, signature: bytes, data: bytes) -> None:
    key = cert.public_key()
    hash_cls = _HASHES.get(_RSA_WITH.get(sig_alg) or _ECDSA_WITH.get(sig_alg) or digest_oid, (None,))[0]
    if hash_cls is None:
        raise TimestampError("tsa.unsupported_algorithm", sig_alg)
    try:
        if isinstance(key, rsa.RSAPublicKey) and sig_alg == OID_RSA_PSS:
            key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=padding.PSS.AUTO),
                       hash_cls())
        elif isinstance(key, rsa.RSAPublicKey) and (sig_alg in _RSA_WITH or sig_alg == OID_RSA):
            key.verify(signature, data, padding.PKCS1v15(), hash_cls())
        elif isinstance(key, ec.EllipticCurvePublicKey) and sig_alg in _ECDSA_WITH:
            key.verify(signature, data, ec.ECDSA(hash_cls()))
        else:
            raise TimestampError("tsa.unsupported_algorithm", sig_alg)
    except InvalidSignature:
        raise TimestampError("tsa.bad_signature")


def _chains(cert: x509.Certificate, pool: Sequence[x509.Certificate], anchors: Sequence[x509.Certificate],
            at: datetime) -> bool:
    current = cert
    for _ in range(MAX_CHAIN):
        for anchor in anchors:
            if current.public_bytes(_DER) == anchor.public_bytes(_DER):
                return True
            if current.issuer == anchor.subject and _issued_by(current, anchor):
                return True
        parent = next((c for c in pool if c.subject == current.issuer and c is not current
                       and _issued_by(current, c) and _valid_at(c, at)), None)
        if parent is None:
            return False
        current = parent
    return False


def _issued_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _valid_at(cert: x509.Certificate, at: datetime) -> bool:
    return cert.not_valid_before_utc <= at <= cert.not_valid_after_utc



def verify_token(token_der: bytes, digest: bytes, anchors: Sequence[x509.Certificate],
                 nonce: Optional[int] = None) -> Token:
    """Everything in the module docstring, for a stored token."""
    try:
        return _verify_token(token_der, digest, anchors, nonce)
    except TimestampError:
        raise
    except (IndexError, ValueError, TypeError, UnicodeDecodeError) as exc:   # malformed structure
        raise TimestampError("tsa.bad_der", type(exc).__name__)


def _verify_token(token_der: bytes, digest: bytes, anchors: Sequence[x509.Certificate],
                  nonce: Optional[int]) -> Token:
    if not anchors:
        raise TimestampError("tsa.no_trust_anchor", "configure the TSA's certificate or CA")
    content_info = read_one(token_der).children()
    if len(content_info) != 2 or parse_oid(content_info[0]) != OID_SIGNED_DATA:
        raise TimestampError("tsa.bad_token", "not CMS SignedData")
    signed = _expect(content_info[1], 0xA0, "content").children()[0].children()
    encap = signed[2].children()
    if parse_oid(encap[0]) != OID_TST_INFO:
        raise TimestampError("tsa.bad_token", "not a TSTInfo")
    tst_der = _expect(_expect(encap[1], 0xA0, "eContent").children()[0], 0x04, "eContent").value
    certs: List[x509.Certificate] = []
    signer_infos = None
    for item in signed[3:]:
        if item.tag == 0xA0:
            certs = [x509.load_der_x509_certificate(c.raw) for c in item.children() if c.tag == 0x30]
        elif item.tag == 0x31:
            signer_infos = item.children()
    if not signer_infos or len(signer_infos) != 1:
        raise TimestampError("tsa.bad_token", "expected one signer")
    si = signer_infos[0].children()
    sid, digest_alg = si[1], parse_oid(si[2].children()[0])
    rest = si[3:]
    if not rest or rest[0].tag != 0xA0:
        raise TimestampError("tsa.bad_token", "no signed attributes")
    attrs_node, sig_alg, signature = rest[0], parse_oid(rest[1].children()[0]), _expect(rest[2], 0x04, "sig").value
    if digest_alg not in _HASHES:
        raise TimestampError("tsa.unsupported_algorithm", digest_alg)

    # the signed attributes: content type TSTInfo and the digest of the content
    content_type = message_digest = None
    for attr in attrs_node.children():
        kind, values = attr.children()
        kind = parse_oid(kind)
        if kind == OID_CONTENT_TYPE:
            content_type = parse_oid(values.children()[0])
        elif kind == OID_MESSAGE_DIGEST:
            message_digest = values.children()[0].value
    if content_type != OID_TST_INFO or message_digest != _HASHES[digest_alg][1](tst_der).digest():
        raise TimestampError("tsa.bad_token", "signed attributes do not match the content")

    policy, hash_oid, hashed, serial, gen_time, tst_nonce = _tst_info(tst_der)
    if hashed != digest:
        raise TimestampError("tsa.imprint_mismatch", "the time-stamp is for other data")
    if nonce is not None and tst_nonce != nonce:
        raise TimestampError("tsa.nonce_mismatch")

    cert = _signer_cert(certs, sid)
    # what is signed is the DER of the attributes as a SET (tag 0x31), not [0]
    _verify_sig(cert, sig_alg, digest_alg, signature, b"\x31" + attrs_node.raw[1:])
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        raise TimestampError("tsa.not_a_tsa_certificate", "no extended key usage")
    if list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING] or not eku.critical:
        raise TimestampError("tsa.not_a_tsa_certificate", "EKU must be timeStamping only, critical")
    if not _valid_at(cert, gen_time):
        raise TimestampError("tsa.certificate_expired", "not valid at the stamped time")
    if not _chains(cert, certs, anchors, gen_time):
        raise TimestampError("tsa.untrusted", "the signer does not chain to a configured trust anchor")
    return Token(der=token_der, gen_time=gen_time, serial=serial, policy=policy, nonce=tst_nonce,
                 tsa_subject=cert.subject.rfc4514_string(), hash_oid=hash_oid)


def verify_response(resp_der: bytes, digest: bytes, nonce: int, anchors: Sequence[x509.Certificate]) -> Token:
    """A TimeStampResp, as the TSA answered the request(digest, nonce)."""
    try:
        items = read_one(resp_der).children()
        status = parse_int(items[0].children()[0])
    except TimestampError:
        raise
    except (IndexError, ValueError) as exc:
        raise TimestampError("tsa.bad_der", type(exc).__name__)
    if status not in (0, 1) or len(items) < 2:
        raise TimestampError("tsa.refused", f"status {status}")
    return verify_token(items[1].raw, digest, anchors, nonce)


def load_anchors(pem: str) -> List[x509.Certificate]:
    try:
        return list(x509.load_pem_x509_certificates(pem.encode()))
    except ValueError as exc:
        raise TimestampError("tsa.bad_trust_anchor", str(exc)[:100])
