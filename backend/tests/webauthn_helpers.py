"""
A software authenticator for the tests: makes passkeys and assertions the
way a browser and a device would (WebAuthn Level 2, "none" attestation),
with a minimal CBOR encoder.
"""

import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ORIGIN = "http://localhost:3000"
RP_ID = "localhost"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def cbor(value) -> bytes:
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
        raise ValueError(n)

    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


class SoftAuthenticator:
    def __init__(self, alg: int = -7, user_verified: bool = True, counting: bool = True):
        self.alg, self.uv, self.counting, self.count = alg, user_verified, counting, 0
        self.credential_id = secrets.token_bytes(32)
        if alg == -7:
            self.key = ec.generate_private_key(ec.SECP256R1())
            n = self.key.public_key().public_numbers()
            self.cose = {1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")}
        elif alg == -8:
            self.key = ed25519.Ed25519PrivateKey.generate()
            raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.cose = {1: 1, 3: -8, -1: 6, -2: raw}
        else:
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            n = self.key.public_key().public_numbers()
            self.cose = {1: 3, 3: -257, -1: n.n.to_bytes(256, "big"), -2: n.e.to_bytes(3, "big")}

    @property
    def id(self) -> str:
        return b64url(self.credential_id)

    def _flags(self, attested: bool) -> int:
        return 0x01 | (0x04 if self.uv else 0) | (0x40 if attested else 0)

    def _counter(self) -> bytes:
        if self.counting:
            self.count += 1
        return self.count.to_bytes(4, "big")

    def create(self, challenge: str, origin: str = ORIGIN, rp_id: str = RP_ID) -> dict:
        client = json.dumps({"type": "webauthn.create", "challenge": challenge, "origin": origin}).encode()
        auth = (hashlib.sha256(rp_id.encode()).digest() + bytes([self._flags(True)]) + self._counter()
                + b"\x00" * 16 + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cbor(self.cose))
        return {"client_data_json": b64url(client),
                "attestation_object": b64url(cbor({"fmt": "none", "attStmt": {}, "authData": auth}))}

    def get(self, challenge: str, origin: str = ORIGIN, rp_id: str = RP_ID) -> dict:
        client = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": origin}).encode()
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([self._flags(False)]) + self._counter()
        signed = auth + hashlib.sha256(client).digest()
        if self.alg == -7:
            sig = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        elif self.alg == -8:
            sig = self.key.sign(signed)
        else:
            sig = self.key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        return {"credential_id": self.id, "client_data_json": b64url(client),
                "authenticator_data": b64url(auth), "signature": b64url(sig)}
