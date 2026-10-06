# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Tamper-evident audit log: the hash chain and the Merkle tree over it.

Every audit record of an organization gets a sequence number (1, 2, 3, ...)
and a hash over its canonical form, which includes the hash of the record
before it. Change, remove or reorder one record and every hash after it
changes.

A chain alone proves nothing to an outsider: whoever controls the database
can rewrite a record and recompute every hash after it. So the record hashes
are also the leaves of a Merkle tree (RFC 9162 / Certificate Transparency
hashing), and the server periodically signs the tree's root - a checkpoint -
with its audit key (Ed25519 + ML-DSA-65). With a checkpoint someone kept
outside the server:
  - an inclusion proof shows one record is in the log the checkpoint signed,
    without seeing any other record;
  - a consistency proof shows a newer checkpoint only appended to the older
    one: nothing before it was changed or removed.

Everything here is pure functions; the database side is
app/services/audit_proofs.py. tools/provenza_audit.py re-implements the
checks independently, so a verifier does not have to trust this code.

Record canonical form ("v": 1) - see docs/audit-proofs.md:
  {"v":1,"org_id":..,"seq":..,"prev_hash":"<hex>","created_at":"YYYY-MM-DDTHH:MM:SS.ffffffZ",
   "actor_user_id":..,"entity_type":..,"entity_id":..,"action":..,"metadata":..}
serialized like every signed payload in Provenza (agent_signing.canonical_bytes):
sorted keys, no whitespace, ASCII with \\uXXXX escapes.
record_hash = hex(SHA-256(canonical bytes)); the first record's prev_hash is 64 zeros.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from app.core.agent_signing import canonical_bytes

RECORD_VERSION = 1
GENESIS_HASH = "0" * 64

# pg_advisory_xact_lock(class, object) namespaces ("PVZA" / "PVZC")
LOCK_APPEND = 0x50565A41
LOCK_CHECKPOINT = 0x50565A43

CHECKPOINT_TYPE = "provenza.audit.checkpoint"
HANDOVER_TYPE = "provenza.audit.key_handover"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

def normalize_metadata(value: Any) -> Any:
    """The JSON value that survives a round trip through PostgreSQL JSONB
    unchanged, so the hash computed before the insert still matches the row
    read back later:
      - anything json cannot encode becomes its str() (datetimes, Decimals, sets...);
      - integral floats become ints (JSONB returns 1e20 as an integer);
      - NaN / Infinity (rejected by JSONB) become strings;
      - NUL characters (rejected by JSONB) become U+FFFD;
      - non-string keys become strings, as json does."""
    if value is None:
        return None
    data = json.loads(json.dumps(value, default=str))
    return _walk(data)


def _walk(v: Any) -> Any:
    if isinstance(v, dict):
        return {_clean_str(str(k)): _walk(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_walk(x) for x in v]
    if isinstance(v, float):
        if not math.isfinite(v):
            return str(v)
        if v.is_integer():
            return int(v)
        return v
    if isinstance(v, str):
        return _clean_str(v)
    return v


def _clean_str(s: str) -> str:
    return s.replace("\x00", "�") if "\x00" in s else s


def format_ts(dt: Optional[datetime]) -> Optional[str]:
    """UTC, microseconds, 'Z' - exactly what timestamptz keeps."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def record_payload(*, org_id: int, seq: int, prev_hash: str, created_at: Optional[datetime],
                   actor_user_id: Optional[int], entity_type: str, entity_id: Optional[int],
                   action: str, metadata: Any) -> Dict[str, Any]:
    return {
        "v": RECORD_VERSION,
        "org_id": int(org_id),
        "seq": int(seq),
        "prev_hash": prev_hash,
        "created_at": format_ts(created_at),
        "actor_user_id": actor_user_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "action": action,
        "metadata": metadata,
    }


def payload_of(row) -> Dict[str, Any]:
    """record_payload for a stored AIAuditLog row."""
    return record_payload(org_id=row.org_id, seq=row.seq, prev_hash=row.prev_hash, created_at=row.created_at,
                          actor_user_id=row.actor_user_id, entity_type=row.entity_type,
                          entity_id=row.entity_id, action=row.action, metadata=row.metadata_json)


def record_hash(payload: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Merkle tree (RFC 9162 section 2.1): leaf = SHA-256(0x00 || data),
# node = SHA-256(0x01 || left || right); a tree of n leaves splits at the
# largest power of two below n. The leaf data is the 32-byte record hash.
# ---------------------------------------------------------------------------

def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


EMPTY_ROOT = hashlib.sha256(b"").digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class Frontier:
    """Root of every prefix of the log in one pass: keeps the roots of the
    perfect subtrees ("peaks") the leaves so far form. O(log n) memory."""

    def __init__(self) -> None:
        self.size = 0
        self._peaks: List[bytes] = []  # left to right, sizes are decreasing powers of two

    def append(self, data: bytes) -> None:
        h = leaf_hash(data)
        self.size += 1
        n = self.size
        # one merge per trailing zero bit of the new size
        while n & 1 == 0:
            h = node_hash(self._peaks.pop(), h)
            n >>= 1
        self._peaks.append(h)

    def root(self) -> bytes:
        if not self._peaks:
            return EMPTY_ROOT
        h = self._peaks[-1]
        for p in reversed(self._peaks[:-1]):
            h = node_hash(p, h)
        return h


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    f = Frontier()
    for d in leaves:
        f.append(d)
    return f.root()


class _Tree:
    """Leaf hashes of one log, for building proofs (O(n) per proof)."""

    def __init__(self, leaves: Sequence[bytes]):
        self.h = [leaf_hash(d) for d in leaves]

    def mth(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return self.h[lo]
        k = _split(n)
        return node_hash(self.mth(lo, lo + k), self.mth(lo + k, hi))

    def path(self, m: int, lo: int, hi: int) -> List[bytes]:
        n = hi - lo
        if n <= 1:
            return []
        k = _split(n)
        if m < k:
            return self.path(m, lo, lo + k) + [self.mth(lo + k, hi)]
        return self.path(m - k, lo + k, hi) + [self.mth(lo, lo + k)]

    def subproof(self, m: int, lo: int, hi: int, whole: bool) -> List[bytes]:
        n = hi - lo
        if m == n:
            return [] if whole else [self.mth(lo, hi)]
        k = _split(n)
        if m <= k:
            return self.subproof(m, lo, lo + k, whole) + [self.mth(lo + k, hi)]
        return self.subproof(m - k, lo + k, hi, False) + [self.mth(lo, lo + k)]


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> List[bytes]:
    """Audit path for leaf `index` (0-based) in the tree of all `leaves`."""
    if not 0 <= index < len(leaves):
        raise ValueError("leaf index out of range")
    return _Tree(leaves).path(index, 0, len(leaves))


def consistency_proof(old_size: int, leaves: Sequence[bytes]) -> List[bytes]:
    """Proof that the tree of the first `old_size` leaves is a prefix of the tree of all `leaves`."""
    n = len(leaves)
    if not 0 < old_size <= n:
        raise ValueError("old_size out of range")
    if old_size == n:
        return []
    return _Tree(leaves).subproof(old_size, 0, n, True)


def verify_inclusion(index: int, size: int, data: bytes, proof: Sequence[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn = index, size - 1
    r = leaf_hash(data)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes,
                       proof: Sequence[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if not 0 < old_size <= new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # power of two: the old root is the first node
        path = [old_root] + path
    if not path:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------

def checkpoint_statement(*, org_id: int, tree_size: int, root_hash: str, issued_at: datetime,
                         key_fingerprint: str, algorithm: str) -> Dict[str, Any]:
    """What the audit key signs (canonical bytes of this dict)."""
    return {
        "type": CHECKPOINT_TYPE,
        "v": RECORD_VERSION,
        "org_id": int(org_id),
        "tree_size": int(tree_size),
        "root_hash": root_hash,
        "issued_at": format_ts(issued_at),
        "key_fingerprint": key_fingerprint,
        "algorithm": algorithm,
    }


def handover_statement(*, org_id: int, rotation_id: int, tree_size: int, root_hash: str, issued_at: datetime,
                       proposed_at: datetime, quorum: int, approvals: Sequence[int],
                       old_key_fingerprint: str, old_algorithm: str,
                       new_key_fingerprint: str, new_algorithm: str) -> Dict[str, Any]:
    """What BOTH the old and the new audit key sign when the key changes:
    the old key consents to its successor, the new key proves it exists.
    tree_size / root_hash tie the change to a point in the log."""
    return {
        "type": HANDOVER_TYPE,
        "v": RECORD_VERSION,
        "org_id": int(org_id),
        "rotation_id": int(rotation_id),
        "tree_size": int(tree_size),
        "root_hash": root_hash,
        "issued_at": format_ts(issued_at),
        "proposed_at": format_ts(proposed_at),
        "quorum": int(quorum),
        "approvals": sorted(int(u) for u in approvals),
        "old_key_fingerprint": old_key_fingerprint,
        "old_algorithm": old_algorithm,
        "new_key_fingerprint": new_key_fingerprint,
        "new_algorithm": new_algorithm,
    }


def hexes(items: Iterable[bytes]) -> List[str]:
    return [x.hex() for x in items]
