# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
A local, signed, hash-chained audit log (JSON Lines) - what an agent keeps
when there is no server (standalone mode), and where a connected agent
writes a gap: an action that ran but that the server did not record.

Each line is one entry:

    {"v": 1, "seq": n, "prev_hash": <hash of entry n-1, or 64 zeros>,
     "ts": <unix seconds>, "agent": <name>, "status": "recorded" | "unrecorded" | "denied",
     "tool": ..., "action_type": ..., "input_sha256": ..., "output_sha256": ...,
     "duration_ms": ..., "reason": ..., "check_id": ...,
     "signature": <Ed25519 over the canonical entry without signature/pq_signature/hash>,
     "pq_signature": <ML-DSA-65, hybrid keys>, "hash": <SHA-256 of the canonical entry with signatures>}

Only hashes of inputs and outputs are written, never the content. Change,
drop or reorder a line and verify() names it. Like any log the agent writes
itself, it shows that it was not changed after the fact by someone without
the key - not that the agent wrote down everything it did.
"""

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from provenza.crypto import Keys, canonical, content_hash

GENESIS = "0" * 64
_SIGNATURE_FIELDS = ("signature", "pq_signature", "hash")

try:  # POSIX: serialize appends between processes too
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None


def _signed_part(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in entry.items() if k not in _SIGNATURE_FIELDS}


def _entry_hash(entry: Dict[str, Any]) -> str:
    return content_hash({k: v for k, v in entry.items() if k != "hash"})


class AuditLog:
    def __init__(self, path: Path, keys: Keys, agent: str):
        self.path, self.keys, self.agent = Path(path), keys, agent
        self._lock = threading.Lock()

    @staticmethod
    def _last(fd: int) -> Dict[str, Any]:
        """The last entry, read backwards from the end - O(entry), not O(log)."""
        end = os.lseek(fd, 0, os.SEEK_END)
        buf, pos = b"", end
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            os.lseek(fd, pos, os.SEEK_SET)
            buf = os.read(fd, step) + buf
            lines = [x for x in buf.split(b"\n") if x.strip()]
            if len(lines) > 1 or (lines and pos == 0):
                return json.loads(lines[-1])
        return {"seq": 0, "hash": GENESIS}

    def append(self, **fields: Any) -> Dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._lock:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                prev = self._last(fd)
                entry = {"v": 1, "seq": prev["seq"] + 1, "prev_hash": prev["hash"], "ts": int(time.time()),
                         "agent": self.agent, **fields}
                sig, pq = self.keys.sign(_signed_part(entry))
                entry["signature"] = sig
                if pq:
                    entry["pq_signature"] = pq
                entry["hash"] = _entry_hash(entry)
                os.write(fd, canonical(entry) + b"\n")   # O_APPEND: lands at the end
                os.fsync(fd)
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
        return entry

    def entries(self) -> Iterator[Dict[str, Any]]:
        if not self.path.exists():
            return
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)


def verify(path: Path, public_key: str, pq_public_key: Optional[str] = None) -> List[str]:
    """Problems found in a log, by line; empty when every entry is signed by
    this key and the chain is unbroken."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    problems: List[str] = []
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
    prev_hash, prev_seq = GENESIS, 0
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                problems.append(f"line {n}: not JSON")
                continue
            if entry.get("seq") != prev_seq + 1 or entry.get("prev_hash") != prev_hash:
                problems.append(f"line {n}: chain broken (an entry was removed, inserted or reordered)")
            if entry.get("hash") != _entry_hash(entry):
                problems.append(f"line {n}: hash does not match the entry (altered)")
            try:
                pub.verify(base64.b64decode(entry.get("signature", "")), canonical(_signed_part(entry)))
            except Exception:  # noqa: BLE001
                problems.append(f"line {n}: signature does not verify")
            if pq_public_key:
                from provenza.crypto import _mldsa

                try:
                    _mldsa().MLDSA65PublicKey.from_public_bytes(base64.b64decode(pq_public_key)).verify(
                        base64.b64decode(entry.get("pq_signature", "")), canonical(_signed_part(entry)))
                except Exception:  # noqa: BLE001
                    problems.append(f"line {n}: ML-DSA-65 signature does not verify")
            prev_hash, prev_seq = entry.get("hash", ""), entry.get("seq", prev_seq + 1)
    return problems
