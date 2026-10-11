# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
An agent's identity: who it is to the server (agent id, API key) and the keys
it signs with. Keys are generated HERE, on the agent's side; the server only
ever receives public keys (enrollment, docs/agent-signing.md).

Storage:
  file      (default) ~/.config/provenza/agents/<name>.json, mode 600 in a
            700 directory, written atomically. The same format as
            `tools/provenza_sign.py enroll`, so an agent enrolled with the CLI
            runs with the SDK and the other way round.
  keychain  pip install 'provenza[keychain]': the private keys and the API
            key go to the OS keychain (service "provenza"); the file keeps
            only public data.

What this protects against, said plainly: other users and processes on the
machine, and a leaked file (keychain). It does not protect the key from the
agent's own code - that code can read whatever the agent can.
"""

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from provenza.client import Client
from provenza.crypto import Keys
from provenza.errors import ProvenzaConfigError

SECRET_FIELDS = ("private_key", "pq_private_key", "api_key")
KEYCHAIN_SERVICE = "provenza"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "provenza" / "agents"


def default_path(name: str) -> Path:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-.") or "agent"
    return config_dir() / f"{slug}.json"


@dataclass
class Identity:
    keys: Keys
    server: Optional[str] = None          # None = a standalone (local-only) identity
    agent_id: Optional[int] = None
    api_key: Optional[str] = None
    name: Optional[str] = None

    @property
    def fingerprint(self) -> str:
        return self.keys.fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return {"server": self.server, "agent_id": self.agent_id, "api_key": self.api_key, "name": self.name,
                "private_key": self.keys.private_key, "public_key": self.keys.public_key,
                "pq_private_key": self.keys.pq_private_key, "pq_public_key": self.keys.pq_public_key,
                "key_fingerprint": self.fingerprint}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Identity":
        try:
            keys = Keys(d["private_key"], d["public_key"], d.get("pq_private_key"), d.get("pq_public_key"))
        except KeyError as exc:
            raise ProvenzaConfigError(f"identity file lacks {exc}") from exc
        return cls(keys=keys, server=d.get("server"), agent_id=d.get("agent_id"), api_key=d.get("api_key"),
                   name=d.get("name"))


# --- storage ----------------------------------------------------------------------

def _write_private(path: Path, data: Dict[str, Any]) -> None:
    """Owner-only, atomic: a crash never leaves half a key file behind."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _keyring():
    try:
        import keyring
    except ImportError as exc:
        raise ProvenzaConfigError("key_store='keychain' needs: pip install 'provenza[keychain]'") from exc
    return keyring


def _account(path: Path) -> str:
    return str(path.resolve())


def save(identity: Identity, path: Path, key_store: str = "file") -> None:
    data = identity.to_dict()
    if key_store == "keychain":
        kr = _keyring()
        kr.set_password(KEYCHAIN_SERVICE, _account(path), json.dumps({k: data[k] for k in SECRET_FIELDS}))
        data = {**{k: None for k in SECRET_FIELDS}, **{k: v for k, v in data.items() if k not in SECRET_FIELDS},
                "secrets": "keychain"}
    elif key_store != "file":
        raise ProvenzaConfigError("key_store must be 'file' or 'keychain'")
    _write_private(path, data)


def load(path: Path) -> Identity:
    try:
        st = path.stat()
        if os.name == "posix" and st.st_mode & 0o077:
            raise ProvenzaConfigError(f"{path} is readable by other users; chmod 600 it (it holds private keys)")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise ProvenzaConfigError(f"cannot read the identity at {path}: {exc}") from exc
    if data.get("secrets") == "keychain":
        stored = _keyring().get_password(KEYCHAIN_SERVICE, _account(path))
        if not stored:
            raise ProvenzaConfigError(f"the keychain has no secrets for {path}")
        data.update(json.loads(stored))
    return Identity.from_dict(data)


# --- enrollment -------------------------------------------------------------------

def enroll(client: Client, token: str, *, name: Optional[str] = None, hybrid: bool = False) -> Identity:
    """Join with a one-time enrollment token: generate the keys here, prove
    possession by signing the server's challenge (provenza.agent.enroll v1)."""
    ch = client.post("/agent-enrollment/challenge", {"token": token}, authenticated=False)
    keys = Keys.generate(hybrid or bool(ch.get("require_hybrid")))
    final = (ch.get("name") or name or "").strip()
    statement = {"type": "provenza.agent.enroll", "v": 1, "challenge": ch["challenge"], "org_id": ch["org_id"],
                 "enrollment_id": ch["enrollment_id"], "public_key": keys.public_key,
                 "pq_public_key": keys.pq_public_key, "name": final}
    sig, pq = keys.sign(statement)
    res = client.post("/agent-enrollment/enroll", {
        "token": token, "challenge": ch["challenge"], "public_key": keys.public_key,
        "pq_public_key": keys.pq_public_key, "name": final or None, "signature": sig, "pq_signature": pq,
    }, authenticated=False)
    if res.get("key_fingerprint") and res["key_fingerprint"] != keys.fingerprint:
        raise ProvenzaConfigError("the server registered another key than the one generated here")
    return Identity(keys=keys, server=client.server_url, agent_id=res["agent_id"], api_key=res.get("api_key"),
                    name=res.get("name") or final or None)
