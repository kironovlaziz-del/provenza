# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Per-organization envelope encryption (BYOK).

Each organization may have a data-encryption key (DEK, a Fernet key) that
encrypts its secrets: connection API keys, raw prompts, directory
passwords. The DEK is stored only wrapped by a key-encryption key (KEK):

  local          the server master key (ENCRYPTION_KEY) - per-organization
                 keys, rotation and shredding, no external dependency
  vault_transit  a HashiCorp Vault Transit key the customer controls
  aws_kms        an AWS KMS key the customer controls (needs boto3); the
                 organization id is bound as encryption context

Ciphertext formats understood by app.core.crypto.decrypt_secret:
  pvz2:<org_key_id>:<fernet token>   - this module
  <fernet token>                     - legacy, server key

Unwrapped DEKs are cached in process memory for CACHE_TTL. The cache is
filled when a key is created or rotated in this process; on a miss (another
process, after a restart) the key row is read through the synchronous
engine and unwrapped. A KEK disabled in the customer's KMS therefore stops
decryption everywhere within CACHE_TTL; shredding in Provenza wipes the
wrapped DEK, after which the data cannot be decrypted by anyone.
"""

import base64
import json
import threading
import time
from typing import Any, Dict, Optional, Tuple

from cryptography.fernet import Fernet

PREFIX = "pvz2:"
CACHE_TTL = 300.0          # unwrapped DEK
ACTIVE_TTL = 60.0          # org -> active key id
PROVIDERS = ("local", "vault_transit", "aws_kms")
SECRET_FIELDS = {"vault_transit": ("token",), "aws_kms": ("secret_access_key",), "local": ()}

_lock = threading.Lock()
_dek: Dict[int, Tuple[Fernet, float]] = {}            # key id -> (fernet, expires)
_active: Dict[int, Tuple[Optional[int], float]] = {}  # org id -> (key id | None, expires)


class KeyUnavailable(ValueError):
    """The organization key cannot be used (shredded, KMS refused, unknown)."""


# ---------------------------------------------------------------------- cache
def remember(key_id: int, dek: bytes) -> None:
    with _lock:
        _dek[key_id] = (Fernet(dek), time.monotonic() + CACHE_TTL)


def remember_active(org_id: int, key_id: Optional[int]) -> None:
    with _lock:
        _active[org_id] = (key_id, time.monotonic() + ACTIVE_TTL)


def forget(key_id: Optional[int] = None, org_id: Optional[int] = None) -> None:
    with _lock:
        if key_id is not None:
            _dek.pop(key_id, None)
        if org_id is not None:
            _active.pop(org_id, None)


# ---------------------------------------------------------------------- KEK providers
def _master() -> Fernet:
    from app.core.crypto import _get_fernet
    return _get_fernet()


def seal_config(provider: str, config: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
    """Split a KEK config into the public part and the master-key-encrypted secret part."""
    secret = {k: config[k] for k in SECRET_FIELDS.get(provider, ()) if config.get(k)}
    public = {k: v for k, v in config.items() if k not in SECRET_FIELDS.get(provider, ()) and v not in (None, "")}
    sealed = _master().encrypt(json.dumps(secret).encode()).decode() if secret else None
    return public, sealed


def _open_config(public: Dict[str, Any], sealed: Optional[str]) -> Dict[str, Any]:
    cfg = dict(public or {})
    if sealed:
        cfg.update(json.loads(_master().decrypt(sealed.encode()).decode()))
    return cfg


def _vault_client():
    import httpx
    return httpx.Client(timeout=10.0)


def _vault(cfg: Dict[str, Any], op: str, body: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{cfg['addr'].rstrip('/')}/v1/{cfg.get('mount') or 'transit'}/{op}/{cfg['key_name']}"
    headers = {"X-Vault-Token": cfg.get("token", "")}
    if cfg.get("namespace"):
        headers["X-Vault-Namespace"] = cfg["namespace"]
    try:
        with _vault_client() as c:
            r = c.post(url, json=body, headers=headers)
    except Exception as exc:  # noqa: BLE001
        raise KeyUnavailable(f"Vault unreachable: {exc}") from exc
    if r.status_code >= 400:
        raise KeyUnavailable(f"Vault refused ({r.status_code}): {r.text[:200]}")
    return r.json().get("data") or {}


def _kms(cfg: Dict[str, Any]):
    try:
        import boto3  # noqa: F401
    except ImportError as exc:
        raise KeyUnavailable("AWS KMS needs boto3 on the server (pip install boto3)") from exc
    import boto3
    kwargs = {"region_name": cfg["region"]}
    if cfg.get("access_key_id") and cfg.get("secret_access_key"):
        kwargs.update(aws_access_key_id=cfg["access_key_id"], aws_secret_access_key=cfg["secret_access_key"])
    return boto3.client("kms", **kwargs)


def aws_available() -> bool:
    try:
        import boto3  # noqa: F401
        return True
    except ImportError:
        return False


def wrap(provider: str, public: Dict[str, Any], sealed: Optional[str], org_id: int, dek: bytes) -> str:
    cfg = _open_config(public, sealed)
    if provider == "local":
        return _master().encrypt(dek).decode()
    if provider == "vault_transit":
        data = _vault(cfg, "encrypt", {"plaintext": base64.b64encode(dek).decode()})
        if "ciphertext" not in data:
            raise KeyUnavailable("Vault returned no ciphertext")
        return data["ciphertext"]
    if provider == "aws_kms":
        try:
            out = _kms(cfg).encrypt(KeyId=cfg["key_id"], Plaintext=dek,
                                    EncryptionContext={"provenza_org": str(org_id)})
        except KeyUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            raise KeyUnavailable(f"AWS KMS refused: {exc}") from exc
        return base64.b64encode(out["CiphertextBlob"]).decode()
    raise KeyUnavailable(f"unknown key provider {provider!r}")


def unwrap(provider: str, public: Dict[str, Any], sealed: Optional[str], org_id: int, wrapped: Optional[str]) -> bytes:
    if not wrapped:
        raise KeyUnavailable("the organization key was shredded; its data can no longer be decrypted")
    cfg = _open_config(public, sealed)
    if provider == "local":
        try:
            return _master().decrypt(wrapped.encode())
        except Exception as exc:  # noqa: BLE001
            raise KeyUnavailable("the server master key cannot unwrap this organization key") from exc
    if provider == "vault_transit":
        data = _vault(cfg, "decrypt", {"ciphertext": wrapped})
        try:
            return base64.b64decode(data["plaintext"])
        except Exception as exc:  # noqa: BLE001
            raise KeyUnavailable("Vault returned no plaintext") from exc
    if provider == "aws_kms":
        try:
            out = _kms(cfg).decrypt(CiphertextBlob=base64.b64decode(wrapped),
                                    EncryptionContext={"provenza_org": str(org_id)})
        except KeyUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            raise KeyUnavailable(f"AWS KMS refused: {exc}") from exc
        return out["Plaintext"]
    raise KeyUnavailable(f"unknown key provider {provider!r}")


# ---------------------------------------------------------------------- lookups (sync fallback)
def _load_key_sync(key_id: int) -> Fernet:
    try:
        from sqlalchemy import select

        from app.core.sync_database import SyncSessionLocal
        from app.models.org_key import OrgKey

        db = SyncSessionLocal()
    except Exception as exc:  # noqa: BLE001
        raise KeyUnavailable(f"organization key store unavailable: {exc}") from exc
    try:
        row = db.execute(select(OrgKey).where(OrgKey.id == key_id)).scalar_one_or_none()
        if row is None:
            raise KeyUnavailable(f"organization key {key_id} not found")
        if row.status == "shredded":
            raise KeyUnavailable("the organization key was shredded; its data can no longer be decrypted")
        dek = unwrap(row.provider, row.config_public, row.config_secret_encrypted, row.org_id, row.wrapped_dek)
    except KeyUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001
        raise KeyUnavailable(f"organization key {key_id} could not be loaded: {exc}") from exc
    finally:
        db.close()
    remember(key_id, dek)
    return Fernet(dek)


def _active_key_sync(org_id: int) -> Optional[int]:
    from sqlalchemy import select

    from app.core.sync_database import SyncSessionLocal
    from app.models.org_key import OrgKey

    db = SyncSessionLocal()
    try:
        return db.execute(
            select(OrgKey.id).where(OrgKey.org_id == org_id, OrgKey.status == "active").limit(1)
        ).scalar_one_or_none()
    finally:
        db.close()


def fernet_for(key_id: int) -> Fernet:
    now = time.monotonic()
    with _lock:
        hit = _dek.get(key_id)
    if hit and hit[1] > now:
        return hit[0]
    return _load_key_sync(key_id)


def active_key_for(org_id: int) -> Optional[int]:
    now = time.monotonic()
    with _lock:
        hit = _active.get(org_id)
    if hit and hit[1] > now:
        return hit[0]
    try:
        key_id = _active_key_sync(org_id)
    except Exception:  # noqa: BLE001 - no BYOK table yet / DB hiccup: fall back to the server key
        key_id = None
    remember_active(org_id, key_id)
    return key_id


# ---------------------------------------------------------------------- format
def encrypt_for_key(key_id: int, plaintext: str) -> str:
    return f"{PREFIX}{key_id}:{fernet_for(key_id).encrypt(plaintext.encode()).decode()}"


def parse(ciphertext: str) -> Optional[Tuple[int, str]]:
    if not ciphertext.startswith(PREFIX):
        return None
    try:
        key_id, token = ciphertext[len(PREFIX):].split(":", 1)
        return int(key_id), token
    except ValueError as exc:
        raise ValueError("Malformed organization-key ciphertext") from exc


def decrypt_v2(ciphertext: str) -> str:
    key_id, token = parse(ciphertext)  # type: ignore[misc]
    try:
        return fernet_for(key_id).decrypt(token.encode()).decode()
    except KeyUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Could not decrypt with the organization key") from exc
