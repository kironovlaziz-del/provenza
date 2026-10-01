"""
BYOK: per-organization data keys wrapped by a KEK (local / Vault Transit),
re-encryption on enable / rotate / disable, crypto-shredding, health check,
validation and roles. Vault is a mock transport - nothing leaves the process.
"""

import base64
import secrets

import httpx
import pytest

from app.core import keyring
from app.core.crypto import decrypt_secret, encrypt_secret
from app.models.agent import Agent
from app.models.ai_provider import AIProvider
from app.models.ai_request import AIRequest
from tests.conftest import auth_headers

B = "/api/v1/byok"


async def _org(client, token, db):
    r = await client.post("/api/v1/agents/register",
                          json={"name": "bk-" + secrets.token_hex(3), "agent_type": "custom", "capabilities": [],
                                "allowed_tools": [], "allowed_models": [], "max_delegation_depth": 1},
                          headers=auth_headers(token))
    assert r.status_code == 200, r.text
    return (await db.get(Agent, r.json()["id"])).org_id


async def _secrets(db, org_id):
    """A connection key and a raw prompt, both under the legacy server key."""
    p = AIProvider(org_id=org_id, name="p-" + secrets.token_hex(3), type="openai", status="active",
                   api_key_encrypted=encrypt_secret("sk-live-123"))
    r = AIRequest(org_id=org_id, status="completed", masked_input_text="x",
                  input_text_encrypted=encrypt_secret("my raw prompt"))
    db.add_all([p, r])
    await db.commit()
    await db.refresh(p)
    await db.refresh(r)
    return p.id, r.id


async def _values(db, pid, rid):
    db.expire_all()
    return (await db.get(AIProvider, pid)).api_key_encrypted, (await db.get(AIRequest, rid)).input_text_encrypted


class FakeVault:
    def __init__(self, token="s.good"):
        self.token, self.calls = token, []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        if request.headers.get("X-Vault-Token") != self.token:
            return httpx.Response(403, json={"errors": ["permission denied"]})
        body = __import__("json").loads(request.content)
        if request.url.path.endswith("/encrypt/provenza"):
            return httpx.Response(200, json={"data": {"ciphertext": "vault:v1:" + body["plaintext"][::-1]}})
        if request.url.path.endswith("/decrypt/provenza"):
            return httpx.Response(200, json={"data": {"plaintext": body["ciphertext"][len("vault:v1:"):][::-1]}})
        return httpx.Response(404)


@pytest.fixture
def vault(monkeypatch):
    v = FakeVault()
    monkeypatch.setattr(keyring, "_vault_client", lambda: httpx.Client(transport=httpx.MockTransport(v.handler)))
    return v


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_enable_rotate_disable_local(self, client, admin_token, db_session):
        org = await _org(client, admin_token, db_session)
        pid, rid = await _secrets(db_session, org)

        r = await client.post(B + "/keys", json={"provider": "local"}, headers=auth_headers(admin_token))
        assert r.status_code == 200 and r.json()["status"] == "done" and r.json()["done"] == 2, r.text
        k1 = r.json()["key_id"]
        pkey, praw = await _values(db_session, pid, rid)
        assert pkey.startswith(f"pvz2:{k1}:") and praw.startswith(f"pvz2:{k1}:")
        assert decrypt_secret(pkey) == "sk-live-123" and decrypt_secret(praw) == "my raw prompt"
        assert encrypt_secret("new", org_id=org).startswith(f"pvz2:{k1}:")      # new data goes to the org key
        assert not encrypt_secret("new").startswith("pvz2:")                       # no org -> server key

        r = await client.post(B + "/keys", json={"provider": "local"}, headers=auth_headers(admin_token))
        k2 = r.json()["key_id"]
        assert k2 != k1 and r.json()["done"] == 2
        pkey, _ = await _values(db_session, pid, rid)
        assert pkey.startswith(f"pvz2:{k2}:") and decrypt_secret(pkey) == "sk-live-123"
        ov = (await client.get(B + "/", headers=auth_headers(admin_token))).json()
        assert [k["status"] for k in ov["keys"]] == ["active", "retired"]
        prov = next(d for d in ov["data"] if d["table"] == "ai_providers")
        assert prov["active_key"] == 1 and prov["server_key"] == 0

        r = await client.post(B + "/disable", headers=auth_headers(admin_token))
        assert r.status_code == 200 and r.json()["done"] == 2
        pkey, praw = await _values(db_session, pid, rid)
        assert not pkey.startswith("pvz2:") and decrypt_secret(praw) == "my raw prompt"
        assert not encrypt_secret("new", org_id=org).startswith("pvz2:")
        assert (await client.post(B + "/disable", headers=auth_headers(admin_token))).status_code == 409

    @pytest.mark.asyncio
    async def test_shred_makes_data_unreadable(self, client, admin_token, db_session):
        org = await _org(client, admin_token, db_session)
        pid, rid = await _secrets(db_session, org)
        await client.post(B + "/keys", json={"provider": "local"}, headers=auth_headers(admin_token))
        assert (await client.post(B + "/shred", json={"confirm": "yes"}, headers=auth_headers(admin_token))).status_code == 422
        r = await client.post(B + "/shred", json={"confirm": "SHRED"}, headers=auth_headers(admin_token))
        assert r.status_code == 200 and r.json()["shredded_keys"] == 1
        pkey, praw = await _values(db_session, pid, rid)
        for value in (pkey, praw):
            with pytest.raises(ValueError):
                decrypt_secret(value)
        ov = (await client.get(B + "/", headers=auth_headers(admin_token))).json()
        assert ov["enabled"] is False and ov["keys"][0]["status"] == "shredded"
        assert not encrypt_secret("after", org_id=org).startswith("pvz2:")


class TestVault:
    @pytest.mark.asyncio
    async def test_vault_transit_wraps_and_checks(self, client, admin_token, db_session, vault):
        org = await _org(client, admin_token, db_session)
        pid, rid = await _secrets(db_session, org)
        cfg = {"provider": "vault_transit", "addr": "https://vault.example:8200", "key_name": "provenza", "token": "s.good"}
        r = await client.post(B + "/keys", json=cfg, headers=auth_headers(admin_token))
        assert r.status_code == 200, r.text
        assert any(p.endswith("/transit/encrypt/provenza") for p in vault.calls)
        ov = (await client.get(B + "/", headers=auth_headers(admin_token))).json()
        key = ov["keys"][0]
        assert key["provider"] == "vault_transit" and key["has_secret"] and "token" not in key["config"]

        # the DEK cache is dropped: the next decrypt must unwrap through Vault
        keyring.forget(key_id=key["id"])
        assert (await client.post(B + "/check", headers=auth_headers(admin_token))).json()["ok"] is True
        pkey, _ = await _values(db_session, pid, rid)
        assert decrypt_secret(pkey) == "sk-live-123"

        # the customer revokes the token in Vault -> the check fails, the cache is dropped
        vault.token = "s.other"
        chk = (await client.post(B + "/check", headers=auth_headers(admin_token))).json()
        assert chk["ok"] is False and "Vault refused" in chk["error"]

    @pytest.mark.asyncio
    async def test_bad_vault_credentials_are_refused_up_front(self, client, admin_token, db_session, vault):
        await _org(client, admin_token, db_session)
        cfg = {"provider": "vault_transit", "addr": "https://vault.example:8200", "key_name": "provenza", "token": "s.bad"}
        r = await client.post(B + "/keys", json=cfg, headers=auth_headers(admin_token))
        assert r.status_code == 400 and "Vault refused" in r.text
        assert (await client.get(B + "/", headers=auth_headers(admin_token))).json()["enabled"] is False


class TestValidation:
    @pytest.mark.asyncio
    async def test_validation_and_roles(self, client, admin_token, approver_token):
        for bad in ({"provider": "vault_transit", "addr": "https://v"}, {"provider": "aws_kms", "region": "eu-west-1"},
                    {"provider": "aws_kms", "region": "eu-west-1", "key_id": "k", "access_key_id": "AKIA"},
                    {"provider": "gcp"}):
            assert (await client.post(B + "/keys", json=bad, headers=auth_headers(admin_token))).status_code == 422
        assert (await client.post(B + "/keys", json={"provider": "local"}, headers=auth_headers(approver_token))).status_code == 403
        assert (await client.post(B + "/shred", json={"confirm": "SHRED"}, headers=auth_headers(approver_token))).status_code == 403
        assert (await client.get(B + "/", headers=auth_headers(approver_token))).status_code == 200

    @pytest.mark.asyncio
    async def test_aws_without_boto3(self, client, admin_token, monkeypatch):
        monkeypatch.setattr(keyring, "aws_available", lambda: False)
        r = await client.post(B + "/keys", json={"provider": "aws_kms", "region": "eu-west-1", "key_id": "alias/x"},
                              headers=auth_headers(admin_token))
        assert r.status_code == 400 and "boto3" in r.text
