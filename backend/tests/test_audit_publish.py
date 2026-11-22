# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Publishing checkpoints outside the server (app/services/audit_publish.py):
Rekor on by default, its answers verified before anything is kept, the
interval respected, a failing target noted and retried, the publications
append-only - and the signed entry timestamp checked on a real entry of the
public Rekor.
"""

import base64
import hashlib
import json
import threading
import time
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.core.config import settings
from app.models.audit_log import AuditCheckpointPublication, AuditPublicationSettings
from app.services import audit_publish
from tests.conftest import auth_headers

A = "/api/v1/audit-logs"
VECTOR = json.loads((Path(__file__).parent / "data" / "rekor_vector.json").read_text())


class FakeRekor:
    """A Rekor v1 log: checks the hashedrekord signature like Rekor does,
    answers with an entry and a signed entry timestamp from its own key."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pem = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        der = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        self.log_id = hashlib.sha256(der).hexdigest()
        self.entries, self.mode = [], "ok"       # ok | down | tamper | bad_set | other_log
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path != "/api/v1/log/entries" or outer.mode == "down":
                    return self._send(503, {"message": "down"})
                spec = body["spec"]
                key = serialization.load_pem_public_key(base64.b64decode(spec["signature"]["publicKey"]["content"]))
                key.verify(base64.b64decode(spec["signature"]["content"]),
                           bytes.fromhex(spec["data"]["hash"]["value"]), ec.ECDSA(Prehashed(hashes.SHA256())))
                outer.entries.append(body)
                if outer.mode == "tamper":
                    body["spec"]["data"]["hash"]["value"] = "0" * 64
                entry = {"body": base64.b64encode(json.dumps(body).encode()).decode(),
                         "integratedTime": int(time.time()),
                         "logID": "ab" * 32 if outer.mode == "other_log" else outer.log_id,
                         "logIndex": len(outer.entries) - 1}
                signed = audit_publish.set_payload(entry)
                if outer.mode == "bad_set":
                    signed += b" "
                entry["verification"] = {"signedEntryTimestamp": base64.b64encode(
                    outer.key.sign(signed, ec.ECDSA(hashes.SHA256()))).decode()}
                self._send(201, {hashlib.sha256(json.dumps(body).encode()).hexdigest(): entry})

            def _send(self, code, doc):
                out = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def rekor(monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "127.0.0.1")
    server = FakeRekor()
    yield server
    server.close()


def _code(r) -> str:
    detail = r.json()["detail"]
    return detail if isinstance(detail, str) else detail["code"]


async def _use(client, token, rekor, **over):
    body = {"interval_minutes": 60, "rekor_enabled": True, "rekor_url": rekor.url, "rekor_public_key": rekor.pem, **over}
    return await client.put(f"{A}/publication", json=body, headers=auth_headers(token))


# ----------------------------------------------------------------------------- the real thing

def test_a_real_rekor_entry_verifies_with_the_key_sigstore_distributes():
    entry = VECTOR["entry"]
    sent = json.loads(base64.b64decode(entry["body"]))
    uuid, checked = audit_publish.verify_rekor_answer({"x": entry}, sent, audit_publish.SIGSTORE_REKOR_PUBLIC_KEY)
    assert checked["logID"] == audit_publish.SIGSTORE_REKOR_LOG_ID
    pinned = serialization.load_pem_public_key(audit_publish.SIGSTORE_REKOR_PUBLIC_KEY.encode())
    der = pinned.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert hashlib.sha256(der).hexdigest() == audit_publish.SIGSTORE_REKOR_LOG_ID
    tampered = {**entry, "logIndex": entry["logIndex"] + 1}
    with pytest.raises(audit_publish.PublishError) as err:
        audit_publish.verify_rekor_answer({"x": tampered}, sent, audit_publish.SIGSTORE_REKOR_PUBLIC_KEY)
    assert err.value.code == "publish.rekor_bad_signature"


# ----------------------------------------------------------------------------- defaults and settings

@pytest.mark.asyncio
async def test_rekor_is_on_by_default(client, admin_token, approver_token):
    st = (await client.get(f"{A}/publication", headers=auth_headers(approver_token))).json()
    assert st["interval_minutes"] == 60 and (st["min_interval"], st["max_interval"]) == (5, 1440)
    by = {t["target"]: t for t in st["targets"]}
    assert by["rekor"]["enabled"] and by["rekor"]["public_instance"]
    assert by["rekor"]["host"] == "rekor.sigstore.dev"          # shown as the outbound destination it is
    assert set(by) == {"rekor", "s3"}
    assert not by["s3"]["enabled"] and not by["s3"]["configured"]
    assert st["publishing_key"] is None                           # made with the first publication


@pytest.mark.asyncio
async def test_settings_are_checked(client, admin_token, approver_token, rekor):
    assert (await _use(client, approver_token, rekor)).status_code == 403
    for interval in (4, 1441):
        r = await _use(client, admin_token, rekor, interval_minutes=interval)
        assert r.status_code == 422
    r = await _use(client, admin_token, rekor, rekor_public_key=None)        # another instance: its key is needed
    assert r.status_code == 422 and _code(r) == "publish.rekor_no_key"
    ed = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n"
    r = await _use(client, admin_token, rekor, rekor_public_key=ed)
    assert r.status_code == 422 and _code(r) == "publish.bad_public_key"
    r = await _use(client, admin_token, rekor, interval_minutes=5)
    assert r.status_code == 200, r.text
    assert r.json()["interval_minutes"] == 5
    # the change is in the audit log
    logs = (await client.get(f"{A}/", params={"entity_type": "audit_publication"},
                             headers=auth_headers(admin_token))).json()["items"]
    assert logs and logs[0]["action"] == "configured"
    # back to the public instance: no key to give
    r = await client.put(f"{A}/publication", json={"interval_minutes": 60, "rekor_enabled": False},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200
    rek = next(t for t in r.json()["targets"] if t["target"] == "rekor")
    assert not rek["enabled"] and rek["destination"] == audit_publish.DEFAULT_REKOR_URL


# ----------------------------------------------------------------------------- publishing

@pytest.mark.asyncio
async def test_publish_to_rekor(client, admin_token, rekor, db_session):
    assert (await _use(client, admin_token, rekor)).status_code == 200
    cp = (await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
    r = await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))
    assert r.status_code == 200, r.text
    assert r.json()["result"] == {"rekor": "published"}
    key = r.json()["publishing_key"]
    assert key["fingerprint"].startswith("SHA256:")

    # what reached Rekor: the hash of the statement, signed by the publishing key - never the log
    [sent] = rekor.entries
    assert sent["spec"]["data"]["hash"]["value"] == hashlib.sha256(cp["statement"].encode()).hexdigest()
    pub = serialization.load_pem_public_key(base64.b64decode(sent["spec"]["signature"]["publicKey"]["content"]))
    pub.verify(base64.b64decode(sent["spec"]["signature"]["content"]), cp["statement"].encode(),
               ec.ECDSA(hashes.SHA256()))
    assert audit_publish.fingerprint(base64.b64decode(sent["spec"]["signature"]["publicKey"]["content"]).decode()) \
        == key["fingerprint"]
    assert cp["root_hash"] not in json.dumps(sent)

    # nothing new: not published twice
    r = await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))
    assert r.json()["result"] == {"rekor": "nothing_new"} and len(rekor.entries) == 1

    listed = (await client.get(f"{A}/publications", headers=auth_headers(admin_token))).json()
    assert listed["total"] == 1
    item = listed["items"][0]
    assert item["target"] == "rekor" and item["tree_size"] == cp["tree_size"] and item["log_index"] == 0
    assert item["receipt"]["entry"]["verification"]["signedEntryTimestamp"]
    # and the checkpoint carries it, for whoever exports it
    cps = (await client.get(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
    assert next(c for c in cps if c["tree_size"] == cp["tree_size"])["publications"][0]["reference"] == item["reference"]

    # append-only
    with pytest.raises(DBAPIError):
        async with db_session.begin_nested():
            await db_session.execute(text("UPDATE audit_checkpoint_publications SET reference = 'x'"))


@pytest.mark.asyncio
async def test_the_interval_is_respected(client, admin_token, rekor, db_session):
    org_id = (await client.get("/api/v1/users/me", headers=auth_headers(admin_token))).json()["org_id"]
    assert (await _use(client, admin_token, rekor)).status_code == 200
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    assert await audit_publish.publish_org(db_session, org_id) == {"rekor": "published"}
    assert (await _use(client, admin_token, rekor)).status_code == 200            # a record: the log grew
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    assert await audit_publish.publish_org(db_session, org_id) == {"rekor": "not_due"}
    # the interval is over
    await db_session.execute(text("ALTER TABLE audit_checkpoint_publications DISABLE TRIGGER USER"))
    await db_session.execute(text("UPDATE audit_checkpoint_publications SET created_at = created_at - interval '61 minutes'"))
    await db_session.execute(text("ALTER TABLE audit_checkpoint_publications ENABLE TRIGGER USER"))
    await db_session.commit()
    assert await audit_publish.publish_org(db_session, org_id) == {"rekor": "published"}
    assert len(rekor.entries) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,code", [("down", "publish.http_error"), ("tamper", "publish.rekor_bad_answer"),
                                       ("bad_set", "publish.rekor_bad_signature"),
                                       ("other_log", "publish.rekor_wrong_log")])
async def test_an_answer_that_does_not_check_keeps_nothing(client, admin_token, rekor, db_session, mode, code):
    assert (await _use(client, admin_token, rekor)).status_code == 200
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    rekor.mode = mode
    r = await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))
    assert r.json()["result"] == {"rekor": "failed"}
    rek = next(t for t in r.json()["targets"] if t["target"] == "rekor")
    assert rek["last_error"].startswith(code) and rek["last_error_at"]
    assert (await db_session.execute(select(AuditCheckpointPublication))).scalars().all() == []
    rekor.mode = "ok"
    r = await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))
    assert r.json()["result"] == {"rekor": "published"}
    assert next(t for t in r.json()["targets"] if t["target"] == "rekor")["last_error"] is None


@pytest.mark.asyncio
async def test_switched_off_publishes_nothing(client, admin_token, rekor):
    assert (await _use(client, admin_token, rekor, rekor_enabled=False)).status_code == 200
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    r = await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))
    assert r.json()["result"] == {} and rekor.entries == []


@pytest.mark.asyncio
async def test_the_publishing_key_stays(client, admin_token, rekor, db_session):
    assert (await _use(client, admin_token, rekor)).status_code == 200
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    first = (await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))).json()["publishing_key"]
    # saving the settings again never replaces it
    assert (await _use(client, admin_token, rekor, interval_minutes=30)).status_code == 200
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    again = (await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))).json()
    assert again["result"] == {"rekor": "published"} and again["publishing_key"] == first
    keys = {e["spec"]["signature"]["publicKey"]["content"] for e in rekor.entries}
    assert len(keys) == 1
    row = (await db_session.execute(select(AuditPublicationSettings))).scalars().one()
    assert "PRIVATE KEY" not in row.publish_private_key_enc          # stored encrypted
