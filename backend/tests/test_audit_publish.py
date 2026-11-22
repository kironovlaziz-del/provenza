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


# ----------------------------------------------------------------------------- S3 with Object Lock

class FakeS3:
    """A bucket of an S3-compatible store (path style): checks the SigV4
    signature and Content-MD5 like S3, keeps each object with its lock, and
    answers HEAD with the lock - or, in mode "no_lock", without it (a bucket
    without Object Lock)."""

    ACCESS, SECRET, REGION, BUCKET = "PROVENZATESTKEY", "provenza-test-secret-0123456789", "eu-central-1", "audit-bucket"

    def __init__(self):
        self.objects, self.mode, self.versions = {}, "ok", 0     # ok | down | deny | no_lock
        outer = self

        class H(BaseHTTPRequestHandler):
            def _check(self, body: bytes) -> bool:
                from datetime import datetime as dt, timezone as tz
                from app.core import sigv4
                auth = self.headers["Authorization"]
                signed = auth.split("SignedHeaders=")[1].split(",")[0].split(";")
                when = dt.strptime(self.headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=tz.utc)
                want = sigv4.sign(self.command, self.path, {n: self.headers[n] for n in signed},
                                  hashlib.sha256(body).hexdigest(), access_key=outer.ACCESS, secret_key=outer.SECRET,
                                  region=outer.REGION, when=when)
                return auth == want and auth.startswith(f"AWS4-HMAC-SHA256 Credential={outer.ACCESS}/")

            def do_PUT(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if outer.mode == "down":
                    return self._send(503)
                if outer.mode == "deny" or not self._check(body):
                    return self._send(403, b"<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>")
                if base64.b64decode(self.headers["Content-MD5"]) != hashlib.md5(body).digest():
                    return self._send(400, b"<Error><Code>BadDigest</Code></Error>")
                outer.versions += 1
                outer.objects[self.path] = {"body": body, "version": f"v{outer.versions}",
                                            "mode": self.headers.get("x-amz-object-lock-mode"),
                                            "until": self.headers.get("x-amz-object-lock-retain-until-date")}
                self._send(200, headers={"ETag": f'"{hashlib.md5(body).hexdigest()}"',
                                         "x-amz-version-id": f"v{outer.versions}"})

            def do_HEAD(self):
                obj = outer.objects.get(self.path)
                if obj is None or not self._check(b""):
                    return self._send(404)
                h = {"x-amz-version-id": obj["version"]}
                if outer.mode != "no_lock":
                    h.update({"x-amz-object-lock-mode": obj["mode"],
                              "x-amz-object-lock-retain-until-date": obj["until"].replace("Z", ".000Z")})
                self._send(200, headers=h)

            def _send(self, code, body=b"", headers=None):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def s3(monkeypatch):
    monkeypatch.setattr(settings, "OUTBOUND_PRIVATE_ALLOWLIST", "127.0.0.1")
    server = FakeS3()
    yield server
    server.close()


async def _use_s3(client, token, s3, **over):
    body = {"enabled": True, "endpoint": s3.url, "region": s3.REGION, "bucket": s3.BUCKET, "prefix": "audit",
            "access_key": s3.ACCESS, "secret_key": s3.SECRET, "retention_days": 30, **over}
    return await client.put(f"{A}/publication/s3", json=body, headers=auth_headers(token))


@pytest.mark.asyncio
async def test_s3_is_tried_before_it_is_saved(client, admin_token, approver_token, s3, db_session):
    assert (await _use_s3(client, approver_token, s3)).status_code == 403
    r = await _use_s3(client, admin_token, s3, secret_key="wrong-secret-0000")
    assert r.status_code == 422 and _code(r) == "publish.http_error" and "AccessDenied" in r.json()["detail"]["context"]["detail"]
    s3.mode = "no_lock"
    r = await _use_s3(client, admin_token, s3)
    assert r.status_code == 422 and _code(r) == "publish.s3_not_locked"
    row = (await db_session.execute(select(AuditPublicationSettings))).scalars().first()
    assert row is None or not row.s3_enabled                          # nothing stored
    for over in ({"bucket": "Bad_Bucket"}, {"region": "EU"}, {"prefix": "../x"}, {"retention_days": 0},
                 {"endpoint": "http://s3.example.com"}):          # plain HTTP only inside the operator's network
        assert (await _use_s3(client, admin_token, s3, **over)).status_code == 422, over

    s3.mode = "ok"
    r = await _use_s3(client, admin_token, s3)
    assert r.status_code == 200, r.text
    [test_obj] = s3.objects                                            # the test object, locked for a day
    assert test_obj.startswith("/audit-bucket/audit/org-") and "provenza-test-" in test_obj
    t = next(x for x in r.json()["targets"] if x["target"] == "s3")
    assert t["enabled"] and t["configured"] and t["host"] == s3.url.removeprefix("http://")
    assert t["settings"]["retention_days"] == 30 and t["settings"]["lock_mode"] == "COMPLIANCE"
    assert "secret" not in json.dumps(t["settings"]).lower()
    row = (await db_session.execute(select(AuditPublicationSettings))).scalars().one()
    assert s3.SECRET not in row.s3_secret_enc                          # stored encrypted
    # switched off without giving the secret again: it is kept
    r = await _use_s3(client, admin_token, s3, enabled=False, secret_key=None)
    assert r.status_code == 200 and not next(x for x in r.json()["targets"] if x["target"] == "s3")["enabled"]


@pytest.mark.asyncio
async def test_publish_to_s3_locked(client, admin_token, rekor, s3, db_session):
    assert (await _use(client, admin_token, rekor)).status_code == 200
    assert (await _use_s3(client, admin_token, s3)).status_code == 200
    cp = (await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
    r = await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))
    assert r.json()["result"] == {"rekor": "published", "s3": "published"}, r.text
    key = f"/audit-bucket/audit/org-{cp['org_id']}/checkpoint-{cp['tree_size']:012d}.json"
    obj = s3.objects[key]
    assert json.loads(obj["body"]) == cp                               # the signed checkpoint itself
    assert obj["mode"] == "COMPLIANCE"
    from datetime import datetime, timezone
    days = (datetime.fromisoformat(obj["until"].replace("Z", "+00:00")) - datetime.now(timezone.utc)).days
    assert days in (29, 30)
    [pub] = (await client.get(f"{A}/publications", params={"target": "s3"}, headers=auth_headers(admin_token))).json()["items"]
    assert pub["location"] == f"s3:/{key}" and pub["reference"] == obj["version"]
    assert pub["receipt"]["lock_mode"] == "COMPLIANCE" and pub["receipt"]["sha256"] == hashlib.sha256(obj["body"]).hexdigest()


@pytest.mark.asyncio
async def test_an_s3_failure_is_noted_and_retried(client, admin_token, s3, db_session):
    r = await client.put(f"{A}/publication", json={"interval_minutes": 60, "rekor_enabled": False},
                         headers=auth_headers(admin_token))
    assert r.status_code == 200
    assert (await _use_s3(client, admin_token, s3)).status_code == 200
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    s3.mode = "no_lock"
    r = await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))
    assert r.json()["result"] == {"s3": "failed"}
    assert next(x for x in r.json()["targets"] if x["target"] == "s3")["last_error"].startswith("publish.s3_not_locked")
    s3.mode = "ok"
    assert (await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))).json()["result"] == {"s3": "published"}



# ----------------------------------------------------------------------------- offline verification

ROOT = Path(__file__).resolve().parents[2]


def _tool():
    import importlib.util

    spec = importlib.util.spec_from_file_location("provenza_audit_tool_publish", ROOT / "tools" / "provenza_audit.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_offline_verifier_pins_the_same_sigstore_key():
    tool = _tool()
    assert tool.SIGSTORE_REKOR_KEY == audit_publish.SIGSTORE_REKOR_PUBLIC_KEY
    assert tool.SIGSTORE_REKOR_LOG_ID == audit_publish.SIGSTORE_REKOR_LOG_ID
    assert list(tool.rekor_logs()) == [audit_publish.SIGSTORE_REKOR_LOG_ID]


def test_the_offline_verifier_checks_a_real_rekor_entry():
    tool = _tool()
    logs = tool.rekor_logs()
    assert tool.check_rekor_set(VECTOR["entry"], logs) == "Sigstore Rekor"
    for change in ({"logIndex": VECTOR["entry"]["logIndex"] + 1}, {"integratedTime": VECTOR["entry"]["integratedTime"] + 1},
                   {"body": base64.b64encode(b"{}").decode()}):
        with pytest.raises(tool.Fail, match="signed entry timestamp does not verify"):
            tool.check_rekor_set({**VECTOR["entry"], **change}, logs)
    assert tool.check_rekor_set({**VECTOR["entry"], "logID": "ab" * 32}, logs) is None   # a log it has no key for


@pytest.mark.asyncio
async def test_the_offline_verifier_checks_the_publications(client, admin_token, rekor, tmp_path, capsys):
    assert (await _use(client, admin_token, rekor)).status_code == 200
    first = (await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
    r = await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))
    assert r.json()["result"] == {"rekor": "published"}
    fp = r.json()["publishing_key"]["fingerprint"]
    cp = next(c for c in (await client.get(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
              if c["tree_size"] == first["tree_size"])
    (tmp_path / "cp.json").write_text(json.dumps(cp))
    (tmp_path / "log.pem").write_text(rekor.pem)
    tool, path = _tool(), str(tmp_path / "cp.json")
    with_key = ["--rekor-key", str(tmp_path / "log.pem")]

    # not the Sigstore log, and no key given for it: named, not checked - and not enough when one is required
    assert tool.main(["checkpoint", path]) == 0
    assert "not checked  a Rekor entry" in capsys.readouterr().out
    assert tool.main(["checkpoint", path, "--require-rekor"]) == 1
    assert "no Rekor entry that verifies" in capsys.readouterr().out

    assert tool.main(["checkpoint", path, "--require-rekor", "--publishing-key", fp, *with_key]) == 0
    out = capsys.readouterr().out
    assert f"published in Rekor log {rekor.log_id[:16]}" in out and fp in out
    assert f"the log had these {cp['tree_size']} records then" in out
    assert tool.main(["checkpoint", path, "--publishing-key", "SHA256:" + "A" * 43, *with_key]) == 1
    assert "expected SHA256:AAAA" in capsys.readouterr().out

    def broken(change, name):
        doc = json.loads(json.dumps(cp))
        change(doc["publications"][0]["receipt"]["entry"], doc)
        (tmp_path / name).write_text(json.dumps(doc))
        return tool.main(["checkpoint", str(tmp_path / name), *with_key])

    # Rekor's signature covers the index and the time
    assert broken(lambda e, d: e.update(integratedTime=e["integratedTime"] + 3600), "later.json") == 1
    assert "signed entry timestamp does not verify" in capsys.readouterr().out
    # an entry for another statement, moved onto this checkpoint
    def other(e, d):
        body = json.loads(base64.b64decode(e["body"]))
        body["spec"]["data"]["hash"]["value"] = hashlib.sha256(b"another").hexdigest()
        e["body"] = base64.b64encode(json.dumps(body).encode()).decode()
    assert broken(other, "other.json") == 1
    assert "for another statement" in capsys.readouterr().out
    # a signature the publishing key did not make
    def resigned(e, d):
        body = json.loads(base64.b64decode(e["body"]))
        body["spec"]["signature"]["content"] = base64.b64encode(
            ec.generate_private_key(ec.SECP256R1()).sign(cp["statement"].encode(), ec.ECDSA(hashes.SHA256()))).decode()
        e["body"] = base64.b64encode(json.dumps(body).encode()).decode()
    assert broken(resigned, "resigned.json") == 1
    assert "publishing key's signature over the statement does not verify" in capsys.readouterr().out
    # and a checkpoint that is not the published one
    assert broken(lambda e, d: d.update(publications=[]), "bare.json") == 0
    capsys.readouterr()
    assert tool.main(["checkpoint", str(tmp_path / "bare.json"), "--require-rekor", *with_key]) == 1

    # later: the log grew; the older end was published, the newer one not yet
    assert (await _use(client, admin_token, rekor)).status_code == 200
    await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))
    doc = (await client.get(f"{A}/consistency", params={"from_size": cp["tree_size"]},
                            headers=auth_headers(admin_token))).json()
    assert doc["old"]["publications"] and not doc["new"]["publications"]
    (tmp_path / "cons.json").write_text(json.dumps(doc))
    assert tool.main(["consistency", str(tmp_path / "cons.json"), "--pinned", path, "--require-rekor",
                      "--publishing-key", fp, *with_key]) == 0
    out = capsys.readouterr().out
    assert "extends" in out and "published in Rekor log" in out
    # the auditor's own copy carries the receipt even when the server's answer leaves it out
    doc["old"]["publications"] = []
    (tmp_path / "cons2.json").write_text(json.dumps(doc))
    assert tool.main(["consistency", str(tmp_path / "cons2.json"), "--pinned", path, "--require-rekor", *with_key]) == 0
    capsys.readouterr()
    assert tool.main(["consistency", str(tmp_path / "cons2.json"), "--pinned", str(tmp_path / "bare.json"),
                      "--require-rekor", *with_key]) == 1


@pytest.mark.asyncio
async def test_the_offline_verifier_names_the_s3_copy(client, admin_token, rekor, s3, tmp_path, capsys):
    assert (await _use(client, admin_token, rekor)).status_code == 200
    assert (await _use_s3(client, admin_token, s3)).status_code == 200
    first = (await client.post(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
    assert (await client.post(f"{A}/publication/run", headers=auth_headers(admin_token))).json()["result"] == \
        {"rekor": "published", "s3": "published"}
    cp = next(c for c in (await client.get(f"{A}/checkpoints", headers=auth_headers(admin_token))).json()
              if c["tree_size"] == first["tree_size"])
    (tmp_path / "cp.json").write_text(json.dumps(cp))
    (tmp_path / "log.pem").write_text(rekor.pem)
    tool = _tool()
    assert tool.main(["checkpoint", str(tmp_path / "cp.json"), "--require-rekor",
                      "--rekor-key", str(tmp_path / "log.pem")]) == 0
    assert "(S3, Object Lock): not checked here" in capsys.readouterr().out
    # the object in the bucket is the checkpoint, verified as is
    key = f"/audit-bucket/audit/org-{cp['org_id']}/checkpoint-{cp['tree_size']:012d}.json"
    (tmp_path / "s3.json").write_bytes(s3.objects[key]["body"])
    assert tool.main(["checkpoint", str(tmp_path / "s3.json")]) == 0
