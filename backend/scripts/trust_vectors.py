# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Generate sdk/testdata/trust-vectors.json: what an enforcement point checks
without the server (docs/pvp/edge.md, sections 3-4) - a chain of signed policy
releases, a human approval and an agent's signed request - made the way the
server and a browser make them, with software passkeys. Keys are random, so
the file is generated once and committed; backend/tests/test_trust_vectors.py
checks it with the server's own code and tools/provenza_audit.py, and
proxy/internal/trust checks it in Go. From backend/:

    python scripts/trust_vectors.py

With "sensor-commands" it makes sdk/testdata/sensor-command-vectors.json
instead: commands to a sensor that an administrator signed, checked by
sensor/internal/trust (docs/pvp/edge.md, section 5); with "lift",
sdk/testdata/lift-vectors.json: the passkeys that lift a proxy's local kill
switch (section 7); with "enforce", sdk/testdata/enforce-vectors.json: a
release in enforce mode and the agent's key, for the proxy's agent mode
(section 4).
"""

import base64
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.core import webauthn  # noqa: E402
from app.core.agent_signing import canonical_bytes, content_hash, key_fingerprint  # noqa: E402
from app.pvp import policy_bundle as pb  # noqa: E402
from app.pvp import sealed  # noqa: E402
from tests.webauthn_helpers import SoftAuthenticator, b64url  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "sdk" / "testdata" / "trust-vectors.json"
SENSOR_OUT = OUT.with_name("sensor-command-vectors.json")
LIFT_OUT = OUT.with_name("lift-vectors.json")
ENFORCE_OUT = OUT.with_name("enforce-vectors.json")
ORG = 1
NOW = 1_800_000_000


def _raw(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                          serialization.PublicFormat.Raw)).decode()


def _sign(key: Ed25519PrivateKey, doc) -> str:
    return base64.b64encode(key.sign(canonical_bytes(doc))).decode()


def _passkey(dev: SoftAuthenticator):
    reg = webauthn.verify_registration(**dev.create(b64url(b"c" * 32)), challenge=b"c" * 32)
    return {"alg": reg.alg, "public_key": webauthn.spki(reg.public_key),
            "fingerprint": webauthn.passkey_fingerprint(reg.public_key)}, reg.credential_id


def build():
    admin_a, admin_b, approver = SoftAuthenticator(-7), SoftAuthenticator(-8), SoftAuthenticator(-7)
    pk_a, cred_a = _passkey(admin_a)
    pk_b, cred_b = _passkey(admin_b)
    pk_c, cred_c = _passkey(approver)
    agent_key = Ed25519PrivateKey.generate()
    agent_fp = key_fingerprint(_raw(agent_key))
    signers = {"1": {"email": "a@example.com", "role": "admin", "passkeys": {cred_a: pk_a}}}

    releases, prev = [], None

    def release(number, manifest_c, bundle_extra, sign_with):
        nonlocal prev
        bundle = {"type": pb.BUNDLE_TYPE, "v": 1, "org_id": ORG,
                  "version": prev["bundle"]["version"] + 1 if prev else 1,
                  "previous": prev["release"]["bundle"]["sha256"] if prev else None,
                  "not_after": NOW + 86400, "offline_seconds": 900,
                  "agents": {"5": {"name": "payer", "status": "active", "team_id": None, "capabilities": ["read"],
                                   "allowed_tools": ["proxy.stripe"], "allowed_models": [],
                                   "max_delegation_depth": 1}},
                  **bundle_extra}
        manifest = {"type": pb.MANIFEST_TYPE, "v": 1, "org_id": ORG, **manifest_c}
        if prev and {k: prev["manifest"].get(k) for k in manifest_c} == manifest_c:
            manifest = prev["manifest"]
        else:
            manifest.update(version=prev["manifest"]["version"] + 1 if prev else 1,
                            previous=prev["release"]["manifest"]["sha256"] if prev else None)
        rel = {"number": number, "bundle": {"version": bundle["version"], "sha256": pb.sha256(bundle)},
               "manifest": {"version": manifest["version"], "sha256": pb.sha256(manifest)}}
        sigs = []
        for uid, dev, cred in sign_with:
            st = {"type": "provenza.policy.release", "v": 1, "org_id": ORG, "user_id": uid, "release": number,
                  "bundle": rel["bundle"], "manifest": rel["manifest"], "not_after": bundle["not_after"],
                  "issued_at": NOW - 100}
            a = dev.get(b64url(webauthn.statement_challenge(st)))
            sigs.append({"user_id": uid, "credential_id": cred, "statement": st,
                         "assertion": {k: a[k] for k in ("client_data_json", "authenticator_data", "signature")}})
        doc = {"release": rel, "bundle": bundle, "manifest": manifest, "signatures": sigs,
               "governed_by": None if prev is None else {
                   "number": prev["release"]["number"], "bundle_sha256": prev["release"]["bundle"]["sha256"],
                   "bundle_version": prev["bundle"]["version"], "manifest": prev["manifest"],
                   "manifest_sha256": prev["release"]["manifest"]["sha256"]}}
        releases.append(doc)
        prev = doc
        return doc

    base = {"quorum": 1, "signers": signers, "agents": {"5": agent_fp}, "egress_proxies": {}, "egress_sensors": {},
            "sensor_command_key": None}
    release(1, base, {}, [(1, admin_a, cred_a)])
    # the second administrator and quorum 2 come in - signed by the quorum of release 1 (one)
    two = dict(base, quorum=2, signers={**signers, "2": {"email": "b@example.com", "role": "admin",
                                                         "passkeys": {cred_b: pk_b}},
                                        "3": {"email": "c@example.com", "role": "approver",
                                              "passkeys": {cred_c: pk_c}}})
    release(2, two, {}, [(1, admin_a, cred_a)])
    # from here on both must sign
    release(3, two, {"egress_routes": {"9": {"slug": "stripe", "upstream_url": "https://api.stripe.com",
                                             "methods": ["POST"], "path_prefixes": ["/v1/charges"],
                                             "credential_source": "none", "auth_header": "Authorization",
                                             "max_body_bytes": 1024, "enabled": True}}},
            [(1, admin_a, cred_a), (2, admin_b, cred_b)])

    # the approver's session, its certificate and an approval of one call
    session_key = Ed25519PrivateKey.generate()
    cert = {"type": "provenza.session.certificate", "v": 1, "org_id": ORG, "user_id": 3, "session_id": "s" * 32,
            "public_key": _raw(session_key), "not_before": NOW - 3600, "not_after": NOW + 3600,
            "issued_at": NOW - 3600}
    ca = approver.get(b64url(webauthn.statement_challenge(cert)))
    descriptor = {"route": "stripe", "method": "POST", "path": "/v1/charges", "query_sha256": None,
                  "body_sha256": None, "body_bytes": 0}
    call = {"agent_id": 5, "chain_id": None, "action_type": "proxy", "tool_name": "proxy.stripe",
            "input_sha256": content_hash(descriptor)}
    st = {"type": "provenza.approval", "v": 1, "org_id": ORG, "user_id": 3, "session_id": "s" * 32,
          "action_id": 77, **call, "decision": "approved", "issued_at": NOW - 60}
    approval = {"approval_id": 1, "action_id": 77, "statement": st, "signature": _sign(session_key, st),
                "session_public_key": _raw(session_key),
                "certificate": {"statement": cert, "credential_id": cred_c,
                                "assertion": {k: ca[k] for k in ("client_data_json", "authenticator_data", "signature")}},
                "passkey": {"id": 3, "alg": pk_c["alg"], "public_key": pk_c["public_key"]}}

    # the agent's signed request for the same call
    payload = {"type": "action.request", "agent_id": 5, "chain_id": None, "action_type": "proxy",
               "tool_name": "proxy.stripe", "input_sha256": content_hash(descriptor), "tool_version": None,
               "tool_digest": None, "nonce": secrets.token_hex(16), "issued_at": NOW - 10}
    request = {"payload": payload, "signature": _sign(agent_key, payload), "public_key": _raw(agent_key)}

    return {"comment": "generated by backend/scripts/trust_vectors.py; checked by backend/tests/test_trust_vectors.py "
                       "and proxy/internal/trust - keys are random, the file is made once",
            "now": NOW, "releases": releases, "pin": releases[0]["release"]["manifest"]["sha256"],
            "descriptor": descriptor, "call": call, "approval": approval, "request": request,
            "request_header": base64.urlsafe_b64encode(json.dumps(request).encode()).decode().rstrip("="),
            "agent_fingerprint": agent_fp, "sealed": sealed_vectors(),
            "origins": [[u, sealed.origin(u)] for u in ORIGINS], "http_tools": http_tool_vectors(),
            "llm_messages": llm_message_vectors()}


def llm_message_vectors():
    """The messages' hash the LLM gateway records (app/services/gateway_service.py):
    the proxy computes it from the request it keeps (proxy/internal/egress/llm.go)."""
    from app.schemas.gateway import ChatCompletionIn
    from app.services.gateway_service import _as_sent

    cases = [
        [{"role": "user", "content": "hello"}],
        [{"role": "system", "content": "be brief"}, {"role": "user", "content": "caf\u00e9 \u2603", "name": None}],
        [{"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "image_url", "image_url": {"url": "x"}}]},
         {"role": "assistant", "content": None, "tool_calls": [{"id": "t1", "function": {"name": "f", "arguments": "{}"}}]},
         {"role": "tool", "content": "42", "tool_call_id": "t1", "score": 1.5, "n": 10}],
    ]
    out = []
    for messages in cases:
        dumped = ChatCompletionIn(model="m", messages=messages).model_dump(exclude_none=False)["messages"]
        out.append({"messages": messages, "messages_sha256": content_hash(_as_sent([{**m} for m in dumped]))})
    return out


def http_tool_vectors():
    """HTTP tool calls as the server's gateway builds them (app/pvp/http_tools.py):
    the proxy builds the same request itself (proxy/internal/egress/tools.go)."""
    from types import SimpleNamespace
    from urllib.parse import parse_qsl, urlsplit

    from app.pvp.http_tools import argument_problems, build_request, definition
    from app.services.supply_chain import manifest_digest

    schema = {"type": "object", "properties": {"id": {"type": ["string", "integer"]}, "tier": {"enum": ["gold", "silver"]},
                                               "n": {"type": "integer"}, "q": {"type": "string"},
                                               "tags": {"type": "array"}, "flag": {"type": "boolean"}},
              "required": ["id"], "additionalProperties": False}
    cases = [
        ("PATCH", "https://crm.example/customers/{id}", {"id": "c/42", "tier": "gold"}),
        ("GET", "https://crm.example/customers/{id}/orders?all=1", {"id": 7, "q": "a b&c", "n": 3, "flag": True,
                                                                     "tags": ["x", "y"]}),
        ("DELETE", "https://crm.example/c/{id}", {"id": "\u00e9t\u00e9 \u2603"}),
        ("POST", "https://crm.example/x", {"id": "1", "q": "caf\u00e9", "n": 12345678901234567890}),
        ("GET", "https://crm.example/c/{id}", {"id": ".."}),
        ("GET", "https://crm.example/c/{id}", {"tier": "bronze"}),
        ("GET", "https://crm.example/c/{id}", {"id": 1, "extra": 1}),
        ("GET", "https://crm.example/c/{id}", {"id": 1, "n": 1.5}),
        ("GET", "https://crm.example/c/{id}", {"id": True}),
    ]
    out = []
    for method, url, args in cases:
        tool = SimpleNamespace(name="crm.op", method=method, url=url, input_schema=schema, description="d \u00e9")
        problems = argument_problems(schema, args, url)
        case = {"definition": definition(tool), "digest": manifest_digest(definition(tool)), "arguments": args,
                "refused": bool(problems)}
        if not problems:
            target, query, body = build_request(tool, args)
            import httpx

            full = str(httpx.URL(target).copy_merge_params(query)) if query else target   # as the client sends it
            u = urlsplit(full)
            case.update({"path": u.path, "query": sorted(parse_qsl(u.query, keep_blank_values=True)),
                         "body": json.loads(body) if body else None})
        out.append(case)
    return out


# what a credential may be sent to: the same origin in Python, Go and the browser
ORIGINS = ["https://api.stripe.com/v1/charges", "HTTPS://API.Stripe.COM:443/x", "https://api.stripe.com:8443/",
           "http://127.0.0.1:8080/mcp", "http://localhost:80", "https://[2001:DB8::1]:443/v1", "https://[::1]:9443",
           "https://user:pw@host.example/p?q=1#f", "ftp://host.example/", "https://", "not a url",
           "https://host.example:99999/"]


def sealed_vectors():
    """Credentials sealed as the browser seals them, for the proxy to open
    (proxy/internal/egress/sealed.go): the proxy's encryption key derived from
    its signing seed, the statement it signs about it, and envelopes - one
    that opens, and some that must not."""
    seed = secrets.token_bytes(32)
    enc = sealed.proxy_encryption_key(seed)
    pub = base64.b64encode(enc.public_key().public_bytes(serialization.Encoding.Raw,
                                                         serialization.PublicFormat.Raw)).decode()
    up = "https://api.stripe.com"
    ctx = sealed.context(ORG, "route", 7, 2, up)
    env = sealed.seal("Bearer sk_live_vector \u00e9", pub, ctx)
    base = {"proxy_seed": base64.b64encode(seed).decode(), "encryption_key": pub,
            "key_statement": canonical_bytes(sealed.key_statement(pub)).decode()}
    other = dict(env, ct=base64.b64encode(b"\0" * 32).decode())
    # fixed ephemeral key and nonce: the browser (frontend/lib/sealing.ts) must make exactly this envelope
    eph, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    browser = sealed._seal("sk-browser", pub, ctx, X25519PrivateKey.from_private_bytes(eph), nonce)
    return [
        {**base, "name": "made by the browser", "context": ctx, "envelope": browser, "credential": "sk-browser",
         "ephemeral": base64.b64encode(eph).decode(), "nonce": base64.b64encode(nonce).decode()},
        {**base, "name": "opens", "context": ctx, "envelope": env, "credential": "Bearer sk_live_vector \u00e9"},
        {**base, "name": "another object", "context": sealed.context(ORG, "route", 8, 2, up), "envelope": env,
         "fails": True},
        {**base, "name": "another proxy", "context": sealed.context(ORG, "route", 7, 3, up), "envelope": env,
         "fails": True},
        {**base, "name": "another upstream", "context": sealed.context(ORG, "route", 7, 2, "https://evil.example"),
         "envelope": env, "fails": True},
        {**base, "name": "tampered", "context": ctx, "envelope": other, "fails": True},
    ]


def _session(dev: SoftAuthenticator, cred: str, user_id: int, session_id: str):
    key = Ed25519PrivateKey.generate()
    cert = {"type": "provenza.session.certificate", "v": 1, "org_id": ORG, "user_id": user_id, "session_id": session_id,
            "public_key": _raw(key), "not_before": NOW - 3600, "not_after": NOW + 3600, "issued_at": NOW - 3600}
    a = dev.get(b64url(webauthn.statement_challenge(cert)))
    return key, {"statement": cert, "credential_id": cred,
                 "assertion": {k: a[k] for k in ("client_data_json", "authenticator_data", "signature")}}


def sensor_command_vectors():
    """Commands to a sensor that an administrator signed (app/services/egress_sensor_commands.py),
    as the sensor checks them against its signed manifest (sensor/internal/trust/command.go)."""
    from types import SimpleNamespace

    from app.services.egress_sensor_commands import sensor_command_statement

    admin, approver = SoftAuthenticator(-7), SoftAuthenticator(-8)
    pk_a, cred_a = _passkey(admin)
    pk_c, cred_c = _passkey(approver)
    manifest = {"type": pb.MANIFEST_TYPE, "v": 1, "org_id": ORG, "version": 1, "previous": None, "quorum": 1,
                "signers": {"1": {"email": "a@example.com", "role": "admin", "passkeys": {cred_a: pk_a}},
                            "3": {"email": "c@example.com", "role": "approver", "passkeys": {cred_c: pk_c}}},
                "agents": {}, "egress_proxies": {}, "egress_sensors": {"4": {"name": "edge", "key_hash": "0" * 64,
                                                                              "enabled": True}},
                "sensor_command_key": None, "proxy_binaries": ["ab" * 32]}

    def proof(dev, cred, pk, user_id, sid, kind="restart"):
        key, cert = _session(dev, cred, user_id, sid)
        st = sensor_command_statement(SimpleNamespace(org_id=ORG, id=user_id), SimpleNamespace(id=sid), 4, kind,
                                      secrets.token_urlsafe(16), NOW - 30)
        return {"statement": st, "signature": _sign(key, st), "session_public_key": _raw(key), "certificate": cert,
                "passkey": {"id": user_id, "alg": pk["alg"], "public_key": pk["public_key"]}}

    return {"comment": "generated by backend/scripts/trust_vectors.py sensor-commands; checked by "
                       "backend/tests/test_sensor_signed_commands.py and sensor/internal/trust - keys are random, "
                       "the file is made once",
            "now": NOW, "sensor_id": 4, "manifest": manifest,
            "admin": proof(admin, cred_a, pk_a, 1, "a" * 32),
            "approver": proof(approver, cred_c, pk_c, 3, "c" * 32)}


def lift_vectors():
    """Lifting a proxy's local kill switch (app/pvp/proxy_offline.py): the
    administrators' passkeys over the reconciliation report, as the proxy
    checks them against the manifest it held before the outage
    (proxy/internal/trust/lift.go)."""
    from app.pvp.proxy_offline import lift_statement

    devs = {1: SoftAuthenticator(-7), 2: SoftAuthenticator(-8), 3: SoftAuthenticator(-7)}
    keys = {u: _passkey(d) for u, d in devs.items()}
    signers = {"1": {"email": "a@example.com", "role": "admin", "passkeys": {keys[1][1]: keys[1][0]}},
               "2": {"email": "b@example.com", "role": "admin", "passkeys": {keys[2][1]: keys[2][0]}},
               "3": {"email": "c@example.com", "role": "approver", "passkeys": {keys[3][1]: keys[3][0]}}}
    manifest = {"type": pb.MANIFEST_TYPE, "v": 1, "org_id": ORG, "version": 3, "previous": None, "quorum": 2,
                "signers": signers, "agents": {}, "egress_proxies": {}, "egress_sensors": {},
                "sensor_command_key": None}
    report_sha, unsigned = "ab" * 32, ["credentials.sealed.route:7", "manifest.agents.5"]

    def sig(user, accept=unsigned, sha=report_sha, issued=NOW - 60):
        st = lift_statement(ORG, user, 2, sha, accept, issued)
        a = devs[user].get(b64url(webauthn.statement_challenge(st)))
        return {"user_id": user, "credential_id": keys[user][1], "statement": st,
                "assertion": {k: a[k] for k in ("client_data_json", "authenticator_data", "signature")}}

    return {"comment": "generated by backend/scripts/trust_vectors.py lift; checked by "
                       "backend/tests/test_proxy_kill_switch.py and proxy/internal/trust - keys are random",
            "now": NOW, "engaged_at": NOW - 3600, "proxy_id": 2, "manifest": manifest, "report_sha256": report_sha,
            "unsigned": unsigned, "signatures": [sig(1), sig(2)],
            "approver": sig(3), "partial_accept": sig(1, accept=unsigned[:1]),
            "before_engaged": sig(2, issued=NOW - 7200), "other_report": sig(2, sha="cd" * 32)}


def enforce_vectors():
    """A release in enforce mode (the bundle's "enforcement" section) naming
    agent 5's key, and that key - what the proxy's agent mode signs with
    (proxy/internal/egress/agentmode.go). Checked by proxy/internal/egress
    and backend/tests/test_enforce_mode.py."""
    admin = SoftAuthenticator(-7)
    pk, cred = _passkey(admin)
    agent_key = Ed25519PrivateKey.generate()
    seed = agent_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                   serialization.NoEncryption())
    bundle = {"type": pb.BUNDLE_TYPE, "v": 1, "org_id": ORG, "version": 1, "previous": None,
              "not_after": NOW + 86400, "offline_seconds": 900, "enforcement": {"mode": "enforce"},
              "agents": {"5": {"name": "payer", "status": "active", "team_id": None, "capabilities": ["read"],
                               "allowed_tools": ["proxy.stripe"], "allowed_models": [], "max_delegation_depth": 1}},
              "egress_routes": {"9": {"slug": "stripe", "upstream_url": "https://api.stripe.com", "methods": ["POST"],
                                      "path_prefixes": ["/v1/charges"], "credential_source": "none",
                                      "auth_header": "Authorization", "max_body_bytes": 1024, "enabled": True}}}
    manifest = {"type": pb.MANIFEST_TYPE, "v": 1, "org_id": ORG, "version": 1, "previous": None, "quorum": 1,
                "signers": {"1": {"email": "a@example.com", "role": "admin", "passkeys": {cred: pk}}},
                "agents": {"5": key_fingerprint(_raw(agent_key))}, "egress_proxies": {}, "egress_sensors": {},
                "sensor_command_key": None}
    rel = {"number": 1, "bundle": {"version": 1, "sha256": pb.sha256(bundle)},
           "manifest": {"version": 1, "sha256": pb.sha256(manifest)}}
    st = {"type": "provenza.policy.release", "v": 1, "org_id": ORG, "user_id": 1, "release": 1,
          "bundle": rel["bundle"], "manifest": rel["manifest"], "not_after": bundle["not_after"],
          "issued_at": NOW - 100}
    a = admin.get(b64url(webauthn.statement_challenge(st)))
    sealer = sealer_vectors(admin, cred, pk)
    doc = {"release": rel, "bundle": bundle, "manifest": manifest, "governed_by": None,
           "signatures": [{"user_id": 1, "credential_id": cred, "statement": st,
                           "assertion": {k: a[k] for k in ("client_data_json", "authenticator_data", "signature")}}]}
    return {"comment": "generated by backend/scripts/trust_vectors.py enforce; checked by proxy/internal/egress - "
                       "keys are random, the file is made once",
            "now": NOW, "releases": [doc], "pin": rel["manifest"]["sha256"],
            "agent": {"agent_id": 5, "private_key": base64.b64encode(seed).decode(), "public_key": _raw(agent_key),
                      "key_fingerprint": key_fingerprint(_raw(agent_key))},
            "a2a_cards": a2a_card_vectors(), "sealer": sealer}


def sealer_vectors(admin: SoftAuthenticator, cred: str, pk: dict):
    """A credential sealed to a proxy (its signing seed here, so the test proxy
    has the same key) and signed by the administrator of the release above
    (app/services/credentials.py) - what an enforcing proxy opens
    (proxy/internal/trust/sealer.go)."""
    from types import SimpleNamespace

    from app.services.credentials import sealed_statement

    seed = secrets.token_bytes(32)
    enc = sealed.proxy_encryption_key(seed)
    enc_public = base64.b64encode(enc.public_key().public_bytes(serialization.Encoding.Raw,
                                                                serialization.PublicFormat.Raw)).decode()
    ctx = sealed.context(ORG, "route", 9, 1, "https://api.stripe.com")
    envelope = sealed.seal("Bearer sk_sealed_" + "s" * 24, enc_public, ctx)
    key, cert = _session(admin, cred, 1, "e" * 32)
    st = sealed_statement(SimpleNamespace(org_id=ORG, id=1), SimpleNamespace(id="e" * 32), "route", 9,
                          "https://api.stripe.com", {1: pb.sha256(envelope)}, NOW - 50)
    proof = {"statement": st, "signature": _sign(key, st), "session_public_key": _raw(key), "certificate": cert,
             "passkey": {"id": 1, "alg": pk["alg"], "public_key": pk["public_key"]}}
    return {"proxy_seed": base64.b64encode(seed).decode(), "proxy_id": 1, "org_id": ORG, "object": "route",
            "object_id": 9, "upstream": "https://api.stripe.com", "envelope": envelope,
            "envelope_sha256": pb.sha256(envelope), "proof": proof}


def a2a_card_vectors():
    """The digest of an A2A peer's card the signed Tool Registry pins
    (a2a_wire.pinned_card, supply_chain.manifest_digest): an enforcing proxy
    computes it itself from the card it fetched (proxy/internal/egress/a2a.go)."""
    from app.pvp.a2a_wire import pinned_card
    from app.services.supply_chain import manifest_digest

    cards = [
        {"name": "Billing agent", "version": "1.0.0", "description": "Счета и платежи - Ёж, 東京 \u2028 é",
         "supportedInterfaces": [{"url": "https://billing.example/a2a", "protocolBinding": "JSONRPC",
                                  "protocolVersion": "1.0"}],
         "capabilities": {"streaming": True, "pushNotifications": False},
         "skills": [{"id": "refund", "name": "Refund", "tags": ["money"], "limits": {"max": 1000, "ratio": 0.25,
                                                                                      "big": 12345678901234}}],
         "signatures": [{"protected": "eyJhbGciOiJFUzI1NiJ9", "signature": "c2ln"}]},
        {"name": "x", "url": "https://x.example/", "protocolVersion": "0.3.0", "empty": {}, "list": [], "nil": None,
         "flag": False, "neg": -1.5, "exp": 1e-7},
    ]
    return [{"card": c, "digest": manifest_digest(pinned_card(c))} for c in cards]


if __name__ == "__main__":
    if sys.argv[1:] == ["enforce"]:
        ENFORCE_OUT.write_text(json.dumps(enforce_vectors(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {ENFORCE_OUT}")
    elif sys.argv[1:] == ["lift"]:
        LIFT_OUT.write_text(json.dumps(lift_vectors(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {LIFT_OUT}")
    elif sys.argv[1:] == ["sensor-commands"]:
        SENSOR_OUT.write_text(json.dumps(sensor_command_vectors(), indent=1, ensure_ascii=False) + "\n",
                              encoding="utf-8")
        print(f"wrote {SENSOR_OUT}")
    else:
        OUT.write_text(json.dumps(build(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {OUT}")
