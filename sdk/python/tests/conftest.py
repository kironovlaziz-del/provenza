# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""An in-memory Provenza for the SDK's tests - it verifies signatures for real."""

import base64
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from provenza import Agent
from provenza.crypto import canonical, content_hash

SERVER = "https://provenza.test"


class FakeProvenza:
    """Enrollment, check and record - and the server's signature rule."""

    def __init__(self):
        self.verdicts = {}          # tool -> decision
        self.public_key = None
        self.checks, self.records = {}, []
        self.nonces = set()
        self.down = set()           # paths that fail with 503
        self.record_failures = 0    # record answers 503 this many times first
        self.n = 0

    def _json(self, status, body):
        return httpx.Response(status, json=body)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1")
        if path in self.down:
            return self._json(503, {"detail": "down"})
        body = json.loads(request.content) if request.content else {}
        if path == "/agent-enrollment/challenge":
            return self._json(200, {"challenge": "c" * 32, "org_id": 1, "enrollment_id": 7, "name": None,
                                    "require_hybrid": False})
        if path == "/agent-enrollment/enroll":
            statement = {"type": "provenza.agent.enroll", "v": 1, "challenge": "c" * 32, "org_id": 1,
                         "enrollment_id": 7, "public_key": body["public_key"], "pq_public_key": None,
                         "name": body["name"] or ""}
            Ed25519PublicKey.from_public_bytes(base64.b64decode(body["public_key"])).verify(
                base64.b64decode(body["signature"]), canonical(statement))
            self.public_key = body["public_key"]
            from provenza.crypto import fingerprint
            return self._json(200, {"agent_id": 42, "api_key": "pvz_agent_key", "name": body["name"],
                                    "key_fingerprint": fingerprint(body["public_key"])})
        assert request.headers.get("x-agent-key") == "pvz_agent_key"
        if path == "/pvp/egress-catalog":
            return self._json(200, {"action_type": "egress", "tool_prefix": "egress.", "domains": [
                {"domain": "openai.com", "status": "allowed"}, {"domain": "blocked-ai.com", "status": "blocked"}]})
        if path == "/agents/actions/check":
            # what the server verifies: the agent's signature over the request, a fresh nonce
            payload = {"type": "action.request", "agent_id": body["agent_id"], "chain_id": body["chain_id"],
                       "action_type": body["action_type"], "tool_name": body["tool_name"],
                       "input_sha256": content_hash(body["input"]), "tool_version": body.get("tool_version"),
                       "tool_digest": body.get("tool_digest"), "nonce": body["nonce"], "issued_at": body["issued_at"]}
            Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key)).verify(
                base64.b64decode(body["signature"]), canonical(payload))   # raises if the SDK signed wrong
            assert body["nonce"] not in self.nonces, "nonce reused"
            self.nonces.add(body["nonce"])
            self.n += 1
            token = f"chk_{self.n:040d}"
            decision = self.verdicts.get(body["tool_name"], "allowed")
            self.checks[token] = {**body, "decision": decision}
            return self._json(200, {"decision": decision, "reason": f"policy says {decision}", "check_id": token,
                                    "incident_type": None, "policy_id": None})
        if path == "/agents/actions/record":
            if self.record_failures:
                self.record_failures -= 1
                return self._json(503, {"detail": "down"})
            chk = self.checks.get(body["check_id"])
            if chk is None:
                return self._json(404, {"detail": "Unknown check_id"})
            if chk.get("used"):
                return self._json(409, {"detail": "check_id already used"})
            payload = {"check_id": body["check_id"], "agent_id": body["agent_id"], "chain_id": body["chain_id"],
                       "action_type": body["action_type"], "tool_name": body["tool_name"],
                       "input_sha256": content_hash(body["input"]), "output_sha256": content_hash(body["output"])}
            Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key)).verify(
                base64.b64decode(body["signature"]), canonical(payload))   # raises if the SDK signed wrong
            assert content_hash(body["input"]) == content_hash(chk["input"])
            chk["used"] = True
            self.records.append(body)
            return self._json(200, {"id": len(self.records), "policy_check_result": chk["decision"]})
        if path.endswith("/delegate"):
            payload = {k: body[k] for k in ("to_agent_id", "task", "chain_id", "nonce", "issued_at", "expires_in")}
            payload.update(from_agent_id=42, delegated_capabilities=sorted(body["delegated_capabilities"]))
            if body.get("delegated_tools") is not None:
                payload["delegated_tools"] = sorted(set(body["delegated_tools"]))
            Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key)).verify(
                base64.b64decode(body["signature"]), canonical(payload))
            return self._json(200, {"chain_id": 5, "hop_id": 1, "verified": True})
        return self._json(404, {"detail": "not found"})


@pytest.fixture
def server():
    return FakeProvenza()


@pytest.fixture
def agent(server, tmp_path):
    a = Agent("billing-bot", server_url=SERVER, enrollment_token="pvz_enr_" + "x" * 20,
              identity_path=str(tmp_path / "id.json"), transport=httpx.MockTransport(server.handle),
              async_transport=httpx.MockTransport(server.handle))
    yield a
    a.close()


