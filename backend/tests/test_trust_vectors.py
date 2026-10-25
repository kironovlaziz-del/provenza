"""
sdk/testdata/trust-vectors.json (scripts/trust_vectors.py): a chain of signed
policy releases, a human approval and an agent's signed request, as an
enforcement point checks them without the server (proxy/internal/trust).
Here they are checked with the server's own code and with the standalone
tools/provenza_audit.py, and each tampering is refused - so the Go side and
the server agree on what is valid.
"""

import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.agent_signing import key_fingerprint, verify_payload
from app.models.policy_release import PolicyRelease
from app.pvp import approvals, signed_policy
from app.services.signing_sessions import proof_holds

ROOT = Path(__file__).resolve().parents[2]
V = json.loads((ROOT / "sdk" / "testdata" / "trust-vectors.json").read_text(encoding="utf-8"))
_spec = importlib.util.spec_from_file_location("provenza_audit_tool_trust", ROOT / "tools" / "provenza_audit.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


def _row(doc):
    r = doc["release"]
    return PolicyRelease(org_id=doc["bundle"]["org_id"], number=r["number"], bundle=doc["bundle"],
                         bundle_sha256=r["bundle"]["sha256"], manifest=doc["manifest"],
                         manifest_sha256=r["manifest"]["sha256"])


def _server_signers(doc):
    governing = doc["governed_by"]["manifest"] if doc["governed_by"] else doc["manifest"]
    sigs = [SimpleNamespace(**s) for s in doc["signatures"]]
    return signed_policy.valid_signers(_row(doc), governing, sigs), signed_policy.quorum_of(governing)


def test_the_releases_verify_on_the_server_and_offline():
    for doc in V["releases"]:
        signers, quorum = _server_signers(doc)
        assert len(signers) >= quorum
        tool.check_release(doc)
    first, second, third = V["releases"]
    assert first["release"]["manifest"]["sha256"] == V["pin"]
    assert second["release"]["manifest"]["sha256"] == third["release"]["manifest"]["sha256"]
    assert len(third["signatures"]) == 2 and _server_signers(third)[1] == 2


@pytest.mark.parametrize("change", [
    lambda d: d["bundle"]["agents"]["5"].update(allowed_tools=["*"]),
    lambda d: d["signatures"].pop(),
    lambda d: d["signatures"][0]["statement"].update(release=99),
    lambda d: d["governed_by"]["manifest"].update(quorum=1),
])
def test_a_tampered_release_does_not_verify(change):
    doc = copy.deepcopy(V["releases"][2])
    change(doc)
    with pytest.raises(tool.Fail):
        tool.check_release(doc)


def test_the_approval_holds():
    ap, call = V["approval"], V["call"]
    assert proof_holds(ap)
    assert approvals.listed(V["releases"][2]["manifest"], ap)
    assert not approvals.listed(V["releases"][0]["manifest"], ap)      # the approver signs from release 2 on
    st = ap["statement"]
    assert {k: st[k] for k in call} == call


def test_the_signed_request_verifies():
    rq = V["request"]
    assert verify_payload(rq["payload"], rq["signature"], rq["public_key"])
    assert key_fingerprint(rq["public_key"]) == V["agent_fingerprint"]
    assert V["releases"][2]["manifest"]["agents"]["5"] == V["agent_fingerprint"]
    assert json.loads(tool._b64url_decode(V["request_header"])) == rq


def test_sealed_credentials_open_as_the_proxy_opens_them():
    """The proxy's encryption key derived from its signing seed, the statement
    it signs about it, and envelopes that open only for their context - the
    same vectors proxy/internal/egress/sealed_test.go checks in Go."""
    import base64

    from cryptography.hazmat.primitives import serialization

    from app.core.agent_signing import canonical_bytes
    from app.pvp import sealed

    assert V["sealed"]
    for c in V["sealed"]:
        enc = sealed.proxy_encryption_key(base64.b64decode(c["proxy_seed"]))
        pub = base64.b64encode(enc.public_key().public_bytes(serialization.Encoding.Raw,
                                                             serialization.PublicFormat.Raw)).decode()
        assert pub == c["encryption_key"]
        assert canonical_bytes(sealed.key_statement(pub)).decode() == c["key_statement"]
        problem = sealed.envelope_problem(c["envelope"], c["context"], pub)
        if c.get("fails"):
            if problem is None:
                with pytest.raises(Exception):
                    sealed.open_sealed(c["envelope"], enc)
            continue
        assert problem is None and sealed.open_sealed(c["envelope"], enc) == c["credential"]


def test_the_origin_a_credential_may_go_to():
    from app.pvp import sealed

    assert V["origins"]
    for url, want in V["origins"]:
        assert sealed.origin(url) == want, url
