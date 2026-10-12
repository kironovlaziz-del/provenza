# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP canonical model, version "pvp/1" (docs/pvp/spec.md is the normative text).

Every PVP message is a JSON object with two fixed members:

    "pvp":  "pvp/1"            protocol version
    "type": "action.request"   which message this is (the discriminator)

Rules shared by all messages:
  - unknown members are refused (extra="forbid"): a field one side signs and
    the other silently drops is how signature-confusion bugs start;
  - ids and integers are strict - 5 is an id, "5", 5.0 and true are not;
  - every timestamp is integer Unix seconds, except inside an audit
    checkpoint, whose signed statement fixes its own format;
  - floats in tool input/output must be finite (no NaN / Infinity): they are
    hashed, and NaN has no JSON form a second implementation would agree on.

What gets signed is never the message itself but its signed_payload(): the
same dict, serialized with app.core.agent_signing.canonical_bytes, that the
REST endpoints have always verified. An agent that already signs delegations
and actions produces valid PVP signatures without any change.

A model says what is well-formed (types, sizes, formats); what is allowed
- a signed request without a nonce or check_id, self-delegation, a missing
signature for a keyed agent - is decided by the orchestrator, which knows
the agent and answers with the protocol's error codes.

The models are pure: no database, no I/O. Verification helpers here check
signatures and internal consistency only - whether a key belongs to the
agent, is revoked, or was trusted at a given time is the orchestrator's job.
"""

import hashlib
import json
import math
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

from pydantic import (BaseModel, ConfigDict, Field, StrictInt, StrictStr, StringConstraints, TypeAdapter,
                      field_validator, model_validator)

from app.core import audit_chain
from app.core.agent_signing import (SCHEME_CLASSIC, SCHEME_HYBRID, canonical_bytes, canonical_text, content_hash,
                                    key_fingerprint, verify_agent_signature)

PVP_VERSION = "pvp/1"

# policy verdicts - the values app/services/agent_policy_engine.py returns
ALLOWED = "allowed"
DENIED = "denied"
PENDING_APPROVAL = "pending_approval"

Decision = Literal["allowed", "denied", "pending_approval"]
Scheme = Literal["ed25519", "ed25519+ml-dsa-65"]

# integer columns are 32-bit; Unix seconds stay within the range JSON
# numbers carry exactly (RFC 8785 / I-JSON), so any verifier reads them alike
Id = Annotated[StrictInt, Field(ge=1, le=2**31 - 1)]
UnixTime = Annotated[StrictInt, Field(ge=0, le=2**53 - 1)]
Sha256Hex = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Base64 = Annotated[StrictStr, StringConstraints(min_length=4, max_length=6000, pattern=r"^[A-Za-z0-9+/]+={0,2}$")]
Name = Annotated[StrictStr, StringConstraints(min_length=1, max_length=100)]
ActionType = Annotated[StrictStr, StringConstraints(min_length=1, max_length=50, pattern=r"^[a-z][a-z0-9_.-]*$")]
Nonce = Annotated[StrictStr, StringConstraints(min_length=16, max_length=128)]
CheckToken = Annotated[StrictStr, StringConstraints(min_length=16, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]
ErrorCode = Annotated[StrictStr, StringConstraints(max_length=100, pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")]

MAX_LIST = 200
MAX_TASK = 10_000
MAX_DELEGATION_TTL = 30 * 24 * 3600


def _finite(value: Any, path: str = "$") -> None:
    """Refuse NaN / Infinity anywhere in a JSON value. Iterative: a deeply
    nested value must not turn into a RecursionError (the Input Guard bounds
    depth before this runs, but the model does not rely on it)."""
    stack = [(value, path)]
    while stack:
        node, where = stack.pop()
        if isinstance(node, float) and not math.isfinite(node):
            raise ValueError(f"{where}: non-finite number")
        if isinstance(node, dict):
            stack.extend((v, f"{where}.{k}") for k, v in node.items())
        elif isinstance(node, list):
            stack.extend((v, f"{where}[{i}]") for i, v in enumerate(node))


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pvp: Literal["pvp/1"] = PVP_VERSION


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

class PVPSignature(BaseModel):
    """A signature as evidence: the bytes signed are canonical_bytes of the
    record's signed_payload; the keys are the ones that verified it when the
    record was made (never "the agent's current key"). Hybrid: Ed25519 AND
    ML-DSA-65 over the same bytes, both must verify."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Scheme
    public_key: Base64
    signature: Base64
    pq_public_key: Optional[Base64] = None
    pq_signature: Optional[Base64] = None

    @model_validator(mode="after")
    def _halves(self):
        hybrid = self.scheme == SCHEME_HYBRID
        if hybrid != (self.pq_public_key is not None) or hybrid != (self.pq_signature is not None):
            raise ValueError(f"scheme {self.scheme!r}: pq_public_key and pq_signature are "
                             f"{'required' if hybrid else 'not allowed'}")
        return self

    @property
    def key_fingerprint(self) -> Optional[str]:
        return key_fingerprint(self.public_key, self.pq_public_key)

    def verify(self, payload: Dict[str, Any]) -> bool:
        return verify_agent_signature(payload, self.signature, self.pq_signature,
                                      self.public_key, self.pq_public_key)


def signature_of(signature: Optional[str], pq_signature: Optional[str],
                 public_key: Optional[str], pq_public_key: Optional[str]) -> Optional[PVPSignature]:
    """PVPSignature from stored columns, or None for an unsigned record."""
    if not signature or not public_key:
        return None
    return PVPSignature(
        scheme=SCHEME_HYBRID if pq_public_key else SCHEME_CLASSIC,
        public_key=public_key, signature=signature,
        pq_public_key=pq_public_key, pq_signature=pq_signature if pq_public_key else None,
    )


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

class PVPAgent(_Message):
    """An agent as PVP knows it. The rights are the registered ones - the
    ceiling; what an agent may use in a delegation chain is narrower and is
    computed by the server, never read from a message."""
    type: Literal["agent"] = "agent"
    id: Id
    org_id: Id
    name: Annotated[StrictStr, StringConstraints(min_length=1, max_length=255)]
    status: Literal["active", "suspended", "retired"]
    team_id: Optional[Id] = None
    capabilities: List[Name] = Field(default_factory=list, max_length=MAX_LIST)
    allowed_tools: List[Name] = Field(default_factory=list, max_length=MAX_LIST)
    allowed_models: List[Name] = Field(default_factory=list, max_length=MAX_LIST)
    max_delegation_depth: Annotated[StrictInt, Field(ge=0, le=100)]
    scheme: Optional[Scheme] = None
    public_key: Optional[Base64] = None
    pq_public_key: Optional[Base64] = None
    key_origin: Optional[Literal["agent", "server"]] = None

    @model_validator(mode="after")
    def _key(self):
        if self.pq_public_key and not self.public_key:
            raise ValueError("pq_public_key comes with public_key")
        if self.public_key and self.scheme != (SCHEME_HYBRID if self.pq_public_key else SCHEME_CLASSIC):
            raise ValueError("scheme does not match the keys")
        if not self.public_key and self.scheme is not None:
            raise ValueError("a keyless agent has no scheme")
        return self

    @property
    def key_fingerprint(self) -> Optional[str]:
        return key_fingerprint(self.public_key, self.pq_public_key)


class PVPAttestation(_Message):
    """Where an agent proved it runs, and until when that proof counts
    (services/attestation.py). Only the claims a policy matched are kept."""
    type: Literal["attestation"] = "attestation"
    agent_id: Id
    kind: Literal["k8s_sa"]
    policy_id: Optional[Id] = None
    attested_at: UnixTime
    expires_at: UnixTime
    claims: Dict[Name, Annotated[StrictStr, StringConstraints(max_length=500)]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _window(self):
        if self.expires_at <= self.attested_at:
            raise ValueError("expires_at must be after attested_at")
        return self


# ---------------------------------------------------------------------------
# Actions: request -> check -> record -> action
# ---------------------------------------------------------------------------

class _ActionShape(_Message):
    agent_id: Id
    chain_id: Optional[Id] = None
    action_type: ActionType = "tool_call"   # tool_call, model_call, api_request
    tool_name: Name


class PVPActionRequest(_ActionShape):
    """An agent asks whether it may perform an action. What the action needs
    comes from the Tool Registry, so the request carries no capabilities."""
    type: Literal["action.request"] = "action.request"
    input: Dict[StrictStr, Any] = Field(default_factory=dict)
    # ASI04: what the agent's runtime reports, compared with the registry pins
    tool_version: Optional[Annotated[StrictStr, StringConstraints(max_length=100)]] = None
    tool_digest: Optional[Annotated[StrictStr, StringConstraints(max_length=100)]] = None

    @field_validator("input")
    @classmethod
    def _input_finite(cls, v):
        _finite(v, "$.input")
        return v

    @property
    def input_sha256(self) -> str:
        return content_hash(self.input)


class PVPCheck(_ActionShape):
    """The verdict for one proposed action, bound to it by input_sha256. The
    check_id is single-use and expires: recording presents it once, for
    exactly this action."""
    type: Literal["action.check"] = "action.check"
    check_id: CheckToken
    input_sha256: Sha256Hex
    decision: Decision
    reason: StrictStr = ""   # server-made; never refused for its length
    incident_type: Optional[Name] = None
    policy_id: Optional[Id] = None
    required_capabilities: List[Name] = Field(default_factory=list, max_length=MAX_LIST)
    expires_at: UnixTime


class PVPActionRecord(_ActionShape):
    """An agent reports an action it performed. Agents with a key must
    present the check_id and sign signed_payload()."""
    type: Literal["action.record"] = "action.record"
    check_id: Optional[CheckToken] = None
    input: Dict[StrictStr, Any] = Field(default_factory=dict)
    output: Optional[Dict[StrictStr, Any]] = None
    duration_ms: Optional[Annotated[StrictInt, Field(ge=0, le=2**31 - 1)]] = None
    signature: Optional[Base64] = None
    pq_signature: Optional[Base64] = None

    @field_validator("input", "output")
    @classmethod
    def _finite_values(cls, v, info):
        _finite(v, f"$.{info.field_name}")
        return v

    def signed_payload(self) -> Dict[str, Any]:
        """Exactly what POST /agents/actions/record verifies."""
        return {
            "check_id": self.check_id,
            "agent_id": self.agent_id,
            "chain_id": self.chain_id,
            "action_type": self.action_type,
            "tool_name": self.tool_name,
            "input_sha256": content_hash(self.input),
            "output_sha256": content_hash(self.output),
        }


class PVPAction(_ActionShape):
    """A recorded action - allowed or not: refused attempts are recorded too."""
    type: Literal["action"] = "action"
    action_id: Id
    check_id: Optional[CheckToken] = None
    decision: Decision
    reason: StrictStr = ""   # server-made; never refused for its length
    policy_id: Optional[Id] = None
    input_sha256: Sha256Hex
    output_sha256: Sha256Hex
    duration_ms: Optional[Annotated[StrictInt, Field(ge=0, le=2**31 - 1)]] = None
    recorded_at: UnixTime
    signed_payload: Optional[Dict[StrictStr, Any]] = None
    signed_by: Optional[PVPSignature] = None
    # None = the agent performed the call and reported it; a gateway name =
    # Provenza performed it on the agent's behalf (no agent signature: the
    # gateway is the witness, and the audit log holds its record)
    executed_by: Optional[Literal["mcp_gateway", "a2a_gateway", "egress_proxy"]] = None

    @model_validator(mode="after")
    def _evidence(self):
        if (self.signed_payload is None) != (self.signed_by is None):
            raise ValueError("signed_payload and signed_by come together")
        return self

    def problems(self) -> List[str]:
        """What does not hold in this record, judged from the record alone:
        the signature over signed_payload, and that signed_payload names
        this very action. Empty for a consistent signed record - and for an
        action a Provenza gateway executed, which no agent signs (the gateway
        is the witness; a seal commits to its record)."""
        if self.signed_by is None:
            return [] if self.executed_by is not None and self.signed_payload is None else ["unsigned"]
        out = []
        p = self.signed_payload or {}
        expected = {"check_id": self.check_id, "agent_id": self.agent_id, "chain_id": self.chain_id,
                    "action_type": self.action_type, "tool_name": self.tool_name,
                    "input_sha256": self.input_sha256, "output_sha256": self.output_sha256}
        if set(p) != set(expected):
            out.append("signed_payload_fields")
        out += [f"signed_payload_mismatch:{k}" for k, v in expected.items() if k in p and p[k] != v]
        if not self.signed_by.verify(p):
            out.append("signature_invalid")
        return out


# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------

class PVPDelegation(_Message):
    """One agent hands a task, and a subset of its rights, to another. The
    server checks the subset (child <= parent), the depth and that the
    lifetime never grows down the chain; expires_in counts from the signed
    issued_at, so a late resend cannot extend it."""
    type: Literal["delegation"] = "delegation"
    from_agent_id: Id
    to_agent_id: Id
    task: Annotated[StrictStr, StringConstraints(max_length=MAX_TASK)]
    delegated_capabilities: List[Name] = Field(default_factory=list, max_length=MAX_LIST)
    # omitted = the delegating agent's tools in the chain (never more)
    delegated_tools: Optional[List[Name]] = Field(default=None, max_length=MAX_LIST)
    chain_id: Optional[Id] = None   # None = a new chain
    nonce: Optional[Nonce] = None
    issued_at: Optional[UnixTime] = None
    expires_in: Optional[Annotated[StrictInt, Field(ge=1, le=MAX_DELEGATION_TTL)]] = None
    signature: Optional[Base64] = None
    pq_signature: Optional[Base64] = None

    def signed_payload(self) -> Dict[str, Any]:
        """Exactly what POST /agents/{id}/delegate verifies."""
        payload = {
            "from_agent_id": self.from_agent_id,
            "to_agent_id": self.to_agent_id,
            "task": self.task,
            "delegated_capabilities": sorted(self.delegated_capabilities),
            "chain_id": self.chain_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_in": self.expires_in,
        }
        if self.delegated_tools is not None:
            # signed only when sent, so payloads of agents that do not delegate tools stay as they were
            payload["delegated_tools"] = sorted(set(self.delegated_tools))
        return payload


# ---------------------------------------------------------------------------
# Audit evidence
# ---------------------------------------------------------------------------

class PVPCheckpoint(_Message):
    """A signed Merkle root of an organization's audit log - the same object
    GET /audit-logs/checkpoints returns (app/services/audit_proofs.py).
    issued_at is the string the signed statement carries."""
    type: Literal["checkpoint"] = "checkpoint"
    org_id: Id
    tree_size: Annotated[StrictInt, Field(ge=0, le=2**53 - 1)]
    root_hash: Sha256Hex
    issued_at: StrictStr
    algorithm: Scheme
    statement: Annotated[StrictStr, StringConstraints(max_length=4000)]
    signature: Base64
    pq_signature: Optional[Base64] = None
    public_key: Base64
    pq_public_key: Optional[Base64] = None
    key_fingerprint: Annotated[StrictStr, StringConstraints(max_length=80)]

    def problems(self) -> List[str]:
        """Same rule as audit_proofs.checkpoint_valid, without the database:
        the statement is canonical, says what the fields say, and verifies."""
        try:
            stmt = json.loads(self.statement)
        except ValueError:
            return ["statement_not_json"]
        if not isinstance(stmt, dict) or canonical_text(stmt) != self.statement:
            return ["statement_not_canonical"]
        out = [f"statement_mismatch:{k}" for k in
               ("org_id", "tree_size", "root_hash", "issued_at", "key_fingerprint", "algorithm")
               if stmt.get(k) != getattr(self, k)]
        if key_fingerprint(self.public_key, self.pq_public_key) != self.key_fingerprint:
            out.append("fingerprint_mismatch")
        if self.algorithm != (SCHEME_HYBRID if self.pq_public_key else SCHEME_CLASSIC):
            out.append("algorithm_mismatch")
        if not verify_agent_signature(stmt, self.signature, self.pq_signature,
                                      self.public_key, self.pq_public_key):
            out.append("signature_invalid")
        return out


class PVPSeal(BaseModel):
    """Where an action's evidence sits in a seal (app/pvp/seal.py): leaf
    leaf_index of a Merkle tree (RFC 9162) of `size` evidence hashes whose
    root is written in audit record audit_log_id."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    seal_id: Id
    leaf_index: Annotated[StrictInt, Field(ge=0)]
    size: Annotated[StrictInt, Field(ge=1)]
    root: Sha256Hex
    inclusion_path: List[Sha256Hex] = Field(default_factory=list, max_length=64)
    audit_log_id: Id


def evidence_sha256(action: "PVPAction") -> str:
    """The leaf of an action in a seal: SHA-256 of its canonical evidence."""
    return hashlib.sha256(canonical_bytes(action.model_dump(mode="json"))).hexdigest()


class PVPReceipt(_Message):
    """Everything needed to show, without trusting the server, that an
    action was checked, performed as checked, signed by its agent (or
    witnessed by a Provenza gateway), and committed to the signed audit log:

        action (evidence as recorded) -> seal leaf -> seal record in the
        audit log (audit_proof, provenza.audit.proof/1) -> signed checkpoint

    current_decision is what the action's verdict is now (a human approval
    may have changed a pending one) - informational, not part of the proof."""
    type: Literal["receipt"] = "receipt"
    action: PVPAction
    check: Optional[PVPCheck] = None
    seal: Optional[PVPSeal] = None
    audit_proof: Optional[Dict[StrictStr, Any]] = None
    checkpoint: Optional[PVPCheckpoint] = None
    current_decision: Optional[Decision] = None

    def problems(self) -> List[str]:
        a = self.action
        out = a.problems()
        if self.check is not None:
            c = self.check
            out += [f"check_mismatch:{k}" for k in
                    ("check_id", "agent_id", "chain_id", "action_type", "tool_name", "input_sha256")
                    if getattr(a, k) != getattr(c, k)]
            # an executor may refuse after the check, never the other way round
            if c.decision != ALLOWED and a.decision == ALLOWED:
                out.append("check_mismatch:decision")
        if self.seal is not None:
            out += self._seal_problems()
        if self.checkpoint is not None:
            out += [f"checkpoint:{p}" for p in self.checkpoint.problems()]
        return out

    def _seal_problems(self) -> List[str]:
        s = self.seal
        out = []
        leaf = bytes.fromhex(evidence_sha256(self.action))
        if not audit_chain.verify_inclusion(s.leaf_index, s.size, leaf, [bytes.fromhex(h) for h in s.inclusion_path],
                                            bytes.fromhex(s.root)):
            out.append("seal:inclusion")
        proof = self.audit_proof
        if proof is None or self.checkpoint is None:
            return out + ["seal:no_audit_proof"]
        record = proof.get("record") or {}
        payload = record.get("payload") or {}
        meta = payload.get("metadata") or {}
        if (record.get("id"), payload.get("entity_type"), payload.get("entity_id")) != \
                (s.audit_log_id, "pvp_action_seal", s.seal_id) or meta.get("root") != s.root \
                or meta.get("size") != s.size:
            out.append("seal:audit_record_mismatch")
        if not isinstance(payload, dict) or audit_chain.record_hash(payload) != record.get("record_hash"):
            out.append("audit:record_hash")
        try:
            ok = audit_chain.verify_inclusion(
                proof["leaf_index"], proof["tree_size"], bytes.fromhex(record["record_hash"]),
                [bytes.fromhex(h) for h in proof["inclusion_path"]], bytes.fromhex(self.checkpoint.root_hash))
        except (KeyError, TypeError, ValueError):
            ok = False
        if not ok or proof.get("tree_size") != self.checkpoint.tree_size:
            out.append("audit:inclusion")
        return out


# ---------------------------------------------------------------------------
# Queries and errors
# ---------------------------------------------------------------------------

class PVPQuery(_Message):
    """A request for evidence. format "trace" asks for a TRACE Trust Record
    export (step P6) instead of the PVP form."""
    type: Literal["query"] = "query"
    subject: Literal["receipt", "action", "chain", "checkpoint"]
    id: Id
    format: Literal["pvp", "trace"] = "pvp"


class PVPError(_Message):
    """A refusal. code is a stable dotted identifier (e.g. agent.key_required);
    message is for humans and never echoes the refused content."""
    type: Literal["error"] = "error"
    code: ErrorCode
    message: Annotated[StrictStr, StringConstraints(max_length=500)] = ""
    details: Dict[StrictStr, Any] = Field(default_factory=dict)


PVPMessage = Annotated[
    Union[PVPAgent, PVPAttestation, PVPActionRequest, PVPCheck, PVPActionRecord, PVPAction,
          PVPDelegation, PVPCheckpoint, PVPReceipt, PVPQuery, PVPError],
    Field(discriminator="type"),
]
MESSAGE_TYPES = (PVPAgent, PVPAttestation, PVPActionRequest, PVPCheck, PVPActionRecord, PVPAction,
                 PVPDelegation, PVPCheckpoint, PVPReceipt, PVPQuery, PVPError)

_ADAPTER: TypeAdapter = TypeAdapter(PVPMessage)


def parse_message(data: Union[bytes, str, Dict[str, Any]]) -> BaseModel:
    """Any PVP message, by its "type". Raises pydantic.ValidationError."""
    if isinstance(data, (bytes, str)):
        return _ADAPTER.validate_json(data)
    return _ADAPTER.validate_python(data)
