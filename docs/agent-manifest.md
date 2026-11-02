# Agent Manifest

Provenza issues an **Agent Manifest** for every agent: a signed record of the
agent's identity, the tools it was approved for and the audit log its actions
are recorded in. Anyone can check it offline, without access to Provenza. The
format is the open [Agent Manifest specification
v0.2](https://github.com/agentrust-io/agent-manifest) of AgenTrust; the manifest
verifies with its `agent-manifest` SDK.

**Where:** the agent's page → **Agent Manifest** downloads it as a `.cose` file.
Administrators, approvers, auditors and compliance officers can download it.

```text
GET /api/v1/agents/{id}/manifest        the payload, the COSE envelope (base64) and the signing keys
GET /api/v1/agents/{id}/manifest.cose   the COSE envelope
```

## What it binds

Provenza is the policy gate, not the agent, so the manifest uses the
specification's `composition-only` profile. It binds what Provenza governs and
names everything else as `unbound_artifacts`:

| Field | Content |
|---|---|
| `agent_id` | the SPIFFE ID the agent attested with ([workload attestation](attestation.md)), else `spiffe://<server>/org/<org>/agent/<id>` |
| `issuer` | `spiffe://<server>/org/<org>/provenza` |
| `artifacts.tool_manifest` | the approved MCP tools the agent may call through Provenza's MCP gateway: per tool, the hashes of its approved schema and description, and the Merkle root of the catalog. A tool whose definition changes upstream is withheld until it is approved again (`rug_pull_policy: require-reapproval`). Bound only when every tool the agent is registered for is such a tool |
| `artifacts.decision_trace` | the organization's [audit log](audit-proofs.md): the root of its latest signed checkpoint, the number of records, the key that signs checkpoints |
| `hitl_record.required` | whether the agent's policies hold actions for a person's approval |
| `unbound_artifacts` | system prompt, model identity, RAG corpus, memory, supply chain and delegation chain (Provenza does not see them); the policy bundle (the specification names Cedar, Rego and AGT YAML only); the tool catalog when it cannot be bound completely |

The manifest is valid for 90 days. A new one is issued when what it binds
changes (tools, the approval requirement, the signing key) or near expiry; it
names the one it replaces (`previous_manifest_id`). Each issue is recorded in
the audit log (`agent_manifest_issued`, with the SHA-256 of the envelope).

## Signature

The organization's audit key signs it: a `COSE_Sign` with two signers,
Ed25519 and ML-DSA-65 (post-quantum), over the RFC 8785 form of the manifest.
On a server without ML-DSA-65 it is a `COSE_Sign1` with Ed25519 only. The keys
are the ones listed under the audit log's keys (`GET /api/v1/audit/keys`); when
the audit key is rotated, the next manifest is issued with the new key.

## Checking it

```bash
pip install agent-manifest==0.15.0
```

```python
import base64, hashlib
from agent_manifest import RevocationStore, VerificationContext, verify_cose_manifest, verify_manifest

def kid_map(*keys_b64):  # the audit key's public keys, base64, as Provenza lists them
    out = {}
    for k in keys_b64:
        raw = base64.b64decode(k)
        out[hashlib.sha256(raw).hexdigest()] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return out

envelope = open("agent-7-manifest.cose", "rb").read()
keys = kid_map(ED25519_PUBLIC_KEY, ML_DSA_65_PUBLIC_KEY)
print(verify_cose_manifest(envelope, keys).verified)            # True: both signatures
print(verify_manifest(envelope, VerificationContext(trusted_keys=keys), RevocationStore()).result)
# INCOMPLETE: authentic, and deliberately partial (composition-only)
```

Take the keys from a source you trust (the audit keys of the organization),
not from the file you are checking. A ready script is in AgenTrust's
integrations repository (`integrations/provenza-agent-manifest`).

## What it is not

- Not proof of what the agent runs: Provenza does not see its prompt, model or
  code. The verdict is `INCOMPLETE`, never `VALID`.
- No hardware attestation and no transparency log: the key is a software key on
  the Provenza server (`audit_key_sealed: false`).
- Approvals are not attached: Provenza records and signs them per held action
  ([agent signatures](agent-signing.md)); the manifest states only that they are
  required.
