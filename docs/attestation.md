# Workload attestation

An agent's signing key proves **who** is acting. Attestation proves **where**:
that the agent runs in your Kubernetes cluster, in an approved namespace or
service account, inside a pod — not on a laptop with a copied key.

Agents whose role template requires attestation cannot act — no action checks,
records, delegations, agent messages or gateway calls — until they hold a
current, passing attestation. The only routes open to them before that are
the attestation routes, their own key rotation and `GET /agent-identity/me`.

## How it works

```
agent (in a pod)                              Provenza
----------------                              --------
POST /agents/{id}/attestation/challenge  ──▶  one-use challenge (5 min) + the
  (X-Agent-Key)                               policy's audience
read the projected ServiceAccount token
sign {type, v, challenge, agent_id, kind,
      evidence_sha256 = sha256(token)}
  with the agent's own signing key
POST /agents/{id}/attestation            ──▶  1. challenge (spent by any attempt)
  {challenge, kind, evidence: token,          2. agent signature, current and unrevoked key
   signature, pq_signature}                   3. token: signature against the cluster's JWKS,
                                                 iss, aud, exp/iat, pod-bound
                                              4. namespace / service account allowed
                                              5. recorded + audited; ok → valid until
                                                 min(now + validity, token exp)
```

* **The token is bound to the agent.** A token copied off the pod is useless
  without the agent's private key, and the agent's key is useless without a
  token from the right workload.
* **Nothing lasts forever.** A passing attestation counts until the policy's
  validity (default 60 minutes) or the token's own expiry, whichever comes
  first. Changing the policy, or the role's policy, makes earlier
  attestations stop counting. The agent re-attests on a schedule
  (`provenza_sign.py attest --every N`).
* **Bound to the agent's key.** An attestation counts only while the agent
  still has the key that signed it: rotating, re-keying or revoking the key
  takes it away (attest again with the new key).
* **One pod's token, one agent.** A token that already attested one agent is
  refused for another (`attestation.token_reused`).
* **Short-lived tokens only.** A token whose lifetime (`exp - iat`) exceeds
  24 hours is refused, and an auto-extended token counts only until its
  `kubernetes.io.warnafter`. Keep `expirationSeconds` at 3600.
* **Every attempt is in the audit log**: `attested`, `attestation_failed`
  (the evidence was checked and refused, with the reason) and
  `attestation_refused` (bad challenge, or not signed by the agent's current
  key). Attempts that reached the evidence are also listed under
  Registry → Attestation.
* **Rate limited**: 30 challenges and attempts per agent per 10 minutes,
  counted only for the agent itself (nobody else can use up its budget).

## The audience — one value in three places

The token's `aud` must be the policy's audience. Set the same value in:

1. the pod spec (`serviceAccountToken.audience`),
2. the attestation policy (Registry → Attestation),
3. nothing else to do on the agent: the challenge tells it the audience and
   `provenza_sign.py attest` refuses to send a token for another one.

Use a value only Provenza accepts (default `provenza`), never the API
server's audience: a token Provenza accepts should be good for nothing else,
and the reverse. Policies refuse the issuer and the usual API-server
audiences (`https://kubernetes.default.svc...`, `kubernetes`, `api`).

The enrollment token screen and `provenza_sign.py enroll` show the audience
when the agent's role requires attestation.

## Setting it up

**1. The cluster's issuer and keys.** On a machine with `kubectl` access:

```bash
kubectl get --raw /.well-known/openid-configuration   # "issuer"
kubectl get --raw /openid/v1/jwks                      # the keys
```

Create a policy in Registry → Attestation: the issuer, the audience, and the
keys — pasted (private clusters), from a URL, or by OIDC discovery when the
issuer is publicly reachable (managed clusters: EKS, GKE, AKS). Fetched keys
and discovery documents are cached for an hour; a token signed with an
unknown key id triggers a refetch (the cluster rotated its key), at most once
a minute. Discovery must name the policy's issuer and its `jwks_uri` must be
https on the issuer's host; documents are limited to 256 KiB. A
self-managed cluster whose issuer is `https://kubernetes.default.svc...`
usually advertises its keys on another address: paste the keys or set the
JWKS URL instead of using discovery.

A token attests one agent: several agent processes in one pod sharing its
token cannot each attest with it — give each agent its own pod (or its own
projected token path).

Name the allowed namespaces and/or service accounts (`namespace/name`),
patterns with `*` allowed. At least one rule is required — without one any
workload of the cluster would pass.

**2. A role that requires it.** Teams & Roles → role → *Require attestation*
→ pick the policy. Agents that already have the role are blocked until they
attest (the page asks first).

**3. The pod.**

```yaml
spec:
  serviceAccountName: billing-agent
  containers:
  - name: agent
    volumeMounts:
    - name: provenza-token
      mountPath: /var/run/secrets/provenza
      readOnly: true
  volumes:
  - name: provenza-token
    projected:
      sources:
      - serviceAccountToken:
          audience: provenza
          expirationSeconds: 3600
          path: token
```

**4. The agent attests, and keeps attesting.**

```bash
python tools/provenza_sign.py attest --keys provenza-agent.json --every 10
```

It re-reads the token every time (the kubelet renews it when 80% of its
lifetime has passed, so a 1-hour token always has at least 12 minutes left)
and runs until stopped: as a sidecar or a background loop next to the agent.

**Checking a token first.** Registry → Attestation → *Test a token* checks a
token against a policy without recording anything:

```bash
kubectl create token billing-agent -n payments --audience provenza
```

(`kubectl create token` tokens are not bound to a pod: with *Only pod-bound
tokens* on they fail with `attestation.not_pod_bound` — expected; the
namespace and audience checks still show.)

## API

| | |
|---|---|
| `POST /agents/{id}/attestation/challenge` | the agent (X-Agent-Key): challenge + audience |
| `POST /agents/{id}/attestation` | the agent: evidence + signature → `{ok, reason, identity, valid_until}` |
| `GET/POST /attestation/policies`, `PATCH/DELETE /attestation/policies/{id}` | policies (admin to change) |
| `POST /attestation/policies/{id}/test` | dry run of a token (admin) |
| `GET /attestation/records?agent_id=` | attempts, newest first |
| `GET /attestation/agents/{id}` | what the agent needs and has |

Refusals elsewhere: `403 agent.attestation_required` (no current attestation)
and `403 agent.attestation_policy_missing` (the role requires attestation but
names no policy).

## Not covered (yet)

* Other evidence: TPM 2.0 quotes, cloud instance identity, other OIDC
  issuers (GitHub Actions, GCP, Azure) — the policy has a `kind` for them.
* Pinning one agent to one pod or node: the identity (pod, node) is recorded
  with every attestation, not enforced.
