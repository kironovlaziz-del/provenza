from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.core.agent_signing import verify_agent_signature, verify_payload
from app.schemas.pagination import Page
from app.schemas.enrollment import AttestIn, RotateIn
from app.schemas.agent import (
    AgentCreate, AgentUpdate, AgentOut, AgentCreated,
    AgentKillRequest, AgentKillResponse,
    DelegateRequest, DelegateResponse, ChainOut, ChainDetail, HopOut,
    ActionCheckRequest, ActionCheckResponse, ActionRecordRequest, ActionDenyRequest, ActionOut,
    AgentPolicyCreate, AgentPolicyOut, AgentIncidentOut,
    GovernanceGraph, KeyRevokeIn, SigningKeyIn, SigningKeyOut, AgentAssignment,
)
from app.services.agent_registry import AgentRegistry
from app.services.agent_identity import keyless_refused, pq_signature_required
from app.services.delegation_service import DelegationService
from app.services.agent_audit import AgentAudit
from app.services.governance_graph_service import GovernanceGraphService
from app.services.audit_service import AuditService
from app.models.agent import Agent, AgentPolicy
from app.models.agent_action import AgentIncident
from app.models.user import User, UserRole
from app.api.deps import get_current_user, require_role

router = APIRouter()


# ============================ Agents ============================

@router.post("/register", response_model=AgentCreated)
async def register_agent(
    data: AgentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Direct registration (no proof that the agent holds its key) - only
    where the organization allows it. Otherwise agents join with an
    enrollment token: POST /agent-enrollment/tokens."""
    from app.services.agent_identity import org_settings

    if not (await org_settings(db, current_user.org_id)).get("allow_direct_registration"):
        from app.core.errors import api_error
        raise api_error(403, "agent.enrollment_required")
    registry = AgentRegistry(db)
    agent, raw_key, private_key = await registry.register(current_user.org_id, current_user.id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent", agent.id, "registered",
        {"name": agent.name, "agent_type": agent.agent_type},
    )
    return AgentCreated(
        **AgentOut.model_validate(agent).model_dump(),
        api_key=raw_key,
        private_key=private_key,
        pq_private_key=registry.generated_pq_private_key,
    )


@router.get("/delegation-hops/{hop_id}/verification")
async def hop_verification(
    hop_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Evidence for verifying a hop's signature without this server: the exact
    signed text, the Ed25519 signature and the public key that verified it,
    with that key's fingerprint and origin. A verifier checks the signature
    over `signed_message` and compares the fingerprint (computed on its own
    side) with the one the agent's owner holds - see docs/agent-signing.md.
    """
    from fastapi import HTTPException, status as st
    from app.models.delegation import DelegationHop

    result = await db.execute(
        select(DelegationHop).where(
            DelegationHop.id == hop_id, DelegationHop.org_id == current_user.org_id
        )
    )
    hop = result.scalar_one_or_none()
    if not hop:
        raise HTTPException(status_code=st.HTTP_404_NOT_FOUND, detail="Hop not found")

    reg = AgentRegistry(db)
    from_agent = await reg.get_agent(hop.from_agent_id, current_user.org_id)
    return await _evidence(db, "delegation_hop", hop.id, from_agent, hop.signed_payload, hop.signature,
                           hop.signer_public_key, bool(hop.verified),
                           pq_signature=hop.pq_signature, signer_pq_public_key=hop.signer_pq_public_key,
                           signed_at=hop.created_at)


async def _evidence(db, kind: str, record_id: int, agent, signed_payload, signature, signer_public_key,
                    server_verified: bool, pq_signature=None, signer_pq_public_key=None, signed_at=None) -> dict:
    """One self-contained, offline-verifiable evidence object (also what the
    UI offers as a download)."""
    from app.core.agent_signing import canonical_text, key_fingerprint, scheme_of
    from app.models.agent import AgentSigningKey

    # Only the key recorded when the signature was verified - never "the
    # agent's current key", which may not be the one that signed.
    key = signer_public_key
    origin = None
    if key:
        row = (await db.execute(
            select(AgentSigningKey).where(AgentSigningKey.public_key == key)
            .order_by(AgentSigningKey.created_at.desc()).limit(1)
        )).scalar_one_or_none()
        origin = row.origin if row else agent.key_origin
    from app.services import key_revocation

    rev = await key_revocation.for_signer(db, agent.org_id, key, signer_pq_public_key)
    return {
        "format": "provenza-signature-evidence/1",
        "record": kind,
        "record_id": record_id,
        "hop_id": record_id if kind == "delegation_hop" else None,
        "agent_id": agent.id,
        "agent_name": agent.name,
        "has_signature": bool(signature),
        # "ed25519", or "ed25519+ml-dsa-65" (hybrid: BOTH signatures must verify)
        "algorithm": scheme_of(signer_pq_public_key) if key else None,
        "signed_payload": signed_payload,
        # The exact ASCII text that was signed (canonical JSON). Verify the
        # signature over these bytes; do not re-serialize signed_payload.
        "signed_message": canonical_text(signed_payload) if signed_payload is not None else None,
        "signature": signature,
        "public_key": key,
        "pq_signature": pq_signature if signer_pq_public_key else None,
        "pq_public_key": signer_pq_public_key,
        # over the raw Ed25519 key, followed by the raw ML-DSA-65 key if hybrid
        "key_fingerprint": key_fingerprint(key, signer_pq_public_key),
        # The server's statement about where the key was made: "agent" = the
        # agent registered only the public key; "server" = generated here at
        # registration. A claim, like server_verified - not something a
        # verifier can check from the evidence itself.
        "key_origin": origin,
        "server_verified": server_verified,
        # when the server received the record - what revocation is judged against
        "signed_at": signed_at.isoformat() if signed_at else None,
        # the signing key's entry in the revocation list, if any; a signature
        # received at or after untrusted_from is not trusted even if it verifies
        "revocation": key_revocation.out(rev) if rev else None,
        "trusted": bool(server_verified and key_revocation.trusted_at(rev, signed_at)),
    }


@router.get("/actions/{action_id}/verification")
async def action_verification(
    action_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Same evidence as for a delegation hop, for a recorded agent action."""
    from fastapi import HTTPException, status as st
    from app.models.agent_action import AgentAction

    action = (await db.execute(
        select(AgentAction).where(AgentAction.id == action_id, AgentAction.org_id == current_user.org_id)
    )).scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=st.HTTP_404_NOT_FOUND, detail="Action not found")
    agent = await AgentRegistry(db).get_agent(action.agent_id, current_user.org_id)
    return await _evidence(db, "agent_action", action.id, agent, action.signed_payload, action.signature,
                           action.signer_public_key,
                           bool(action.signature and action.signed_payload and action.signer_public_key),
                           pq_signature=action.pq_signature, signer_pq_public_key=action.signer_pq_public_key,
                           signed_at=action.created_at)


@router.post("/{agent_id}/signing-key", response_model=AgentOut)
async def set_signing_key(
    agent_id: int,
    data: SigningKeyIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """
    Register the agent's own public key - Ed25519, plus ML-DSA-65 for a
    hybrid post-quantum key (the agent keeps the private keys; the server
    never sees them). Replaces the current key - e.g. moving
    off a server-generated one. Records already signed keep verifying with
    the key that signed them; the change is audited with both fingerprints.

    Nothing proves the agent holds this key, so this is allowed only where
    the organization allows direct registration. Otherwise: the agent
    rotates itself (/{agent_id}/signing-key/challenge + /rotate), or an admin
    issues a re-key enrollment token (purpose "rekey").
    """
    from app.services.agent_identity import org_settings

    if not (await org_settings(db, current_user.org_id)).get("allow_direct_registration"):
        from app.core.errors import api_error
        raise api_error(403, "agent.proof_required")
    agent, previous = await AgentRegistry(db).set_signing_key(agent_id, current_user.org_id,
                                                              data.public_key, current_user.id,
                                                              pq_public_key=data.pq_public_key)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent", agent.id, "signing_key_set",
        {"previous_fingerprint": previous, "fingerprint": AgentOut.model_validate(agent).key_fingerprint},
    )
    return agent


async def _self_agent(request, agent_id: int, current_user: User):
    """Key rotation is the agent's own act: only with its own key (X-Agent-Key)."""
    from fastapi import HTTPException

    agent = getattr(request.state, "agent", None)
    if agent is None or agent.id != agent_id or agent.org_id != current_user.org_id:
        raise HTTPException(status_code=403, detail="agent_identity.agent_key_required: an agent rotates its own "
                                                    "key, authenticated with its own key (X-Agent-Key)")
    return agent


@router.post("/{agent_id}/signing-key/challenge")
async def rotation_challenge(
    agent_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """A fresh single-use challenge for rotating the agent's signing key."""
    from app.services import enrollment

    agent = await AgentRegistry(db).get_agent((await _self_agent(request, agent_id, current_user)).id,
                                              current_user.org_id)
    return await enrollment.rotation_challenge(db, agent)


@router.post("/{agent_id}/signing-key/rotate", response_model=AgentOut)
async def rotate_signing_key(
    agent_id: int,
    data: RotateIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Rotate to a new signing key: the rotation statement (challenge, old
    fingerprint, new keys) signed by the CURRENT key - consent - and by the
    NEW key - possession (services/enrollment.py)."""
    from app.services import enrollment

    agent = await AgentRegistry(db).get_agent((await _self_agent(request, agent_id, current_user)).id,
                                              current_user.org_id)
    return await enrollment.rotate(
        db, agent, new_public_key=data.new_public_key, new_pq_public_key=data.new_pq_public_key,
        challenge_value=data.challenge, old_signature=data.old_signature, old_pq_signature=data.old_pq_signature,
        new_signature=data.new_signature, new_pq_signature=data.new_pq_signature)


ATTEST_LIMIT = 30    # challenges + attempts per agent ...
ATTEST_WINDOW = 600  # ... per 10 minutes (an agent attests every few minutes at most)


@router.post("/{agent_id}/attestation/challenge")
async def attestation_challenge(
    agent_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """A fresh single-use challenge for proving where the agent runs
    (services/attestation.py). Only the agent itself, with its own key."""
    from app.core import rate_limit
    from app.services import attestation

    agent = await AgentRegistry(db).get_agent((await _self_agent(request, agent_id, current_user)).id,
                                              current_user.org_id)
    # counted only once the caller is the agent itself: nobody else can use up its budget
    rate_limit.enforce(request, scope="attest", limit=ATTEST_LIMIT, window_seconds=ATTEST_WINDOW,
                       extra_key=f"agent:{agent.org_id}:{agent.id}")
    return await attestation.challenge(db, agent)


@router.post("/{agent_id}/attestation")
async def attest(
    agent_id: int,
    data: AttestIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """The agent's evidence, signed with its key over the challenge. Answers
    200 with ok true/false and the reason; every attempt is recorded and
    audited (refusals before the evidence is checked too)."""
    from app.core import rate_limit
    from app.services import attestation

    agent = await AgentRegistry(db).get_agent((await _self_agent(request, agent_id, current_user)).id,
                                              current_user.org_id)
    # counted only once the caller is the agent itself: nobody else can use up its budget
    rate_limit.enforce(request, scope="attest", limit=ATTEST_LIMIT, window_seconds=ATTEST_WINDOW,
                       extra_key=f"agent:{agent.org_id}:{agent.id}")
    result = await attestation.attest(db, agent, challenge_value=data.challenge, kind=data.kind,
                                      evidence=data.evidence, signature=data.signature,
                                      pq_signature=data.pq_signature)
    await AuditService(db).log(current_user.org_id, None, "agent", agent_id,
                               "attested" if result["ok"] else "attestation_failed",
                               {k: result[k] for k in ("id", "policy", "kind", "ok", "reason", "identity",
                                                       "valid_until")})
    return result


@router.get("/{agent_id}/signing-keys", response_model=List[SigningKeyOut])
async def list_signing_keys(
    agent_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Every signing key the agent has had, newest first."""
    return await AgentRegistry(db).signing_keys(agent_id, current_user.org_id)


@router.get("/key-revocations")
async def key_revocations(
    agent_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """The organization's revocation list of agent signing keys (append-only;
    every entry is also an audit record - entity "agent_key_revocation" - so
    an audit proof shows it is part of the signed log)."""
    from app.services import key_revocation

    return [key_revocation.out(r) for r in await key_revocation.list_for(db, current_user.org_id, agent_id)]


@router.post("/{agent_id}/signing-keys/{key_id}/revoke")
async def revoke_signing_key(
    agent_id: int,
    key_id: int,
    data: KeyRevokeIn,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Revoke one of the agent's signing keys. Revoking the current key leaves
    the agent without one until it registers a new key."""
    from app.services import key_revocation

    rev = await key_revocation.revoke(db, current_user.org_id, agent_id, key_id, current_user.id,
                                      data.reason, data.compromised_since)
    return key_revocation.out(rev)


@router.get("/graph", response_model=GovernanceGraph)
async def governance_graph(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    The live governance map in one query: agents (nodes) with status,
    violation, and recent-activity annotations; delegation hops (edges)
    with verification and violation state. Polled by the graph UI.
    """
    graph = await GovernanceGraphService(db).build(current_user.org_id)
    return graph


@router.get("/", response_model=Page[AgentOut])
async def list_agents(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    registry = AgentRegistry(db)
    items, total = await registry.list_agents(current_user.org_id, pagination.skip, pagination.limit)
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@router.get("/{agent_id}", response_model=AgentOut)
async def get_agent(
    agent_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await AgentRegistry(db).get_agent(agent_id, current_user.org_id)


@router.put("/{agent_id}", response_model=AgentOut)
async def update_agent(
    agent_id: int,
    data: AgentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    agent = await AgentRegistry(db).update_agent(agent_id, current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent", agent_id, "updated",
        data.model_dump(exclude_unset=True),
    )
    return agent


@router.put("/{agent_id}/assignment", response_model=AgentOut)
async def assign_agent(
    agent_id: int,
    data: AgentAssignment,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Put the agent in a team and give it a role template (null clears either).
    With a role, the agent's rights become the role's and follow it."""
    from app.services import teams

    agent = await AgentRegistry(db).get_agent(agent_id, current_user.org_id)
    before = {"team_id": agent.team_id, "role_id": agent.role_id}
    await teams.assign(db, current_user.org_id, agent, data.team_id, data.role_id)
    from app.services import kill_switch

    held = await kill_switch.hold_new_agent(db, agent)  # moved into a stopped team: it stops too
    await AuditService(db).log(current_user.org_id, current_user.id, "agent", agent_id, "assignment_changed",
                               {"before": before, "after": {"team_id": agent.team_id, "role_id": agent.role_id},
                                **({"kill_switch_event_id": held.id} if held else {})})
    await db.refresh(agent)
    return agent


@router.post("/{agent_id}/kill", response_model=AgentKillResponse)
async def kill_agent(
    agent_id: int,
    data: AgentKillRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Stop one agent: a kill-switch event at agent level (see /kill-switch)."""
    from app.services import kill_switch

    reg = AgentRegistry(db)
    stopped, terminated = await reg.kill_agent(
        agent_id, current_user.org_id, data.reason, data.cascade, user_id=current_user.id, commit=False
    )  # committed with its audit record
    event = reg.last_event
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent", agent_id, "killed",
        {"reason": data.reason, "cascade": data.cascade, "chains_terminated": terminated,
         "kill_switch_event_id": event.id},
    )
    await kill_switch.notify(db, event, lifted=False)
    return AgentKillResponse(agents_stopped=stopped, chains_terminated=terminated, event_id=event.id)


# ========================= Delegation =========================

# Replay protection for signed delegations
DELEGATION_MAX_AGE_SECONDS = 300     # reject requests older than 5 minutes
DELEGATION_CLOCK_SKEW_SECONDS = 30   # tolerate small clock drift


@router.post("/{agent_id}/delegate", response_model=DelegateResponse)
async def delegate(
    agent_id: int,
    data: DelegateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Record a delegation from `agent_id` to `to_agent_id`. If a signature
    is supplied, it is verified against the delegating agent's public key
    over the canonical delegation payload; an invalid signature is
    rejected before any chain state changes.
    """
    service = DelegationService(db)
    registry = AgentRegistry(db)

    # The canonical payload that the delegating agent signs. Built the
    # same way regardless of whether a signature was supplied, and stored
    # on the hop so offline verification reconstructs nothing.
    signed_payload = {
        "from_agent_id": agent_id,
        "to_agent_id": data.to_agent_id,
        "task": data.task,
        "delegated_capabilities": sorted(data.delegated_capabilities or []),
        "chain_id": data.chain_id,
        "nonce": data.nonce,
        "issued_at": data.issued_at,
        "expires_in": data.expires_in,
    }
    if data.delegated_tools is not None:
        # signed only when sent, so payloads of agents that do not delegate tools stay as they were
        signed_payload["delegated_tools"] = sorted(set(data.delegated_tools))

    from fastapi import HTTPException, status as st
    from sqlalchemy.exc import IntegrityError
    from app.models.delegation import DelegationNonce

    from_agent = await registry.get_agent(agent_id, current_user.org_id)
    now = datetime.now(timezone.utc)

    # 0. Only an active agent acts, and - unless the organization allows
    #    keyless agents - only one that can sign.
    if from_agent.status != "active":
        raise HTTPException(status_code=st.HTTP_409_CONFLICT,
                            detail=f"delegation.agent_not_active: agent {from_agent.id} is {from_agent.status}")
    if await keyless_refused(db, from_agent):
        raise HTTPException(status_code=st.HTTP_403_FORBIDDEN, detail="agent.key_required")

    # 1. An agent with a registered public key MUST sign its delegations.
    #    Keyless agents (only where the organization allows them) delegate unsigned.
    if from_agent.public_key and not data.signature:
        raise HTTPException(
            status_code=st.HTTP_401_UNAUTHORIZED,
            detail="This agent has a registered public key; delegations must be signed",
        )

    # 1b. With require_pq_signatures on, only a hybrid key may delegate
    #     (an Ed25519-only key or no key at all is refused).
    if await pq_signature_required(db, from_agent):
        raise HTTPException(status_code=st.HTTP_403_FORBIDDEN, detail="agent.pq_required")
    await _attested(db, from_agent)

    # 2. A signed delegation must carry replay-protection fields.
    if data.signature and (not data.nonce or data.issued_at is None):
        raise HTTPException(
            status_code=st.HTTP_400_BAD_REQUEST,
            detail="Signed delegations must include nonce and issued_at",
        )

    # 3. Signature over the canonical payload (which includes nonce + issued_at).
    verified = False
    if data.signature:
        # Ed25519 AND, for a hybrid agent, ML-DSA-65 over the same bytes
        verified = verify_agent_signature(signed_payload, data.signature, data.pq_signature,
                                          from_agent.public_key, from_agent.pq_public_key)
        if not verified:
            raise HTTPException(
                status_code=st.HTTP_400_BAD_REQUEST,
                detail="Invalid delegation signature",
            )

    # 4. Freshness window: an old signed request cannot be replayed later.
    if data.issued_at is not None:
        age = now.timestamp() - data.issued_at
        if age > DELEGATION_MAX_AGE_SECONDS:
            raise HTTPException(
                status_code=st.HTTP_400_BAD_REQUEST,
                detail=f"Delegation request is stale (issued {int(age)}s ago, max {DELEGATION_MAX_AGE_SECONDS}s)",
            )
        if age < -DELEGATION_CLOCK_SKEW_SECONDS:
            raise HTTPException(
                status_code=st.HTTP_400_BAD_REQUEST,
                detail="Delegation issued_at is in the future",
            )

    # 5. Single-use nonce, enforced by a unique constraint.
    if data.nonce:
        db.add(DelegationNonce(org_id=current_user.org_id, from_agent_id=agent_id, nonce=data.nonce))
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            raise HTTPException(
                status_code=st.HTTP_409_CONFLICT,
                detail="Replayed delegation: nonce already used",
            )

    # TTL counts from the signed issued_at, not from server receive time,
    # so a late resend can never extend a delegation's lifetime.
    expires_at = None
    if data.expires_in:
        base = datetime.fromtimestamp(data.issued_at, tz=timezone.utc) if data.issued_at is not None else now
        expires_at = base + timedelta(seconds=data.expires_in)

    if data.chain_id is not None:
        from app.services.circuit_breaker import CircuitBreaker
        await CircuitBreaker(db).evaluate(current_user.org_id, data.chain_id)
    chain, hop = await service.delegate(
        org_id=current_user.org_id,
        from_agent_id=agent_id,
        to_agent_id=data.to_agent_id,
        task=data.task,
        delegated_capabilities=data.delegated_capabilities or [],
        signature=data.signature,
        chain_id=data.chain_id,
        expires_at=expires_at,
        signed_payload=signed_payload if data.signature else None,
        signer_public_key=from_agent.public_key if data.signature else None,
        pq_signature=data.pq_signature if data.signature and from_agent.pq_public_key else None,
        signer_pq_public_key=from_agent.pq_public_key if data.signature else None,
        delegated_tools=data.delegated_tools,
        verified=verified,
    )
    from app.services.agent_rights import hop_rights

    to_agent = await registry.get_agent(data.to_agent_id, current_user.org_id)
    root = await registry.get_agent(chain.root_agent_id, current_user.org_id)
    # how much deeper the RECEIVER may still delegate: its own and the root's limit
    remaining = max(min(to_agent.max_delegation_depth, root.max_delegation_depth) - hop.depth, 0)
    effective = hop_rights(to_agent, hop)
    return DelegateResponse(
        chain_id=chain.id, hop_id=hop.id, depth=hop.depth,
        max_depth_remaining=remaining, verified=verified,
        effective_capabilities=effective.capabilities, effective_tools=effective.tools,
    )


@router.get("/delegation-chains/", response_model=Page[ChainOut])
async def list_chains(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items, total = await DelegationService(db).list_chains(
        current_user.org_id, pagination.skip, pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


@router.get("/delegation-chains/{chain_id}", response_model=ChainDetail)
async def get_chain(
    chain_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    detail = await DelegationService(db).get_chain_detail(chain_id, current_user.org_id)
    chain = detail["chain"]
    return ChainDetail(
        **ChainOut.model_validate(chain).model_dump(),
        hops=[HopOut.model_validate(h) for h in detail["hops"]],
    )


# ========================== Actions ==========================

async def _attested(db: AsyncSession, agent) -> None:
    """Agents of a role that requires attestation act only with a current
    one - also when a user session acts in their name (relaxed organizations)."""
    from fastapi import HTTPException, status as st

    from app.services.attestation import refusal

    code = await refusal(db, agent)
    if code:
        raise HTTPException(status_code=st.HTTP_403_FORBIDDEN, detail=code)


@router.post("/actions/check", response_model=ActionCheckResponse)
async def check_action_endpoint(
    data: ActionCheckRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Run the policy engine for a proposed action and issue a single-use
    check_id bound to exactly this action (agent, chain, tool, input hash,
    capabilities, verdict). /actions/record must present it, so what gets
    recorded is provably the action that was checked.
    """
    checked = (await db.execute(select(Agent).where(
        Agent.id == data.agent_id, Agent.org_id == current_user.org_id))).scalar_one_or_none()
    if checked is not None:
        await _attested(db, checked)
    if data.chain_id is not None:
        # ASI08: trip the chain first if prior events crossed a threshold,
        # so this very request is already refused
        from app.services.circuit_breaker import CircuitBreaker
        await CircuitBreaker(db).evaluate(current_user.org_id, data.chain_id)
    # ASI10: score the agent against its behavioural baseline first, so a
    # quarantine decided now already applies to this very request
    from app.services.behavior_monitor import BehaviorMonitor
    await BehaviorMonitor(db).evaluate(current_user.org_id, data.agent_id, data.tool_name)
    audit = AgentAudit(db)
    decision = await audit.check(
        org_id=current_user.org_id,
        agent_id=data.agent_id,
        chain_id=data.chain_id,
        action_type=data.action_type,
        tool_name=data.tool_name,
        input_data=data.input,
        tool_version=data.tool_version,
        tool_digest=data.tool_digest,
    )
    chk = await audit.issue_check(
        org_id=current_user.org_id,
        agent_id=data.agent_id,
        chain_id=data.chain_id,
        action_type=data.action_type,
        tool_name=data.tool_name,
        input_data=data.input,
        action_capabilities=decision.required_capabilities,
        decision=decision,
    )
    return ActionCheckResponse(
        decision=decision.result, reason=decision.reason,
        incident_type=decision.incident_type, policy_id=decision.matched_policy_id,
        check_id=chk.token, expires_at=chk.expires_at,
    )


@router.post("/actions/record", response_model=ActionOut)
async def record_action_endpoint(
    data: ActionRecordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Persist an action together with its policy verdict.

    Agents with a registered key (every agent created via /register) must:
      1. call /actions/check first and receive a single-use check_id,
      2. present that check_id here, for exactly the same action,
      3. sign {check_id, agent_id, chain_id, action_type, tool_name,
         input_sha256, output_sha256} with their Ed25519 key.
    The stored verdict is the one issued at check time. Recording a
    different action than the checked one raises an `action_mismatch`
    incident. Keyless agents keep the cooperative path (verdict computed
    here, from the capabilities the Tool Registry requires).
    """
    from fastapi import HTTPException, status as st
    from app.core.agent_signing import content_hash, verify_payload

    audit = AgentAudit(db)
    agent = await AgentRegistry(db).get_agent(data.agent_id, current_user.org_id)

    if await keyless_refused(db, agent):
        raise HTTPException(status_code=st.HTTP_403_FORBIDDEN, detail="agent.key_required")
    if agent.public_key and not data.check_id:
        raise HTTPException(
            status_code=st.HTTP_401_UNAUTHORIZED,
            detail="This agent has a registered public key; record requires a check_id from /actions/check",
        )
    if agent.public_key and not data.signature:
        raise HTTPException(
            status_code=st.HTTP_401_UNAUTHORIZED,
            detail="This agent has a registered public key; actions must be signed",
        )
    if await pq_signature_required(db, agent):
        raise HTTPException(status_code=st.HTTP_403_FORBIDDEN, detail="agent.pq_required")
    await _attested(db, agent)

    check = None
    signed_payload = None
    if data.check_id:
        signed_payload = {
            "check_id": data.check_id,
            "agent_id": data.agent_id,
            "chain_id": data.chain_id,
            "action_type": data.action_type,
            "tool_name": data.tool_name,
            "input_sha256": content_hash(data.input or {}),
            "output_sha256": content_hash(data.output),
        }
        # Verify BEFORE consuming the check, so a forged request cannot
        # burn a legitimate check_id.
        if data.signature and not verify_agent_signature(signed_payload, data.signature, data.pq_signature,
                                                         agent.public_key, agent.pq_public_key):
            raise HTTPException(status_code=st.HTTP_400_BAD_REQUEST, detail="Invalid action signature")
        check, decision = await audit.consume_check(
            current_user.org_id, data.check_id,
            agent_id=data.agent_id, chain_id=data.chain_id, action_type=data.action_type,
            tool_name=data.tool_name, input_data=data.input,
        )
    else:
        decision = await audit.check(
            org_id=current_user.org_id,
            agent_id=data.agent_id,
            chain_id=data.chain_id,
            action_type=data.action_type,
            tool_name=data.tool_name,
            input_data=data.input,
        )

    verified = bool(check and data.signature)
    action = await audit.record(
        org_id=current_user.org_id,
        agent_id=data.agent_id,
        chain_id=data.chain_id,
        action_type=data.action_type,
        tool_name=data.tool_name,
        input_data=data.input,
        output_data=data.output,
        signature=data.signature if verified else None,
        duration_ms=data.duration_ms,
        decision=decision,
        check_id=check.id if check else None,
        signed_payload=signed_payload if verified else None,
        signer_public_key=agent.public_key if verified else None,
        pq_signature=data.pq_signature if verified and agent.pq_public_key else None,
        signer_pq_public_key=agent.pq_public_key if verified else None,
    )
    # ASI01: an instruction hidden in the tool output (indirect injection);
    # before the breaker, so it already counts the new incident
    from app.services.injection_guard import InjectionGuard
    await InjectionGuard(db).scan_output(current_user.org_id, data.agent_id, data.chain_id,
                                         getattr(action, "id", None), data.tool_name, data.output)
    if data.chain_id is not None:
        from app.services.circuit_breaker import CircuitBreaker
        await CircuitBreaker(db).evaluate(current_user.org_id, data.chain_id)
    return action


@router.get("/actions/", response_model=Page[ActionOut])
async def list_actions(
    chain_id: Optional[int] = None,
    agent_id: Optional[int] = None,
    result: Optional[str] = None,
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items, total = await AgentAudit(db).list_actions(
        current_user.org_id, chain_id, agent_id, result, pagination.skip, pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


from app.schemas.agent import ApprovalDecision  # noqa: E402  (ASI09)
from app.services.agent_approval_service import AgentApprovalService  # noqa: E402


@router.get("/approvals/pending")
async def pending_approvals(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    """Actions waiting for a human, oldest first. Expired ones are denied first."""
    return await AgentApprovalService(db).pending(current_user.org_id)


@router.get("/actions/{action_id}/review")
async def review_action(
    action_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    """Everything a reviewer needs, with server-verified facts kept apart from
    text written by agents (ASI09)."""
    return await AgentApprovalService(db).review(current_user.org_id, action_id, current_user)


@router.post("/actions/{action_id}/approve", response_model=ActionOut)
async def approve_action(
    action_id: int,
    data: ApprovalDecision,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    service = AgentApprovalService(db)
    result = await service.approve(current_user.org_id, action_id, current_user,
                                   data.input_sha256, data.confirmation)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent_action", action_id, "approved",
        {"input_sha256": data.input_sha256, **result},
    )
    return await service._action(current_user.org_id, action_id)


@router.post("/actions/{action_id}/deny", response_model=ActionOut)
async def deny_action(
    action_id: int,
    data: ActionDenyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin, UserRole.approver)),
):
    service = AgentApprovalService(db)
    await service.deny(current_user.org_id, action_id, current_user, None, data.reason)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent_action", action_id, "denied", {"reason": data.reason},
    )
    return await service._action(current_user.org_id, action_id)

@router.post("/policies/", response_model=AgentPolicyOut)
async def create_agent_policy(
    data: AgentPolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    policy = AgentPolicy(
        org_id=current_user.org_id,
        agent_id=data.agent_id,
        name=data.name,
        rules=data.rules,
        priority=data.priority,
        enabled=data.enabled,
        created_by=current_user.id,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "agent_policy", policy.id, "created",
        {"name": policy.name, "agent_id": policy.agent_id},
    )
    return policy


@router.get("/policies/", response_model=Page[AgentPolicyOut])
async def list_agent_policies(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from sqlalchemy import func as sqlfunc
    base = select(AgentPolicy).where(AgentPolicy.org_id == current_user.org_id)
    total = await db.scalar(select(sqlfunc.count()).select_from(base.subquery()))
    result = await db.execute(
        base.order_by(AgentPolicy.priority.desc()).offset(pagination.skip).limit(pagination.limit)
    )
    return Page(items=list(result.scalars().all()), total=int(total or 0),
                skip=pagination.skip, limit=pagination.limit)


# ========================== Incidents ==========================

@router.get("/incidents/escalation-summary")
async def escalation_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Per-agent count of capability-escalation attempts, worst first.
    Answers 'which sub-agent keeps trying to escalate?' — the repeat-offender
    view. A high count is a candidate for auto-review or kill-switch."""
    from sqlalchemy import func as sqlfunc
    result = await db.execute(
        select(
            AgentIncident.agent_id,
            sqlfunc.count().label("attempts"),
            sqlfunc.max(AgentIncident.created_at).label("last_attempt"),
        )
        .where(
            AgentIncident.org_id == current_user.org_id,
            AgentIncident.incident_type == "capability_escalation",
        )
        .group_by(AgentIncident.agent_id)
        .order_by(sqlfunc.count().desc())
    )
    rows = result.all()
    return {
        "agents": [
            {"agent_id": r.agent_id, "attempts": int(r.attempts),
             "last_attempt": r.last_attempt.isoformat() if r.last_attempt else None}
            for r in rows
        ]
    }


@router.get("/incidents/", response_model=Page[AgentIncidentOut])
async def list_agent_incidents(
    pagination: PaginationParams = Depends(),
    incident_type: str | None = None,
    unresolved_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from sqlalchemy import func as sqlfunc
    base = select(AgentIncident).where(AgentIncident.org_id == current_user.org_id)
    if incident_type:
        base = base.where(AgentIncident.incident_type == incident_type)
    if unresolved_only:
        base = base.where(AgentIncident.resolved == False)  # noqa: E712
    total = await db.scalar(select(sqlfunc.count()).select_from(base.subquery()))
    result = await db.execute(
        base.order_by(AgentIncident.created_at.desc()).offset(pagination.skip).limit(pagination.limit)
    )
    return Page(items=list(result.scalars().all()), total=int(total or 0),
                skip=pagination.skip, limit=pagination.limit)
