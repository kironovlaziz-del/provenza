# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVPOrchestrator - the one place where agent governance decides (docs/pvp/spec.md).

It understands only PVP messages. Adapters (the REST endpoints in
app/api/agents.py today; MCP and A2A next) turn their protocol into a PVP
message, call the orchestrator and turn the result back. Nothing here knows
which protocol a request came in on, so every protocol gets exactly the same
checks in exactly the same order.

  check(request)     identity / attestation -> circuit breaker -> behaviour
                     baseline -> policy engine (+ supply chain, ASI01, ASI05)
                     -> single-use check bound to the action
  record(record)     key required -> check_id + signature required ->
                     attestation -> signature verified BEFORE the check is
                     burned -> check consumed (same action only) -> stored
                     with the check-time verdict -> output scanned (ASI01)
  delegate(d)        active + keyed -> signed -> PQ rule -> attestation ->
                     signature -> freshness -> single-use nonce -> TTL from
                     the signed issued_at -> rights subset, depth, TTL never
                     beyond the parent's (DelegationService)

Errors are HTTPException with the codes the API has always returned; the
caller is authenticated before it gets here (app/api/deps.py), and an agent
key can only act as its own agent (services/agent_identity.py).
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import verify_agent_signature
from app.models.agent import Agent
from app.models.agent_action import ActionCheck, AgentAction
from app.models.delegation import ActionNonce, DelegationChain, DelegationHop, DelegationNonce
from app.pvp.model import PVPAction, PVPActionRecord, PVPActionRequest, PVPCheck, PVPDelegation
from app.pvp import permits
from app.services.agent_audit import AgentAudit
from app.services.agent_policy_engine import DENIED, Decision
from app.services.agent_identity import keyless_refused, pq_signature_required
from app.services.agent_registry import AgentRegistry
from app.services.delegation_service import DelegationService

# Replay protection for signed delegations
DELEGATION_MAX_AGE_SECONDS = 300     # reject requests older than 5 minutes
DELEGATION_CLOCK_SKEW_SECONDS = 30   # tolerate small clock drift
# the same window for signed action requests (/agents/actions/check)
SIGNED_REQUEST_MAX_AGE_SECONDS = DELEGATION_MAX_AGE_SECONDS
SIGNED_REQUEST_CLOCK_SKEW_SECONDS = DELEGATION_CLOCK_SKEW_SECONDS


def _unix(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


async def require_attestation(db: AsyncSession, agent: Agent) -> None:
    """Agents of a role that requires attestation act only with a current
    one - also when a user session acts in their name (relaxed organizations)."""
    from app.services.attestation import refusal

    code = await refusal(db, agent)
    if code:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=code)


@dataclass
class Delegated:
    """What a delegation produced: the chain and hop, and what the receiving
    agent may actually do there."""
    chain: DelegationChain
    hop: DelegationHop
    verified: bool
    max_depth_remaining: int
    effective_capabilities: List[str] = field(default_factory=list)
    effective_tools: List[str] = field(default_factory=list)


class PVPOrchestrator:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------ actions

    async def check(self, org_id: int, req: PVPActionRequest, *, require_signature: bool = False) -> PVPCheck:
        """Run the policy engine for a proposed action and issue a single-use
        check bound to exactly this action (agent, chain, tool, input hash,
        capabilities, verdict).

        require_signature: the caller is the agent itself (its own key), so
        the request must carry the agent's signature over
        req.signed_payload(), fresh and with a nonce never used before. A
        signature sent where it is not required is verified all the same.
        Gateways and the egress proxy call without it: they are the witness."""
        checked = (await self.db.execute(select(Agent).where(
            Agent.id == req.agent_id, Agent.org_id == org_id))).scalar_one_or_none()
        if checked is not None:
            if await keyless_refused(self.db, checked):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent.key_required")
            if require_signature or req.signature:
                await self._verify_request(org_id, checked, req)
            await require_attestation(self.db, checked)
        elif require_signature:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent.not_found")
        if req.chain_id is not None:
            # ASI08: trip the chain first if prior events crossed a threshold,
            # so this very request is already refused
            from app.services.circuit_breaker import CircuitBreaker
            await CircuitBreaker(self.db).evaluate(org_id, req.chain_id)
        # ASI10: score the agent against its behavioural baseline first, so a
        # quarantine decided now already applies to this very request
        from app.services.behavior_monitor import BehaviorMonitor
        await BehaviorMonitor(self.db).evaluate(org_id, req.agent_id, req.tool_name)
        audit = AgentAudit(self.db)
        decision = await audit.check(
            org_id=org_id, agent_id=req.agent_id, chain_id=req.chain_id, action_type=req.action_type,
            tool_name=req.tool_name, input_data=req.input,
            tool_version=req.tool_version, tool_digest=req.tool_digest,
        )
        chk = await audit.issue_check(
            org_id=org_id, agent_id=req.agent_id, chain_id=req.chain_id, action_type=req.action_type,
            tool_name=req.tool_name, input_data=req.input,
            action_capabilities=decision.required_capabilities, decision=decision,
        )
        permit = None
        if chk.decision == "allowed":
            permit = await permits.issue(self.db, chk)
            await self.db.commit()
        return self.check_out(chk, permit)

    async def _verify_request(self, org_id: int, agent: Agent, req: PVPActionRequest) -> None:
        """Signature (both halves for a hybrid key), freshness, single-use nonce
        - in that order, so a forged request cannot burn a nonce."""
        if not req.signature or not req.nonce or req.issued_at is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="action.signature_required")
        if await pq_signature_required(self.db, agent):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent.pq_required")
        if not verify_agent_signature(req.signed_payload(), req.signature, req.pq_signature,
                                      agent.public_key, agent.pq_public_key):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="action.invalid_signature")
        age = datetime.now(timezone.utc).timestamp() - req.issued_at
        if age > SIGNED_REQUEST_MAX_AGE_SECONDS or age < -SIGNED_REQUEST_CLOCK_SKEW_SECONDS:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="action.stale_request")
        try:
            async with self.db.begin_nested():   # a replay undoes only this insert
                self.db.add(ActionNonce(org_id=org_id, agent_id=agent.id, nonce=req.nonce))
                await self.db.flush()
        except IntegrityError:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="action.replayed_request")

    async def record(self, org_id: int, rec: PVPActionRecord) -> AgentAction:
        """Persist an action with its policy verdict. Agents with a key must
        present the check_id from check() for exactly this action and sign
        rec.signed_payload(); the stored verdict is the one from check time.
        Keyless agents (only where the organization allows them) keep the
        cooperative path: the verdict is computed here."""
        audit = AgentAudit(self.db)
        agent = await AgentRegistry(self.db).get_agent(rec.agent_id, org_id)

        if await keyless_refused(self.db, agent):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent.key_required")
        if agent.public_key and not rec.check_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This agent has a registered public key; record requires a check_id from /actions/check",
            )
        if agent.public_key and not rec.signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This agent has a registered public key; actions must be signed",
            )
        if await pq_signature_required(self.db, agent):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent.pq_required")
        await require_attestation(self.db, agent)

        check = None
        signed_payload = None
        if rec.check_id:
            signed_payload = rec.signed_payload()
            # Verify BEFORE consuming the check, so a forged request cannot
            # burn a legitimate check_id.
            if rec.signature and not verify_agent_signature(signed_payload, rec.signature, rec.pq_signature,
                                                            agent.public_key, agent.pq_public_key):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid action signature")
            check, decision = await audit.consume_check(
                org_id, rec.check_id,
                agent_id=rec.agent_id, chain_id=rec.chain_id, action_type=rec.action_type,
                tool_name=rec.tool_name, input_data=rec.input,
            )
        else:
            decision = await audit.check(
                org_id=org_id, agent_id=rec.agent_id, chain_id=rec.chain_id, action_type=rec.action_type,
                tool_name=rec.tool_name, input_data=rec.input,
            )

        verified = bool(check and rec.signature)
        action = await audit.record(
            org_id=org_id, agent_id=rec.agent_id, chain_id=rec.chain_id, action_type=rec.action_type,
            tool_name=rec.tool_name, input_data=rec.input, output_data=rec.output,
            signature=rec.signature if verified else None,
            duration_ms=rec.duration_ms,
            decision=decision,
            check_id=check.id if check else None,
            signed_payload=signed_payload if verified else None,
            signer_public_key=agent.public_key if verified else None,
            pq_signature=rec.pq_signature if verified and agent.pq_public_key else None,
            signer_pq_public_key=agent.pq_public_key if verified else None,
            check_token=rec.check_id if check else None,
        )
        # ASI01: an instruction hidden in the tool output (indirect injection);
        # before the breaker, so it already counts the new incident
        from app.services.injection_guard import InjectionGuard
        await InjectionGuard(self.db).scan_output(org_id, rec.agent_id, rec.chain_id,
                                                  getattr(action, "id", None), rec.tool_name, rec.output)
        if rec.chain_id is not None:
            from app.services.circuit_breaker import CircuitBreaker
            await CircuitBreaker(self.db).evaluate(org_id, rec.chain_id)
        return action

    async def record_executed(self, org_id: int, check: PVPCheck, *, input_data: dict,
                              output: Optional[dict], duration_ms: Optional[int], executed_by: str,
                              refusal: Optional[str] = None) -> Tuple[AgentAction, Optional[dict]]:
        """Record an action Provenza performed itself (the MCP gateway): the
        check is consumed exactly as for an agent's record - same action
        only, once - and the row says who executed it. There is no agent
        signature; the gateway is the witness. `refusal` records a call the
        executor refused after the check (e.g. the tool changed upstream) as
        denied with that reason. Returns the action and the ASI01 output
        report (None when clean), so the executor can withhold a poisoned
        output."""
        audit = AgentAudit(self.db)
        chk, decision = await audit.consume_check(
            org_id, check.check_id, agent_id=check.agent_id, chain_id=check.chain_id,
            action_type=check.action_type, tool_name=check.tool_name, input_data=input_data,
        )
        if refusal:
            decision = Decision(DENIED, refusal, None, matched_policy_id=decision.matched_policy_id)
        action = await audit.record(
            org_id=org_id, agent_id=check.agent_id, chain_id=check.chain_id, action_type=check.action_type,
            tool_name=check.tool_name, input_data=input_data, output_data=output, signature=None,
            duration_ms=duration_ms, decision=decision, check_id=chk.id, executed_by=executed_by,
            check_token=check.check_id,
        )
        report = None
        if output is not None:
            from app.services.injection_guard import InjectionGuard
            report = await InjectionGuard(self.db).scan_output(org_id, check.agent_id, check.chain_id,
                                                               action.id, check.tool_name, output)
        if check.chain_id is not None:
            from app.services.circuit_breaker import CircuitBreaker
            await CircuitBreaker(self.db).evaluate(org_id, check.chain_id)
        return action, report

    # --------------------------------------------------------- delegation

    async def delegate(self, org_id: int, d: PVPDelegation) -> Delegated:
        """Record a delegation. If signed, the signature is verified against
        the delegating agent's key over d.signed_payload(); an invalid
        signature is rejected before any chain state changes."""
        registry = AgentRegistry(self.db)
        signed_payload = d.signed_payload()

        from_agent = await registry.get_agent(d.from_agent_id, org_id)
        now = datetime.now(timezone.utc)

        # 0. Only an active agent acts, and - unless the organization allows
        #    keyless agents - only one that can sign.
        if from_agent.status != "active":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"delegation.agent_not_active: agent {from_agent.id} is {from_agent.status}")
        if await keyless_refused(self.db, from_agent):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent.key_required")

        # 1. An agent with a registered public key MUST sign its delegations.
        #    Keyless agents (only where the organization allows them) delegate unsigned.
        if from_agent.public_key and not d.signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This agent has a registered public key; delegations must be signed",
            )

        # 1b. With require_pq_signatures on, only a hybrid key may delegate
        #     (an Ed25519-only key or no key at all is refused).
        if await pq_signature_required(self.db, from_agent):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent.pq_required")
        await require_attestation(self.db, from_agent)

        # 2. A signed delegation must carry replay-protection fields.
        if d.signature and (not d.nonce or d.issued_at is None):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signed delegations must include nonce and issued_at",
            )

        # 3. Signature over the canonical payload (which includes nonce + issued_at).
        verified = False
        if d.signature:
            # Ed25519 AND, for a hybrid agent, ML-DSA-65 over the same bytes
            verified = verify_agent_signature(signed_payload, d.signature, d.pq_signature,
                                              from_agent.public_key, from_agent.pq_public_key)
            if not verified:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid delegation signature")

        # 4. Freshness window: an old signed request cannot be replayed later.
        if d.issued_at is not None:
            age = now.timestamp() - d.issued_at
            if age > DELEGATION_MAX_AGE_SECONDS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Delegation request is stale (issued {int(age)}s ago, max {DELEGATION_MAX_AGE_SECONDS}s)",
                )
            if age < -DELEGATION_CLOCK_SKEW_SECONDS:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="Delegation issued_at is in the future")

        # 5. Single-use nonce, enforced by a unique constraint.
        if d.nonce:
            self.db.add(DelegationNonce(org_id=org_id, from_agent_id=d.from_agent_id, nonce=d.nonce))
            try:
                await self.db.flush()
            except IntegrityError:
                await self.db.rollback()
                raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                    detail="Replayed delegation: nonce already used")

        # TTL counts from the signed issued_at, not from server receive time,
        # so a late resend can never extend a delegation's lifetime.
        expires_at = None
        if d.expires_in:
            base = datetime.fromtimestamp(d.issued_at, tz=timezone.utc) if d.issued_at is not None else now
            expires_at = base + timedelta(seconds=d.expires_in)

        if d.chain_id is not None:
            from app.services.circuit_breaker import CircuitBreaker
            await CircuitBreaker(self.db).evaluate(org_id, d.chain_id)
        chain, hop = await DelegationService(self.db).delegate(
            org_id=org_id,
            from_agent_id=d.from_agent_id,
            to_agent_id=d.to_agent_id,
            task=d.task,
            delegated_capabilities=list(d.delegated_capabilities),
            signature=d.signature,
            chain_id=d.chain_id,
            expires_at=expires_at,
            signed_payload=signed_payload if d.signature else None,
            signer_public_key=from_agent.public_key if d.signature else None,
            pq_signature=d.pq_signature if d.signature and from_agent.pq_public_key else None,
            signer_pq_public_key=from_agent.pq_public_key if d.signature else None,
            delegated_tools=list(d.delegated_tools) if d.delegated_tools is not None else None,
            verified=verified,
        )
        from app.services.agent_rights import hop_rights

        to_agent = await registry.get_agent(d.to_agent_id, org_id)
        root = await registry.get_agent(chain.root_agent_id, org_id)
        # how much deeper the RECEIVER may still delegate: its own and the root's limit
        remaining = max(min(to_agent.max_delegation_depth, root.max_delegation_depth) - hop.depth, 0)
        effective = hop_rights(to_agent, hop)
        return Delegated(chain=chain, hop=hop, verified=verified, max_depth_remaining=remaining,
                         effective_capabilities=effective.capabilities, effective_tools=effective.tools)

    # ---------------------------------------------------- PVP views of rows

    @staticmethod
    def check_out(chk: ActionCheck, permit: Optional[str] = None) -> PVPCheck:
        return PVPCheck(
            check_id=chk.token, agent_id=chk.agent_id, chain_id=chk.chain_id,
            action_type=chk.action_type, tool_name=chk.tool_name, input_sha256=chk.input_sha256,
            decision=chk.decision, reason=chk.reason or "", incident_type=chk.incident_type,
            policy_id=chk.policy_id, required_capabilities=list(chk.action_capabilities or []),
            expires_at=_unix(chk.expires_at), permit=permit, permit_id=chk.permit_jti,
            permit_redeemed_at=_unix(chk.permit_redeemed_at) if chk.permit_redeemed_at else None,
        )

    @staticmethod
    def action_out(action: AgentAction, check_token: Optional[str] = None) -> PVPAction:
        """A stored action as PVP, in its current state (app/pvp/evidence.py)."""
        from app.pvp.evidence import action_view

        return action_view(action, check_token)
