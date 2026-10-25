# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Approved calls run once - on every gateway and for the SDK alike.

A call a policy holds for a person (ASI09) is recorded as pending and not
executed. Nothing is replayed from the server: an approval only lets the
SAME call through when the agent makes it again, once, within a window:

    pending action A (agent, chain, action type, tool, input hash)
      -> a person approves A (agent_action_approvals: decided on input_sha256)
      -> the agent repeats the call: the policy engine still says
         "pending approval"; the orchestrator finds an approval of A for
         exactly this agent, chain, action type, tool and input hash,
         decided less than REDEEM_MINUTES ago and not used yet, marks it
         used and issues the check as allowed, naming the approval
      -> the gateway (or the agent, for /actions/record) executes and
         records the call under that allowed check.

Only an approval signed with the reviewer's session key counts, and the
signature is checked again here, against exactly this call: a row written
into the database without the person cannot release a call. Once a signed
policy is in force, the passkey that certified the reviewer's session must
be one the signed manifest lists for that person (app/pvp/signed_policy.py):
a passkey slipped into the database approves nothing.

So an approval cannot be stretched to other arguments, another chain or a
second run, and a later denial (a suspended agent, a tripped breaker, a
quarantine) still wins: only "pending approval" can turn into "allowed".
When the executor refuses the call after the check (rate limit, disabled
connection, a tool changed upstream), the approval is released for the
next repeat.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import content_hash
from app.models.agent_action import AgentAction
from app.models.approval import AgentActionApproval
from app.services.signing_sessions import APPROVAL, proof_holds

REDEEM_MINUTES = float(os.getenv("APPROVAL_REDEEM_MINUTES", "60"))


async def take(db: AsyncSession, org_id: int, *, agent_id: int, chain_id: Optional[int], action_type: str,
               tool_name: str, input_data: dict) -> Optional[AgentActionApproval]:
    """The unused approval of exactly this call, locked and marked used (the
    caller's transaction commits it), or None. Concurrent repeats of the call
    cannot both take it: the row is locked and a locked row is skipped."""
    now = datetime.now(timezone.utc)
    input_sha256 = content_hash(input_data or {})
    want = {"type": APPROVAL, "org_id": org_id, "agent_id": agent_id, "chain_id": chain_id,
            "action_type": action_type, "tool_name": tool_name, "input_sha256": input_sha256,
            "decision": "approved"}
    from app.pvp import signed_policy

    signed = await signed_policy.in_force(db, org_id)
    passed: list = []
    while True:
        row = await _next(db, org_id, now, passed, agent_id=agent_id, chain_id=chain_id, action_type=action_type,
                          tool_name=tool_name, input_sha256=input_sha256)
        if row is None:
            return None
        st = (row.signed or {}).get("statement") or {}
        if (all(st.get(k) == v for k, v in want.items()) and st.get("action_id") == row.action_id
                and proof_holds(row.signed) and (signed is None or listed(signed.manifest, row.signed))):
            row.redeemed_at = now
            await db.flush()
            return row
        passed.append(row.id)       # not signed for exactly this call: it never runs it


def listed(manifest: dict, proof: dict) -> bool:
    """The passkey behind an approval is the reviewer's in the signed manifest."""
    person = (manifest.get("signers") or {}).get(str((proof.get("statement") or {}).get("user_id"))) or {}
    key = (person.get("passkeys") or {}).get((proof.get("certificate") or {}).get("credential_id"))
    return bool(key) and key.get("public_key") == (proof.get("passkey") or {}).get("public_key")


async def _next(db: AsyncSession, org_id: int, now: datetime, passed: list, *, agent_id: int,
                chain_id: Optional[int], action_type: str, tool_name: str,
                input_sha256: str) -> Optional[AgentActionApproval]:
    return (await db.execute(
        select(AgentActionApproval)
        .join(AgentAction, AgentAction.id == AgentActionApproval.action_id)
        .where(AgentActionApproval.org_id == org_id,
               AgentActionApproval.decision == "approved",
               AgentActionApproval.redeemed_at.is_(None),
               AgentActionApproval.decided_at >= now - timedelta(minutes=REDEEM_MINUTES),
               AgentActionApproval.input_sha256 == input_sha256,
               AgentActionApproval.signed.is_not(None),
               AgentActionApproval.id.not_in(passed or [0]),
               AgentAction.org_id == org_id,
               AgentAction.agent_id == agent_id,
               AgentAction.chain_id.is_not_distinct_from(chain_id),
               AgentAction.action_type == action_type,
               AgentAction.tool_name == tool_name)
        .order_by(AgentActionApproval.decided_at, AgentActionApproval.id)
        .limit(1)
        .with_for_update(of=AgentActionApproval, skip_locked=True)
    )).scalar_one_or_none()


async def bind(db: AsyncSession, approval_id: int, check_id: int) -> None:
    """Note the check the approval was spent on."""
    await db.execute(update(AgentActionApproval).where(AgentActionApproval.id == approval_id)
                     .values(redeemed_check_id=check_id))
    await db.commit()


async def release(db: AsyncSession, check_id: int) -> None:
    """The call the approval was spent on was refused by its executor (a
    rate limit, a disabled connection, a changed tool): the approval can be
    used again. Committed with the caller's record."""
    await db.execute(update(AgentActionApproval).where(AgentActionApproval.redeemed_check_id == check_id)
                     .values(redeemed_at=None, redeemed_check_id=None))


def redeemable_until(approval: AgentActionApproval) -> Optional[datetime]:
    if approval.decision != "approved" or approval.redeemed_at is not None or approval.decided_at is None:
        return None
    decided = approval.decided_at if approval.decided_at.tzinfo else approval.decided_at.replace(tzinfo=timezone.utc)
    return decided + timedelta(minutes=REDEEM_MINUTES)


async def proof_for_check(db: AsyncSession, org_id: int, check_token: str) -> Optional[dict]:
    """The signed approval a check was released by, as an enforcement point
    verifies it (proxy/internal/trust): {"approval_id", "action_id", ...the
    proof} - or None."""
    from app.models.agent_action import ActionCheck

    row = (await db.execute(select(AgentActionApproval).join(
        ActionCheck, ActionCheck.id == AgentActionApproval.redeemed_check_id).where(
        ActionCheck.token == check_token, ActionCheck.org_id == org_id))).scalars().first()
    if row is None or not row.signed:
        return None
    return {"approval_id": row.id, "action_id": row.action_id, **row.signed}
