# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
PVP receipts - one self-contained, offline-verifiable document per action
(docs/pvp/spec.md, section 3.4; tools/provenza_audit.py receipt verifies it).

    action evidence (as recorded) -> leaf of a seal -> the seal's record in
    the audit log -> signed checkpoint

An action a person's approval let run carries that approval as signed with
the reviewer's session key and certified by their passkey.

An action not sealed yet is sealed on the spot, and the inclusion proof
signs a checkpoint when the latest one does not cover the seal yet - a
receipt asked for is complete, never "come back in five minutes".
"""

from typing import Any, Dict, Optional

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit_chain as ac
from app.core.errors import api_error
from app.models.agent_action import ActionCheck, AgentAction
from app.models.approval import AgentActionApproval
from app.models.pvp_seal import PVPActionSeal
from app.pvp import seal as seals
from app.pvp.model import PVPAction, PVPCheckpoint, PVPReceipt, PVPSeal
from app.pvp.orchestrator import PVPOrchestrator
from app.services import audit_proofs


async def action_row(db: AsyncSession, org_id: int, action_id: int) -> AgentAction:
    row = (await db.execute(select(AgentAction).where(AgentAction.id == action_id, AgentAction.org_id == org_id)
                            .execution_options(populate_existing=True))).scalar_one_or_none()
    if row is None:
        raise api_error(status.HTTP_404_NOT_FOUND, "pvp.action_not_found")
    if row.evidence is None:
        # recorded before receipts existed (or by a path that keeps no verdict)
        raise api_error(status.HTTP_409_CONFLICT, "pvp.no_evidence")
    return row


async def build(db: AsyncSession, org_id: int, action_id: int,
                proofs: Optional[Dict[int, Dict[str, Any]]] = None) -> PVPReceipt:
    """`proofs`: a cache of audit inclusion proofs by audit record, for
    callers building many receipts (actions of one seal share one proof)."""
    row = await action_row(db, org_id, action_id)
    if row.seal_id is None:
        await seals.seal_org(db, org_id)
        row = await action_row(db, org_id, action_id)
    action = PVPAction.model_validate(row.evidence)
    current = row.policy_check_result
    check = approval = None
    if row.check_id is not None:
        chk = await db.get(ActionCheck, row.check_id)
        check = PVPOrchestrator.check_out(chk) if chk is not None else None
        spent = (await db.execute(select(AgentActionApproval).where(
            AgentActionApproval.org_id == org_id, AgentActionApproval.redeemed_check_id == row.check_id)
        )).scalars().first()
        if spent is not None and spent.signed:
            approval = {"approval_id": spent.id, "action_id": spent.action_id, **spent.signed}

    seal_row: Optional[PVPActionSeal] = await db.get(PVPActionSeal, row.seal_id) if row.seal_id else None
    if seal_row is None or seal_row.audit_log_id is None:
        raise api_error(status.HTTP_409_CONFLICT, "pvp.not_sealed")
    leaves = [bytes.fromhex(h) for h in await seals.members(db, seal_row.id)]
    index = leaves.index(bytes.fromhex(row.evidence_sha256))
    seal = PVPSeal(seal_id=seal_row.id, leaf_index=index, size=len(leaves), root=seal_row.root,
                   inclusion_path=ac.hexes(ac.inclusion_proof(index, leaves)), audit_log_id=seal_row.audit_log_id)
    proof = (proofs or {}).get(seal_row.audit_log_id)
    if proof is None:
        try:
            proof = await audit_proofs.inclusion_proof(db, org_id, seal_row.audit_log_id)
        except audit_proofs.ProofError as exc:
            raise api_error(status.HTTP_409_CONFLICT, exc.code) from exc
        if proofs is not None:
            proofs[seal_row.audit_log_id] = proof
    return PVPReceipt(action=action, check=check, seal=seal, audit_proof=proof,
                      checkpoint=PVPCheckpoint(**proof["checkpoint"]), current_decision=current,
                      approval=approval)
