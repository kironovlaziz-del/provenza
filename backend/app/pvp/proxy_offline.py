# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
When the server was unreachable (docs/pvp/edge.md, sections 6-7).

- **Offline actions.** With policy.mode "enforce" an egress proxy sends, while
  this server is unreachable, the egress-route requests an agent signed
  itself, judged by the signed policy release alone (proxy/internal/egress/
  offline.go). When the server answers again the proxy hands them over:
  each is recorded as an action with the agent's signed request and the
  proxy's receipt as its evidence; one that does not verify is recorded too,
  with a critical incident - it happened.
- **The local kill switch.** After the release's offline_seconds the proxy
  stops. When it reaches the server again it stays stopped and sends a
  reconciliation report, signed with its own key: what the server states now
  that the release it held before the outage did not - each difference is an
  incident here. The quorum of that release lifts it: each administrator signs
  with a passkey the report's hash and the differences no signed release
  explains (all of them must be accepted). The proxy checks the signatures
  itself (proxy/internal/trust/lift.go); this server only carries them.
"""

import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import webauthn
from app.core.agent_signing import content_hash, verify_agent_signature, verify_payload
from app.core.errors import api_error
from app.models.agent import Agent
from app.models.agent_action import AgentAction, AgentIncident
from app.models.ai_incident import AIIncident
from app.models.delegation import ActionNonce
from app.models.egress_proxy import EgressProxy, ProxyKillSwitch, ProxyKillSwitchSignature
from app.models.policy_release import PolicyRelease
from app.models.user import User
from app.pvp import witness
from app.pvp.egress_proxy import ACTION_TYPE, DESCRIPTOR_KEYS, EXECUTOR, PREFIX
from app.services.agent_audit import AgentAudit
from app.services.agent_policy_engine import ALLOWED, DENIED, Decision

REPORT_TYPE = "provenza.reconciliation"
REPORT_RECEIPT = "provenza.reconciliation"
LIFT_TYPE = "provenza.kill_switch.lift"
# how long a lift signature counts (the quorum may sign over hours; the proxy refuses more than a day)
LIFT_LIFE = 12 * 3600
INCIDENT = "reconciliation"
NOTIFY_EVENT = "kill_switch"
MAX_INCIDENTS = 50
_NONCE = re.compile(r"^[A-Za-z0-9_\-]{8,128}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------- offline actions

def _problems(entry: Any) -> Optional[str]:
    if not isinstance(entry, dict):
        return "not an object"
    req, desc = entry.get("request"), entry.get("descriptor")
    if not isinstance(req, dict) or not isinstance(req.get("payload"), dict):
        return "no signed request"
    if not isinstance(desc, dict) or set(desc) != set(DESCRIPTOR_KEYS):
        return "no descriptor"
    if entry.get("decision") not in (ALLOWED, DENIED):
        return "no decision"
    p = req["payload"]
    if p.get("type") != "action.request" or p.get("action_type") != ACTION_TYPE \
            or p.get("tool_name") != PREFIX + str(desc.get("route")) or p.get("input_sha256") != content_hash(desc):
        return "the signed request is for another action"
    if not isinstance(p.get("nonce"), str) or not _NONCE.match(p["nonce"]):
        return "no nonce"
    return None


async def offline_actions(db: AsyncSession, proxy: EgressProxy, actions: List[Any]) -> List[Dict[str, Any]]:
    """Record what a proxy did offline; for each: recorded, duplicate or rejected."""
    org_id, proxy_id, public_key = proxy.org_id, proxy.id, proxy.public_key or ""
    out = []
    for entry in actions:
        problem = _problems(entry)
        if problem:
            out.append({"status": "rejected", "reason": problem})
            continue
        req, desc = entry["request"], entry["descriptor"]
        p = req["payload"]
        agent = await db.get(Agent, p.get("agent_id")) if isinstance(p.get("agent_id"), int) else None
        if agent is None or agent.org_id != org_id:
            out.append({"status": "rejected", "reason": "unknown agent"})
            continue
        agent_id, nonce = agent.id, p["nonce"]
        dup = (await db.execute(select(AgentAction.id).where(
            AgentAction.org_id == org_id, AgentAction.agent_id == agent_id, AgentAction.executed_by == EXECUTOR,
            AgentAction.signed_payload["nonce"].astext == nonce))).first()
        if dup is not None:
            out.append({"status": "duplicate", "action_id": dup[0]})
            continue
        replayed = False
        try:
            async with db.begin_nested():
                db.add(ActionNonce(org_id=org_id, agent_id=agent_id, nonce=nonce))
                await db.flush()
        except IntegrityError:
            replayed = True  # the same signed request was used online too: recorded, with an incident
        signed = (req.get("public_key") == agent.public_key and
                  verify_agent_signature(p, req.get("signature"), req.get("pq_signature"), agent.public_key,
                                         agent.pq_public_key))
        outcome = entry.get("outcome") if entry["decision"] == ALLOWED else None
        decision_s = entry["decision"]
        check_token = "offline-" + nonce
        expected = {"check_id": check_token, "agent_id": agent_id, "chain_id": None, "action_type": ACTION_TYPE,
                    "tool_name": p["tool_name"], "input_sha256": content_hash(desc),
                    "output_sha256": content_hash(outcome), "decision": decision_s}
        receipt = entry.get("receipt") if isinstance(entry.get("receipt"), dict) else {}
        w = witness.make(receipt.get("statement"), receipt.get("signature"), public_key, expected)
        release = entry.get("release")
        reason = (f"sent by the egress proxy while Provenza was unreachable, under signed release #{release}"
                  if decision_s == ALLOWED else
                  f"refused by the egress proxy while Provenza was unreachable: {entry.get('reason') or ''}")
        issues = [k for k, bad in (("agent_signature", not signed), ("receipt", w is None),
                                   ("nonce_reused", replayed)) if bad]
        if issues:
            reason += f" - does not verify: {', '.join(issues)}"
        action = await AgentAudit(db).record(
            org_id=org_id, agent_id=agent_id, chain_id=None, action_type=ACTION_TYPE, tool_name=p["tool_name"],
            input_data=desc, output_data=outcome, signature=req.get("signature") if signed else None,
            duration_ms=entry.get("duration_ms") if isinstance(entry.get("duration_ms"), int) else None,
            decision=Decision(decision_s, reason, None), signed_payload=p,
            signer_public_key=agent.public_key, pq_signature=req.get("pq_signature"),
            signer_pq_public_key=agent.pq_public_key, executed_by=EXECUTOR, check_token=check_token, witness=w)
        if issues:
            db.add(AgentIncident(org_id=org_id, agent_id=agent_id, incident_type="offline_action_unverified",
                                 severity="critical",
                                 details={"via": EXECUTOR, "proxy_id": proxy_id, "action_id": action.id,
                                          "problems": issues, "decision": decision_s}))
            await db.commit()
        out.append({"status": "recorded", "action_id": action.id, **({"problems": issues} if issues else {})})
    return out


# ---------------------------------------------------------------------- reconciliation

async def reconciliation_state(db: AsyncSession, org_id: int) -> Dict[str, Any]:
    """What the server states now: the working copy's manifest and Tool Registry."""
    from app.services import policy_release as pr

    bundle, manifest, _ = await pr.working_copy(db, org_id)
    return {"manifest": manifest, "tool_registry": bundle.get("tool_registry") or {}}


def unsigned_ids(report: Dict[str, Any]) -> List[str]:
    return sorted(d["id"] for d in report.get("differences") or [] if isinstance(d, dict) and not d.get("signed"))


async def report(db: AsyncSession, proxy: EgressProxy, rep: Any, receipt: Any) -> Dict[str, Any]:
    """A proxy's kill switch and its reconciliation report, signed with its key."""
    if not isinstance(rep, dict) or rep.get("type") != REPORT_TYPE or rep.get("v") != 1:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.bad_report")
    if rep.get("org_id") != proxy.org_id or rep.get("proxy_id") != proxy.id:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.bad_report")
    sha = content_hash(rep)
    st = (receipt or {}).get("statement") if isinstance(receipt, dict) else None
    if not proxy.public_key or not isinstance(st, dict) or st.get("type") != REPORT_RECEIPT \
            or st.get("report_sha256") != sha or not verify_payload(st, receipt.get("signature") or "",
                                                                    proxy.public_key):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.bad_receipt")
    before = (rep.get("release_before") or {}).get("number")
    if not isinstance(before, int) or isinstance(rep.get("engaged_at"), bool) \
            or not isinstance(rep.get("engaged_at"), int):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.bad_report")
    org_id, proxy_id, name = proxy.org_id, proxy.id, proxy.name
    row = await _engaged(db, proxy_id)
    seen = set()
    if row is not None:
        if row.report_sha256 == sha:
            return {"id": row.id, "report_sha256": sha}
        seen = {d.get("id") for d in (row.report or {}).get("differences") or []}
        row.report, row.report_sha256, row.receipt = rep, sha, receipt
        row.release_before = before
    else:
        row = ProxyKillSwitch(org_id=org_id, proxy_id=proxy_id,
                              engaged_at=datetime.fromtimestamp(rep["engaged_at"], timezone.utc),
                              release_before=before, report=rep, report_sha256=sha, receipt=receipt,
                              status="engaged")
        db.add(row)
    diffs = [d for d in rep.get("differences") or [] if isinstance(d, dict) and d.get("id") not in seen]
    for d in diffs[:MAX_INCIDENTS]:
        db.add(AIIncident(
            org_id=org_id, severity="high" if not d.get("signed") else "medium", category=INCIDENT, status="open",
            summary=f"Egress proxy {name}: {d.get('area')} {d.get('section')} {d.get('label') or d.get('key')} "
                    f"{'changed through a signed release' if d.get('signed') else 'changed without a signed release'}"
                    f" while it was cut off",
            impact=f"local kill switch since {rep['engaged_at']}; report {sha[:12]}"))
    await db.flush()
    rid = row.id
    await db.commit()
    from app.services import notification_service

    await notification_service.notify(
        db, org_id, NOTIFY_EVENT, "An egress proxy stopped: local kill switch",
        f"Egress proxy {name} could not reach Provenza for longer than the signed policy allows and stopped. "
        f"Its reconciliation report lists {len(rep.get('differences') or [])} differences "
        f"({len(unsigned_ids(rep))} not signed). Administrators lift it under Gateways -> External APIs -> Proxies.",
        {"proxy_id": proxy_id, "report_sha256": sha})
    return {"id": rid, "report_sha256": sha}


async def _engaged(db: AsyncSession, proxy_id: int) -> Optional[ProxyKillSwitch]:
    return (await db.execute(select(ProxyKillSwitch).where(
        ProxyKillSwitch.proxy_id == proxy_id, ProxyKillSwitch.status == "engaged")
        .order_by(ProxyKillSwitch.id.desc()).limit(1))).scalar_one_or_none()


async def lift_signatures(db: AsyncSession, proxy: EgressProxy) -> Dict[str, Any]:
    row = await _engaged(db, proxy.id)
    if row is None:
        return {"report_sha256": None, "signatures": []}
    sigs = (await db.execute(select(ProxyKillSwitchSignature).where(
        ProxyKillSwitchSignature.kill_switch_id == row.id,
        ProxyKillSwitchSignature.report_sha256 == row.report_sha256)
        .order_by(ProxyKillSwitchSignature.id))).scalars()
    return {"report_sha256": row.report_sha256,
            "signatures": [{"user_id": s.user_id, "credential_id": s.credential_id, "statement": s.statement,
                            "assertion": s.assertion} for s in sigs]}


async def lifted(db: AsyncSession, proxy: EgressProxy, sha: str, signers: Any) -> None:
    row = await _engaged(db, proxy.id)
    if row is None or row.report_sha256 != sha:
        raise api_error(status.HTTP_409_CONFLICT, "kill_switch.not_engaged")
    row.status, row.lifted_at = "lifted", _now()
    row.lifted_by = [str(s) for s in signers][:20] if isinstance(signers, list) else None
    org_id, proxy_id, name = proxy.org_id, proxy.id, proxy.name
    await db.commit()
    from app.services import notification_service

    await notification_service.notify(db, org_id, NOTIFY_EVENT, "An egress proxy's kill switch was lifted",
                                      f"Egress proxy {name} works again: the quorum signed its reconciliation "
                                      f"report. Sign a new policy release now.", {"proxy_id": proxy_id})


# ---------------------------------------------------------------------- the administrators' signatures

def lift_statement(org_id: int, user_id: int, proxy_id: int, sha: str, accept: List[str],
                   issued_at: int) -> Dict[str, Any]:
    return {"type": LIFT_TYPE, "v": 1, "org_id": org_id, "user_id": user_id, "proxy_id": proxy_id,
            "report_sha256": sha, "accept": sorted(set(accept)), "issued_at": issued_at,
            "expires_at": issued_at + LIFT_LIFE}


async def _before(db: AsyncSession, row: ProxyKillSwitch) -> Dict[str, Any]:
    """The manifest of the release the proxy held before the outage: only its administrators lift."""
    rel = (await db.execute(select(PolicyRelease).where(PolicyRelease.org_id == row.org_id,
                                                        PolicyRelease.number == row.release_before))
           ).scalar_one_or_none()
    return rel.manifest if rel is not None else {}


def _credentials(manifest: Dict[str, Any], user: User) -> List[str]:
    s = (manifest.get("signers") or {}).get(str(user.id)) or {}
    if user.role != "admin" or s.get("role") != "admin":
        return []
    return list((s.get("passkeys") or {}).keys())


async def _row_for(db: AsyncSession, user: User, proxy_id: int) -> ProxyKillSwitch:
    proxy = await db.get(EgressProxy, proxy_id)
    if proxy is None or proxy.org_id != user.org_id:
        raise api_error(status.HTTP_404_NOT_FOUND, "egress.proxy_not_found")
    row = await _engaged(db, proxy_id)
    if row is None:
        raise api_error(status.HTTP_409_CONFLICT, "kill_switch.not_engaged")
    return row


def _check_accept(row: ProxyKillSwitch, accept: Any) -> List[str]:
    ids = {d.get("id") for d in (row.report or {}).get("differences") or [] if isinstance(d, dict)}
    if not isinstance(accept, list) or not all(isinstance(a, str) and a in ids for a in accept):
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.bad_accept")
    missing = set(unsigned_ids(row.report)) - set(accept)
    if missing:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "kill_switch.accept_all", missing=len(missing))
    return sorted(set(accept))


async def lift_challenge(db: AsyncSession, user: User, proxy_id: int, accept: Any) -> Dict[str, Any]:
    from app.services import signing_sessions as ss

    row = await _row_for(db, user, proxy_id)
    creds = _credentials(await _before(db, row), user)
    if not creds:
        raise api_error(status.HTTP_403_FORBIDDEN, "kill_switch.not_a_signer")
    st = lift_statement(user.org_id, user.id, proxy_id, row.report_sha256, _check_accept(row, accept), int(time.time()))
    return await ss.challenge_for(db, user, st, creds)


async def lift_sign(db: AsyncSession, user: User, proxy_id: int, statement: Any, assertion: Any) -> Dict[str, Any]:
    """One administrator's passkey over the report. The proxy lifts itself when
    it has counted the quorum of the release it held before the outage."""
    from app.services import signing_sessions as ss

    row = await _row_for(db, user, proxy_id)
    manifest = await _before(db, row)
    creds = _credentials(manifest, user)
    if not creds:
        raise api_error(status.HTTP_403_FORBIDDEN, "kill_switch.not_a_signer")
    st = statement if isinstance(statement, dict) else {}
    accept = _check_accept(row, st.get("accept"))
    issued = st.get("issued_at")
    expected = lift_statement(user.org_id, user.id, proxy_id, row.report_sha256, accept,
                              issued if isinstance(issued, int) else 0)
    await ss.confirm_expected(db, user, expected, statement, assertion, creds)
    key = ((manifest.get("signers") or {}).get(str(user.id)) or {}).get("passkeys", {}).get(
        (assertion or {}).get("credential_id"))
    try:
        webauthn.verify_assertion_spki(
            public_key_spki=key["public_key"], alg=int(key["alg"]),
            client_data_json=str(assertion.get("client_data_json") or ""),
            authenticator_data=str(assertion.get("authenticator_data") or ""),
            signature=str(assertion.get("signature") or ""), challenge=webauthn.statement_challenge(statement))
    except (webauthn.WebAuthnError, KeyError, TypeError):
        raise api_error(status.HTTP_403_FORBIDDEN, "kill_switch.passkey_not_in_manifest")
    exists = (await db.execute(select(ProxyKillSwitchSignature.id).where(
        ProxyKillSwitchSignature.kill_switch_id == row.id, ProxyKillSwitchSignature.report_sha256 == row.report_sha256,
        ProxyKillSwitchSignature.user_id == user.id))).first()
    if exists:
        raise api_error(status.HTTP_409_CONFLICT, "kill_switch.already_signed")
    db.add(ProxyKillSwitchSignature(org_id=user.org_id, kill_switch_id=row.id, report_sha256=row.report_sha256,
                                    user_id=user.id, credential_id=assertion["credential_id"], statement=statement,
                                    assertion={k: assertion.get(k) for k in
                                               ("client_data_json", "authenticator_data", "signature")}))
    await db.commit()
    return await view(db, row.proxy_id, user)


async def view(db: AsyncSession, proxy_id: int, user: User) -> Optional[Dict[str, Any]]:
    """What the interface shows of a proxy's kill switch (None: not engaged)."""
    row = await _engaged(db, proxy_id)
    if row is None or row.org_id != user.org_id:
        return None
    manifest = await _before(db, row)
    rows = (await db.execute(select(ProxyKillSwitchSignature, User.email)
                             .join(User, User.id == ProxyKillSwitchSignature.user_id)
                             .where(ProxyKillSwitchSignature.kill_switch_id == row.id,
                                    ProxyKillSwitchSignature.report_sha256 == row.report_sha256)
                             .order_by(ProxyKillSwitchSignature.id))).all()
    return {"engaged_at": row.engaged_at, "reason": (row.report or {}).get("reason"),
            "release_before": row.release_before, "report_sha256": row.report_sha256,
            "differences": (row.report or {}).get("differences") or [], "unsigned": unsigned_ids(row.report),
            "quorum": max(1, int(manifest.get("quorum") or 1)),
            "signers": [{"user_id": s.user_id, "email": email} for s, email in rows],
            "can_sign": bool(_credentials(manifest, user)) and all(s.user_id != user.id for s, _ in rows)}
