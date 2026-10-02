# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Agent-to-agent message security - OWASP Agentic Top 10, ASI07
(insecure inter-agent communication).

Agents talk to each other through whatever transport they use (HTTP, a
queue, a framework's in-process bus). Provenza does not carry the messages;
it attests them, with the same Ed25519 keys agents already use to sign
delegations and actions:

  send     the sender signs an envelope
               {"type": "a2a_message", "from_agent_id", "to_agent_id",
                "chain_id", "message_type", "payload_sha256", "nonce",
                "issued_at"}
           (payload_sha256 = content_hash(payload), signature =
           sign_payload(envelope, private_key)) and registers it together
           with the payload. Checked: signature against the sender's
           public key (identity spoofing), nonce never seen before for this
           sender (replay), issued_at fresh, both agents active and in the
           organization, the route allowed (same delegation chain and/or an
           explicit channel), the payload matches its hash and carries no
           injection / code (ASI01 / ASI05 detectors). The payload is not
           stored.

  receive  before acting on a message, the recipient presents the message
           id and the hash of what it actually got. Checked: it is the
           addressee, the content was not altered in transit, the message
           was accepted and is not expired, and it is consumed only once.

mode "off"      nothing is checked;
mode "monitor"  (default) problems are recorded, messages still pass -
                except a replayed nonce and a tampered payload, which are
                never usable;
mode "enforce"  any failed check rejects the message (an incident is raised);
                a poisoned payload is quarantined until an admin releases it.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_signing import content_hash, verify_agent_signature
from app.models.a2a import A2AChannel, A2AMessage, A2ASettings
from app.models.agent import Agent
from app.models.agent_action import AgentIncident
from app.models.delegation import DelegationChain, DelegationHop
from app.services.agent_identity import pq_signature_required

MODES = ("off", "monitor", "enforce")
DEFAULTS = {"mode": "monitor", "allow_same_chain": True, "max_age_seconds": 300, "message_ttl_seconds": 3600}
FUTURE_SKEW = timedelta(seconds=60)
INCIDENT = "agent_communication_violation"


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_issued_at(value: Any) -> Optional[datetime]:
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        if isinstance(value, str):
            return _aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (ValueError, OverflowError, OSError):
        return None
    return None


class A2AGuard:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------ settings
    async def _settings_row(self, org_id: int) -> Optional[A2ASettings]:
        return (await self.db.execute(select(A2ASettings).where(A2ASettings.org_id == org_id))).scalar_one_or_none()

    async def settings(self, org_id: int) -> dict:
        row = await self._settings_row(org_id)
        if not row:
            return {**DEFAULTS, "source": "default"}
        return {k: getattr(row, k) for k in DEFAULTS} | {"source": "org"}

    async def save_settings(self, org_id: int, values: dict, user_id: int) -> tuple:
        row = await self._settings_row(org_id)
        before = None if row is None else {k: getattr(row, k) for k in DEFAULTS}
        if row is None:
            row = A2ASettings(org_id=org_id)
            self.db.add(row)
        for k in DEFAULTS:
            setattr(row, k, values[k])
        row.updated_by = user_id
        await self.db.commit()
        return before, {k: values[k] for k in DEFAULTS}

    # ------------------------------------------------------------------ channels
    async def _agent(self, org_id: int, agent_id: int) -> Optional[Agent]:
        return (await self.db.execute(
            select(Agent).where(Agent.id == agent_id, Agent.org_id == org_id)
        )).scalar_one_or_none()

    async def add_channel(self, org_id: int, data: dict, user_id: int) -> dict:
        for aid in (data["from_agent_id"], data["to_agent_id"]):
            if not await self._agent(org_id, aid):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent {aid} not found")
        existing = (await self.db.execute(
            select(A2AChannel).where(A2AChannel.org_id == org_id, A2AChannel.enabled.is_(True),
                                     A2AChannel.from_agent_id == data["from_agent_id"],
                                     A2AChannel.to_agent_id == data["to_agent_id"])
        )).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This channel already exists")
        ch = A2AChannel(org_id=org_id, from_agent_id=data["from_agent_id"], to_agent_id=data["to_agent_id"],
                        bidirectional=data["bidirectional"], created_by=user_id)
        self.db.add(ch)
        await self.db.commit()
        await self.db.refresh(ch)
        return {"id": ch.id, "from_agent_id": ch.from_agent_id, "to_agent_id": ch.to_agent_id,
                "bidirectional": ch.bidirectional}

    async def disable_channel(self, org_id: int, channel_id: int, user_id: int) -> dict:
        ch = (await self.db.execute(
            select(A2AChannel).where(A2AChannel.id == channel_id, A2AChannel.org_id == org_id)
        )).scalar_one_or_none()
        if not ch:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")
        if not ch.enabled:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Channel is already disabled")
        ch.enabled = False
        ch.disabled_by = user_id
        ch.disabled_at = datetime.now(timezone.utc)
        await self.db.commit()
        return {"id": ch.id, "enabled": False}

    async def _route_allowed(self, org_id: int, src: int, dst: int, chain_id: Optional[int],
                             allow_same_chain: bool) -> Optional[str]:
        """Returns how the route is allowed ("channel" / "chain") or None."""
        ch = (await self.db.execute(
            select(A2AChannel.id).where(
                A2AChannel.org_id == org_id, A2AChannel.enabled.is_(True),
                or_((A2AChannel.from_agent_id == src) & (A2AChannel.to_agent_id == dst),
                    (A2AChannel.bidirectional.is_(True)) & (A2AChannel.from_agent_id == dst)
                    & (A2AChannel.to_agent_id == src)),
            ).limit(1)
        )).scalar_one_or_none()
        if ch:
            return "channel"
        if allow_same_chain and chain_id is not None:
            chain = (await self.db.execute(
                select(DelegationChain).where(DelegationChain.id == chain_id, DelegationChain.org_id == org_id)
            )).scalar_one_or_none()
            if chain is None:
                return None
            members = {chain.root_agent_id}
            for f, t in (await self.db.execute(
                select(DelegationHop.from_agent_id, DelegationHop.to_agent_id).where(DelegationHop.chain_id == chain_id)
            )).all():
                members.update((f, t))
            if src in members and dst in members:
                return "chain"
        return None

    def _incident(self, org_id: int, agent_id: Optional[int], chain_id: Optional[int], details: dict) -> None:
        extra = {"chain_id": chain_id} if hasattr(AgentIncident, "chain_id") else {}
        self.db.add(AgentIncident(org_id=org_id, agent_id=agent_id, incident_type=INCIDENT, severity="high",
                                  details=details, **extra))

    # ------------------------------------------------------------------ send
    async def send(self, org_id: int, envelope: Dict[str, Any], signature: str, payload: Any,
                   pq_signature: Optional[str] = None) -> dict:
        cfg = await self.settings(org_id)
        mode = cfg["mode"]
        enforce = mode == "enforce"
        now = datetime.now(timezone.utc)
        src_id, dst_id = envelope["from_agent_id"], envelope["to_agent_id"]
        chain_id = envelope.get("chain_id")
        issued = parse_issued_at(envelope.get("issued_at"))

        src = await self._agent(org_id, src_id)
        dst = await self._agent(org_id, dst_id)
        if src is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sender agent not found")

        reasons: List[str] = []
        findings: List[dict] = []
        hard: List[str] = []  # failures that make the message unusable in every mode
        sig_ok = False
        route = None

        chain_ok = chain_id is None or (await self.db.execute(
            select(DelegationChain.id).where(DelegationChain.id == chain_id, DelegationChain.org_id == org_id)
        )).scalar_one_or_none() is not None
        if mode != "off":
            if not chain_ok:
                reasons.append(f"chain #{chain_id} does not exist in this organization")
            if not src.public_key:
                reasons.append("sender has no registered public key")
            else:
                try:
                    # Ed25519 AND, for a hybrid sender, ML-DSA-65
                    sig_ok = verify_agent_signature(envelope, signature, pq_signature,
                                                    src.public_key, src.pq_public_key)
                except Exception:  # noqa: BLE001 - a malformed signature is just invalid
                    sig_ok = False
                if not sig_ok:
                    reasons.append("invalid signature (identity cannot be confirmed)")
            if dst is None:
                reasons.append("recipient is not an agent of this organization")
            if src.status != "active":
                reasons.append(f"sender is {src.status}")
            if dst is not None and dst.status != "active":
                reasons.append(f"recipient is {dst.status}")
            if issued is None:
                reasons.append("issued_at is not a valid timestamp")
            elif issued > now + FUTURE_SKEW:
                reasons.append("issued_at is in the future")
            elif now - issued > timedelta(seconds=cfg["max_age_seconds"]):
                reasons.append(f"envelope is older than {cfg['max_age_seconds']}s")
            if content_hash(payload) != envelope["payload_sha256"]:
                hard.append("payload does not match payload_sha256")
            if dst is not None:
                route = await self._route_allowed(org_id, src_id, dst_id, chain_id, cfg["allow_same_chain"])
                if route is None:
                    reasons.append("no allowed route between these agents (channel or shared chain)")
            seen = (await self.db.execute(
                select(A2AMessage.id).where(A2AMessage.org_id == org_id, A2AMessage.from_agent_id == src_id,
                                            A2AMessage.nonce == envelope["nonce"])
            )).scalar_one_or_none()
            if seen:
                hard.append("nonce already used (replay)")

        # An organization policy, not a guard setting: it holds in every mode.
        if await pq_signature_required(self.db, src):
            hard.append("this organization requires post-quantum (hybrid) signatures; the sender has no hybrid key")

        poisoned = False
        if mode != "off" and not hard:
            from app.services.memory_guard import scan_content
            from app.services.injection_guard import InjectionGuard
            r = scan_content(payload, (await InjectionGuard(self.db).settings(org_id))["threshold"])
            findings = r["findings"]
            poisoned = r["poisoned"]
            if poisoned:
                reasons.append(f"payload carries an injection or code (injection {r['injection']}, "
                               f"code {r['code_severity']})")
            elif r["suspicious"]:
                reasons.append(f"suspicious payload (injection {r['injection']}, code {r['code_severity']})")

        all_reasons = hard + reasons
        if hard or (enforce and any(not x.startswith(("payload carries", "suspicious")) for x in reasons)):
            new_status = "rejected"
        elif enforce and poisoned:
            new_status = "quarantined"
        else:
            new_status = "accepted"

        msg = A2AMessage(
            org_id=org_id, from_agent_id=src_id, to_agent_id=dst_id if dst else None,
            chain_id=chain_id if chain_ok else None,
            message_type=str(envelope.get("message_type"))[:50], payload_sha256=envelope["payload_sha256"],
            nonce=envelope["nonce"] if new_status != "rejected" else None, issued_at=issued,
            signature_valid=sig_ok, status=new_status, reasons=all_reasons, findings=findings,
        )
        self.db.add(msg)
        if new_status == "rejected" and mode != "off":
            self._incident(org_id, src_id, chain_id if chain_ok else None, {"stage": "send", "to_agent_id": dst_id,
                                                      "reasons": all_reasons})
        try:
            await self.db.commit()
        except IntegrityError:  # two concurrent sends with the same nonce: the second one loses
            await self.db.rollback()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="nonce already used (replay)")
        await self.db.refresh(msg)
        return {"message_id": msg.id, "status": new_status, "deliver": new_status == "accepted",
                "signature_valid": sig_ok, "route": route, "reasons": all_reasons, "findings": findings,
                "mode": mode}

    # ------------------------------------------------------------------ receive
    async def receive(self, org_id: int, agent_id: int, message_id: int, payload_sha256: str) -> dict:
        cfg = await self.settings(org_id)
        mode = cfg["mode"]
        now = datetime.now(timezone.utc)
        if not await self._agent(org_id, agent_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        msg = (await self.db.execute(
            select(A2AMessage).where(A2AMessage.id == message_id, A2AMessage.org_id == org_id)
        )).scalar_one_or_none()
        if msg is None:
            return {"message_id": message_id, "verdict": "unknown", "use": False}

        msg.receive_attempts = (msg.receive_attempts or 0) + 1
        if msg.to_agent_id != agent_id:
            verdict = "wrong_recipient"
        elif msg.payload_sha256 != payload_sha256:
            verdict = "mismatch"
        elif msg.status != "accepted":
            verdict = msg.status
        elif msg.consumed_at is not None:
            verdict = "replayed"
        elif _aware(msg.created_at) and now - _aware(msg.created_at) > timedelta(seconds=cfg["message_ttl_seconds"]):
            verdict = "expired"
        else:
            verdict = "accepted"
            msg.consumed_at = now

        if mode == "off":
            use = verdict not in ("unknown",)
        elif mode == "monitor":
            use = verdict in ("accepted", "quarantined", "expired", "replayed")
        else:
            use = verdict == "accepted"
        if verdict in ("wrong_recipient", "mismatch", "replayed") and mode != "off":
            self._incident(org_id, agent_id, msg.chain_id,
                           {"stage": "receive", "message_id": msg.id, "verdict": verdict,
                            "from_agent_id": msg.from_agent_id})
        await self.db.commit()
        return {"message_id": msg.id, "verdict": verdict, "use": use, "from_agent_id": msg.from_agent_id,
                "message_type": msg.message_type, "chain_id": msg.chain_id}

    async def release(self, org_id: int, message_id: int) -> dict:
        msg = (await self.db.execute(
            select(A2AMessage).where(A2AMessage.id == message_id, A2AMessage.org_id == org_id)
        )).scalar_one_or_none()
        if msg is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
        if msg.status != "quarantined":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Message is {msg.status}, not quarantined")
        msg.status = "accepted"
        await self.db.commit()
        return {"message_id": msg.id, "status": "accepted"}

    # ------------------------------------------------------------------ overview
    async def overview(self, org_id: int, msg_status: Optional[str] = None) -> dict:
        agents = {a.id: a.name for a in (await self.db.execute(
            select(Agent).where(Agent.org_id == org_id).order_by(Agent.name)
        )).scalars().all()}
        q = select(A2AMessage).where(A2AMessage.org_id == org_id)
        if msg_status:
            q = q.where(A2AMessage.status == msg_status)
        msgs = (await self.db.execute(q.order_by(A2AMessage.created_at.desc()).limit(100))).scalars().all()
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        counts = dict((await self.db.execute(
            select(A2AMessage.status, func.count())
            .where(A2AMessage.org_id == org_id, A2AMessage.created_at >= since).group_by(A2AMessage.status)
        )).all())
        channels = (await self.db.execute(
            select(A2AChannel).where(A2AChannel.org_id == org_id).order_by(A2AChannel.enabled.desc(),
                                                                           A2AChannel.created_at.desc()).limit(200)
        )).scalars().all()
        return {
            "settings": await self.settings(org_id),
            "counts_24h": counts,
            "agents": [{"id": i, "name": n} for i, n in agents.items()],
            "messages": [
                {"id": m.id, "created_at": m.created_at, "from_agent_id": m.from_agent_id,
                 "from_agent": agents.get(m.from_agent_id), "to_agent_id": m.to_agent_id,
                 "to_agent": agents.get(m.to_agent_id), "chain_id": m.chain_id, "message_type": m.message_type,
                 "status": m.status, "signature_valid": m.signature_valid, "reasons": m.reasons,
                 "findings": m.findings, "consumed_at": m.consumed_at, "receive_attempts": m.receive_attempts}
                for m in msgs
            ],
            "channels": [
                {"id": c.id, "from_agent_id": c.from_agent_id, "from_agent": agents.get(c.from_agent_id),
                 "to_agent_id": c.to_agent_id, "to_agent": agents.get(c.to_agent_id),
                 "bidirectional": c.bidirectional, "enabled": c.enabled, "created_at": c.created_at}
                for c in channels
            ],
        }
