from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from typing import Optional
from app.models.ai_request import AIRequest
from app.models.ai_response import AIResponse
from app.models.ai_use_case import AIUseCase
from app.models.ai_provider import AIProvider
from app.models.ai_policy import AIPolicy, AIPolicyVersion
from app.core.errors import api_error
from app.schemas.request import RequestCreate
from app.services import prompt_firewall
from app.services import provider_adapters
from app.services.provider_adapters import ProviderCallError
from app.core.crypto import decrypt_secret, encrypt_secret


class RequestService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_request(
        self, org_id: int, user_id: int, data: RequestCreate
    ) -> AIRequest:
        from app.services.kill_switch import traffic_stop

        if await traffic_stop(self.db, org_id) is not None:
            raise api_error(status.HTTP_503_SERVICE_UNAVAILABLE, "kill_switch.traffic_stopped")
        result = await self.db.execute(
            select(AIUseCase).where(
                AIUseCase.id == data.use_case_id,
                AIUseCase.org_id == org_id,
            )
        )
        use_case = result.scalar_one_or_none()
        if not use_case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Use case not found",
            )

        result = await self.db.execute(
            select(AIProvider).where(
                AIProvider.id == data.provider_id,
                AIProvider.org_id == org_id,
            )
        )
        provider = result.scalar_one_or_none()
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Provider not found",
            )

        # A disabled connection is a hard stop: no request should ever reach
        # the firewall or policy engine on a provider that's been switched
        # off from Connections.
        if provider.status != "active":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"The '{provider.name}' connection is currently disabled and cannot accept new requests.",
            )

        risk_level = use_case.risk_level

        policy_version = None
        if use_case.approved_policy_version_id:
            # Scoped to the organization: a link that does not resolve here
            # (a stale or foreign id) fails closed rather than silently
            # running the request with no rules.
            result = await self.db.execute(
                select(AIPolicyVersion)
                .join(AIPolicy, AIPolicy.id == AIPolicyVersion.policy_id)
                .where(
                    AIPolicyVersion.id == use_case.approved_policy_version_id,
                    AIPolicy.org_id == org_id,
                )
            )
            policy_version = result.scalar_one_or_none()
            # Unapproved counts as invalid too: a draft must never govern traffic.
            if policy_version is None or policy_version.approved_at is None:
                raise api_error(status.HTTP_409_CONFLICT, "request.policy_version_invalid")

        rules = (policy_version.rules_json if policy_version else {}) or {}

        # the organization's policy level (services/hier_policy.py) on top of
        # the use case's: it can only add restrictions
        from app.services import hier_policy

        org_policy = await hier_policy.for_requests(self.db, org_id)
        refused_by = org_policy.refusing_any("providers.allow", [provider.name, provider.type])
        if refused_by:
            raise api_error(status.HTTP_403_FORBIDDEN, "policy.provider_not_allowed", provider=provider.name,
                            level=refused_by)
        blocked_terms = list(rules.get("blocked_terms") or [])
        blocked_terms += [t for t in org_policy.items("content.blocked_terms") if t not in blocked_terms]

        # Prompt Firewall runs before anything is persisted: a blocked
        # prompt never reaches the policy engine or a provider.
        import asyncio

        from app.services import pii_rules

        pii_cfg = await pii_rules.config(self.db, org_id)
        firewall_result = await asyncio.to_thread(
            prompt_firewall.scan, data.input_text, blocked_terms, getattr(data, "language", None) or "en", pii_cfg,
        )
        await pii_rules.note_timeouts(self.db, org_id, firewall_result.timed_out)

        # The raw prompt is only ever stored Fernet-encrypted, and never
        # returned by the API. Anything downstream (UI, provider call,
        # audit log metadata) uses masked_input_text instead.
        encrypted_raw = encrypt_secret(data.input_text, org_id=org_id) if data.input_text else None

        if firewall_result.blocked:
            request = AIRequest(
                org_id=org_id,
                use_case_id=data.use_case_id,
                user_id=user_id,
                provider_id=data.provider_id,
                input_text_encrypted=encrypted_raw,
                masked_input_text=None,
                purpose=data.purpose,
                risk_level=risk_level,
                status="blocked",
                firewall_flags=firewall_result.flags,
            )
            self.db.add(request)
            await self.db.commit()
            await self.db.refresh(request)
            return request

        requires_approval = (rules.get("effect") == "require_approval"
                             or org_policy.switch("requests.require_approval"))

        request = AIRequest(
            org_id=org_id,
            use_case_id=data.use_case_id,
            user_id=user_id,
            provider_id=data.provider_id,
            input_text_encrypted=encrypted_raw,
            masked_input_text=firewall_result.masked_text,
            purpose=data.purpose,
            risk_level=risk_level,
            status="pending_approval" if requires_approval else "pending",
            firewall_flags=firewall_result.flags,
        )
        self.db.add(request)
        await self.db.commit()
        await self.db.refresh(request)

        if not requires_approval:
            # Run the provider call in a worker so the API responds
            # immediately with a "pending" request. The worker will flip
            # the status to "completed" or "failed" when it finishes.
            from app.core.celery_app import celery_app

            from app.services.queue_ttl import enqueue_request
            await enqueue_request(self.db, request, org_id)

        return request

    async def process_request(self, request_id: int, org_id: int) -> Optional[AIResponse]:
        result = await self.db.execute(
            select(AIRequest).where(
                AIRequest.id == request_id,
                AIRequest.org_id == org_id,
            )
        )
        request = result.scalar_one_or_none()
        if not request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Request not found",
            )
        from app.services.kill_switch import traffic_stop

        stop = await traffic_stop(self.db, org_id)
        if stop is not None:
            # queued before the stop: it does not reach the provider
            request.status = "failed"
            request.error_message = f"Stopped by the kill switch (#{stop.id}): the organization's AI traffic is stopped."
            await self.db.commit()
            return None

        provider = None
        if request.provider_id:
            provider_result = await self.db.execute(
                select(AIProvider).where(AIProvider.id == request.provider_id)
            )
            provider = provider_result.scalar_one_or_none()

        # The provider only ever sees the masked text. If masking was somehow
        # empty (should never happen - scan() always sets a value), fall back
        # to a safe placeholder rather than sending nothing.
        prompt = request.masked_input_text or "[MASKED:UNAVAILABLE]"

        api_key: Optional[str] = None
        if provider and provider.api_key_encrypted:
            try:
                api_key = decrypt_secret(provider.api_key_encrypted)
            except ValueError:
                api_key = None

        if provider and api_key:
            try:
                response_text, raw = await provider_adapters.call_provider(
                    provider.type, api_key, provider.base_url, provider.default_model, prompt
                )
                response = AIResponse(
                    request_id=request.id,
                    provider_response_json=raw if isinstance(raw, dict) else {"raw": str(raw)},
                    response_text=response_text,
                    confidence_score=None,
                )
                request.status = "completed"
            except ProviderCallError as exc:
                response = AIResponse(
                    request_id=request.id,
                    provider_response_json={"error": str(exc)},
                    response_text=f"[connection error] {exc}",
                    confidence_score=None,
                )
                request.status = "failed"
        else:
            # No credentials configured on this connection yet - keep the
            # platform testable without live keys, but say so plainly rather
            # than presenting a fake answer as real.
            response = AIResponse(
                request_id=request.id,
                provider_response_json={"mock": True},
                response_text=f"[mock - no API key configured for this connection] {prompt[:80]}",
                confidence_score=0.95,
            )
            request.status = "completed"

        self.db.add(response)
        await self.db.commit()
        await self.db.refresh(response)

        return response

    async def get_request(self, request_id: int, org_id: int) -> AIRequest:
        result = await self.db.execute(
            select(AIRequest).where(
                AIRequest.id == request_id,
                AIRequest.org_id == org_id,
            )
        )
        request = result.scalar_one_or_none()
        if not request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Request not found",
            )
        return request

    async def list_requests(self, org_id: int, skip: int = 0, limit: int = 50):
        from sqlalchemy import func

        base = select(AIRequest).where(AIRequest.org_id == org_id)
        total = await self.db.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await self.db.execute(
            base.order_by(AIRequest.created_at.desc()).offset(skip).limit(limit)
        )
        return list(result.scalars().all()), int(total or 0)

    async def get_response(self, request_id: int, org_id: int) -> Optional[AIResponse]:
        await self.get_request(request_id, org_id)
        result = await self.db.execute(
            select(AIResponse).where(AIResponse.request_id == request_id)
        )
        return result.scalar_one_or_none()
