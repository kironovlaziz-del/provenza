from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Literal
from app.core.database import get_db
from app.core.pagination import PaginationParams
from app.schemas.provider import ProviderCreate, ProviderOut, ProviderUpdate
from app.schemas.pagination import Page
from app.services.provider_service import ProviderService
from app.services.audit_service import AuditService
from app.models.user import User
from app.api.deps import get_current_user, require_role
from app.models.user import UserRole
from app.models.ai_provider import AIProvider
from app.models.organization import Organization
from app.core.crypto import decrypt_secret
from app.services import provider_adapters, provider_policy
import httpx
from app.core.outbound import INTERNAL_ONLY_MESSAGE, error_detail, guarded_async_client
from app.services import prompt_firewall
from app.models.ai_request import AIRequest
from app.core.crypto import encrypt_secret
from fastapi import HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.models.ai_policy import AIPolicy, AIPolicyVersion

router = APIRouter()


@router.post("/", response_model=ProviderOut)
async def create_provider(
    data: ProviderCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin))
):
    service = ProviderService(db)
    provider = await service.create_provider(current_user.org_id, data)
    await AuditService(db).log(
        current_user.org_id, current_user.id, "provider", provider.id, "created",
        {"name": provider.name, "type": provider.type},
    )
    return provider


@router.get("/", response_model=Page[ProviderOut])
async def list_providers(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    service = ProviderService(db)
    items, total = await service.list_providers(
        current_user.org_id, skip=pagination.skip, limit=pagination.limit
    )
    return Page(items=items, total=total, skip=pagination.skip, limit=pagination.limit)


class ProviderPolicyIn(BaseModel):
    policy: Literal["any", "self_hosted"]


async def _policy_view(db: AsyncSession, org_id: int) -> dict:
    """The policy, and the active connections it refuses outright (no base URL,
    a public IP). A host name is judged at connect time, so it is not listed."""
    rows = (await db.execute(
        select(AIProvider).where(AIProvider.org_id == org_id, AIProvider.status == "active").order_by(AIProvider.name)
    )).scalars().all()
    cloud = [{"id": p.id, "name": p.name, "reason": r}
             for p in rows if (r := provider_policy.cloud_reason(p.type, p.base_url))]
    return {"policy": await provider_policy.org_policy(db, org_id), "cloud_connections": cloud}


@router.get("/policy")
async def get_provider_policy(db: AsyncSession = Depends(get_db),
                              current_user: User = Depends(get_current_user)):
    return await _policy_view(db, current_user.org_id)


@router.put("/policy")
async def set_provider_policy(data: ProviderPolicyIn, db: AsyncSession = Depends(get_db),
                              current_user: User = Depends(require_role(UserRole.admin))):
    """Which AI providers the organization's prompts may reach: any, or only
    self-hosted ones (app/services/provider_policy.py)."""
    org_id, user_id = current_user.org_id, current_user.id
    org = await db.get(Organization, org_id)
    before = provider_policy.policy_name(org.ai_provider_policy)
    org.ai_provider_policy = data.policy
    await db.commit()
    await AuditService(db).log(org_id, user_id, "organization", org_id, "ai_provider_policy_changed",
                               {"before": before, "after": provider_policy.policy_name(data.policy)})
    return await _policy_view(db, org_id)


@router.get("/{provider_id}", response_model=ProviderOut)
async def get_provider(
    provider_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    service = ProviderService(db)
    return await service.get_provider(provider_id, current_user.org_id)


@router.put("/{provider_id}", response_model=ProviderOut)
async def update_provider(
    provider_id: int,
    data: ProviderUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin))
):
    service = ProviderService(db)
    provider = await service.update_provider(provider_id, current_user.org_id, data)
    # the audit log is readable by every user: never the key itself
    changes = data.model_dump(exclude_unset=True)
    if "api_key" in changes:
        changes["api_key"] = "set" if changes["api_key"] else "cleared"
    await AuditService(db).log(
        current_user.org_id, current_user.id, "provider", provider.id, "updated", changes,
    )
    return provider


class ProviderChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=100_000)
    system_prompt: str | None = Field(default=None, max_length=20_000)
    model: str | None = Field(default=None, max_length=200)


class ProviderChatResponse(BaseModel):
    answer: str
    masked: bool = False
    flags: list[str] = []
    blocked: bool = False
    blocked_reason: str | None = None


async def _active_policy_rules(db, org_id: int) -> dict:
    """Merged rules from ALL active policies of the org: if the latest
    APPROVED version of any active policy requires approval, the whole
    request does. Blocked terms are not here: policy-scoped terms are kept
    on the Blocked terms page (services/blocked_terms.for_playground)."""
    pres = await db.execute(
        select(AIPolicy).where(AIPolicy.org_id == org_id, AIPolicy.status == "active")
    )
    policies = list(pres.scalars().all())
    require_approval = False
    for policy in policies:
        vres = await db.execute(
            select(AIPolicyVersion)
            .where(AIPolicyVersion.policy_id == policy.id, AIPolicyVersion.approved_by.isnot(None))
            .order_by(AIPolicyVersion.version.desc()).limit(1)
        )
        version = vres.scalar_one_or_none()
        if not version:
            continue
        if (version.rules_json or {}).get("effect") == "require_approval":
            require_approval = True
    out: dict = {}
    if require_approval:
        out["effect"] = "require_approval"
    return out


@router.post("/{provider_id}/chat", response_model=ProviderChatResponse)
async def governed_chat(
    provider_id: int,
    data: ProviderChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Governed chat with a connected provider: the prompt is run through the
    prompt firewall (secrets masked, blocked terms rejected) BEFORE it
    leaves for the provider, the call is made, and the request is logged to
    the Usage Registry. This is the governance-layer difference from
    hitting the provider directly.
    """
    from app.services.kill_switch import traffic_stop

    if await traffic_stop(db, current_user.org_id) is not None:
        from app.core.errors import api_error

        raise api_error(503, "kill_switch.traffic_stopped")
    result = await db.execute(
        select(AIProvider).where(
            AIProvider.id == provider_id, AIProvider.org_id == current_user.org_id
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
    # a switched-off or retired connection takes no traffic, here as in the Usage Registry
    if provider.status != "active":
        from app.core.errors import api_error

        raise api_error(status.HTTP_409_CONFLICT, "provider.not_active", name=provider.name)
    self_hosted = await provider_policy.enforce(db, current_user.org_id, provider.type, provider.base_url)

    # 1. firewall the user's message - and the system prompt: it is user input
    #    too and goes to the same provider - enforcing the org's active policy
    active_policy_rules = await _active_policy_rules(db, current_user.org_id)
    from app.services import blocked_terms as bt

    blocked_terms = await bt.for_playground(db, current_user.org_id)
    import asyncio

    from app.services import pii_rules

    pii_cfg = await pii_rules.config(db, current_user.org_id)
    fw = await asyncio.to_thread(prompt_firewall.scan, data.message, blocked_terms, "en", pii_cfg)
    await pii_rules.note_timeouts(db, current_user.org_id, fw.timed_out)
    await bt.record_hits(db, current_user.org_id, fw.term_hits)
    sys_fw = None
    if data.system_prompt:
        sys_fw = await asyncio.to_thread(prompt_firewall.scan, data.system_prompt, blocked_terms, "en", pii_cfg)
        await pii_rules.note_timeouts(db, current_user.org_id, sys_fw.timed_out)
        await bt.record_hits(db, current_user.org_id, sys_fw.term_hits)
        fw.flags = list(dict.fromkeys([*fw.flags, *(f"system_prompt:{f}" for f in sys_fw.flags)]))
        if sys_fw.blocked and not fw.blocked:
            fw.blocked = True
            fw.blocked_reason = f"System prompt: {sys_fw.blocked_reason or 'blocked by policy'}"
    await db.commit()  # before the provider call: the counted rows are not held locked while it runs
    # what is logged: everything the user sent, encrypted; the masked text for display
    original = f"[system]\n{data.system_prompt}\n\n[user]\n{data.message}" if data.system_prompt else data.message
    masked_logged = (f"[system]\n{sys_fw.masked_text}\n\n[user]\n{fw.masked_text}" if sys_fw else fw.masked_text)

    # what the prompt asks for (services/guardrail.py) - it reads the masked text
    if not fw.blocked:
        from app.services import guardrail
        verdict = await guardrail.classify(db, current_user.org_id, masked_logged, "playground")
        if verdict:
            fw.flags = list(dict.fromkeys([*fw.flags, *verdict.flags]))
            if verdict.block:
                fw.blocked = True
                fw.blocked_reason = f"Intent guardrail: {verdict.reason}"

    # policy may require human approval for every request under it
    if active_policy_rules.get("effect") == "require_approval" and not fw.blocked:
        db.add(AIRequest(
            org_id=current_user.org_id, user_id=current_user.id, provider_id=provider.id,
            input_text_encrypted=encrypt_secret(original, org_id=current_user.org_id),
            masked_input_text=masked_logged, status="pending_approval",
            purpose="playground_chat", firewall_flags=fw.flags,
        ))
        await db.commit()
        return ProviderChatResponse(
            answer="", blocked=True,
            blocked_reason="This request requires human approval before it can run (per active policy).",
            flags=fw.flags,
        )
    if fw.blocked:
        # log the blocked attempt too
        db.add(AIRequest(
            org_id=current_user.org_id, user_id=current_user.id, provider_id=provider.id,
            input_text_encrypted=encrypt_secret(original, org_id=current_user.org_id), status="blocked",
            purpose="playground_chat", firewall_flags=fw.flags,
        ))
        await db.commit()
        return ProviderChatResponse(
            answer="", blocked=True, blocked_reason=fw.blocked_reason or "Blocked by policy",
            flags=fw.flags,
        )

    safe_message = fw.masked_text
    # 2. only the masked texts leave: the message and the system prompt
    prompt = f"{sys_fw.masked_text}\n\n{safe_message}" if sys_fw else safe_message

    # call provider with the MASKED prompt
    api_key = decrypt_secret(provider.api_key_encrypted) if provider.api_key_encrypted else None
    chosen_model = data.model or provider.default_model
    try:
        with provider_policy.scope(self_hosted):
            answer, _raw = await provider_adapters.call_provider(
                provider.type, api_key, provider.base_url, chosen_model, prompt
            )
    except provider_adapters.ProviderCallError as exc:
        from app.core.errors import api_error

        if INTERNAL_ONLY_MESSAGE in str(exc):
            # the host resolved to the internet: refused at connect time, nothing was sent
            raise api_error(status.HTTP_403_FORBIDDEN, "provider.self_hosted_only",
                            reason="the base URL resolves to a public address")
        raise api_error(status.HTTP_502_BAD_GATEWAY, "provider.call_failed", message=str(exc)[:300])

    # 3. log to Usage Registry
    db.add(AIRequest(
        org_id=current_user.org_id, user_id=current_user.id, provider_id=provider.id,
        input_text_encrypted=encrypt_secret(original, org_id=current_user.org_id),
        masked_input_text=masked_logged, status="completed",
        purpose="playground_chat", firewall_flags=fw.flags,
    ))
    await db.commit()

    return ProviderChatResponse(
        answer=answer, masked=bool(fw.flags), flags=fw.flags,
    )


@router.get("/{provider_id}/models")
async def list_provider_models(
    provider_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List models the provider actually offers. For OpenAI-compatible
    providers (openai, groq, azure_openai, custom with a base_url) this
    queries their /models endpoint with the stored key, so the UI can show
    a real, current list instead of a free-text field.
    """
    result = await db.execute(
        select(AIProvider).where(
            AIProvider.id == provider_id, AIProvider.org_id == current_user.org_id
        )
    )
    provider = result.scalar_one_or_none()
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    api_key = decrypt_secret(provider.api_key_encrypted) if provider.api_key_encrypted else None
    if not api_key:
        return {"models": [], "note": "No API key stored for this provider."}

    # resolve base url per type
    base = provider.base_url
    if provider.type == "groq":
        base = base or "https://api.groq.com/openai/v1"
    elif provider.type == "openai":
        base = base or "https://api.openai.com/v1"
    if not base:
        return {"models": [], "note": "Model listing needs a base_url for this provider type."}

    self_hosted = await provider_policy.enforce(db, current_user.org_id, provider.type, provider.base_url)
    url = base.rstrip("/") + "/models"
    try:
        async with guarded_async_client(internal_only=self_hosted, timeout=20) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {api_key}"})
    except (httpx.HTTPError, httpx.InvalidURL) as e:
        raise HTTPException(status_code=502, detail=f"Could not list models: {e}")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Could not list models: provider returned {error_detail(resp)}")
    try:
        data = resp.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="Could not list models: the provider did not return JSON")
    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Could not list models: unexpected response shape")

    items = data.get("data") if isinstance(data.get("data"), list) else []
    models = sorted(str(m["id"]) for m in items if isinstance(m, dict) and m.get("id"))
    return {"models": models}
