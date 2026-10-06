from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
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
from app.core.crypto import decrypt_secret
from app.services import provider_adapters
import httpx
from app.core.outbound import error_detail, guarded_async_client
from app.services import prompt_firewall
from app.models.ai_request import AIRequest
from app.core.crypto import encrypt_secret
from fastapi import HTTPException, status
from pydantic import BaseModel
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
    await AuditService(db).log(
        current_user.org_id, current_user.id, "provider", provider.id, "updated",
        data.model_dump(exclude_unset=True),
    )
    return provider


class ProviderChatRequest(BaseModel):
    message: str
    system_prompt: str | None = None
    model: str | None = None


class ProviderChatResponse(BaseModel):
    answer: str
    masked: bool = False
    flags: list[str] = []
    blocked: bool = False
    blocked_reason: str | None = None


async def _active_policy_rules(db, org_id: int) -> dict:
    """Merged rules from ALL active policies of the org: the latest APPROVED
    version of each active policy contributes its blocked_terms, and if any
    requires approval, the whole request does. This way every active rule
    applies, not just one arbitrary policy."""
    pres = await db.execute(
        select(AIPolicy).where(AIPolicy.org_id == org_id, AIPolicy.status == "active")
    )
    policies = list(pres.scalars().all())
    blocked_terms: list[str] = []
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
        rules = version.rules_json or {}
        for term in (rules.get("blocked_terms") or []):
            if term not in blocked_terms:
                blocked_terms.append(term)
        if rules.get("effect") == "require_approval":
            require_approval = True
    out: dict = {}
    if blocked_terms:
        out["blocked_terms"] = blocked_terms
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

    # 1. firewall the user's message, enforcing the org's active policy
    active_policy_rules = await _active_policy_rules(db, current_user.org_id)
    blocked_terms = active_policy_rules.get("blocked_terms") or []
    fw = prompt_firewall.scan(data.message, blocked_terms=blocked_terms, language="en")

    # policy may require human approval for every request under it
    if active_policy_rules.get("effect") == "require_approval" and not fw.blocked:
        db.add(AIRequest(
            org_id=current_user.org_id, user_id=current_user.id, provider_id=provider.id,
            input_text_encrypted=encrypt_secret(data.message, org_id=current_user.org_id),
            masked_input_text=fw.masked_text, status="pending_approval",
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
            input_text_encrypted=encrypt_secret(data.message, org_id=current_user.org_id), status="blocked",
            purpose="playground_chat", firewall_flags=fw.flags,
        ))
        await db.commit()
        return ProviderChatResponse(
            answer="", blocked=True, blocked_reason=fw.blocked_reason or "Blocked by policy",
            flags=fw.flags,
        )

    safe_message = fw.masked_text
    prompt = f"{data.system_prompt}\n\n{safe_message}" if data.system_prompt else safe_message

    # 2. call provider with the MASKED prompt
    api_key = decrypt_secret(provider.api_key_encrypted) if provider.api_key_encrypted else None
    chosen_model = data.model or provider.default_model
    answer, _raw = await provider_adapters.call_provider(
        provider.type, api_key, provider.base_url, chosen_model, prompt
    )

    # 3. log to Usage Registry
    db.add(AIRequest(
        org_id=current_user.org_id, user_id=current_user.id, provider_id=provider.id,
        input_text_encrypted=encrypt_secret(data.message, org_id=current_user.org_id),
        masked_input_text=safe_message, status="completed",
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

    url = base.rstrip("/") + "/models"
    try:
        async with guarded_async_client(timeout=20) as client:
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
