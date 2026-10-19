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
from app.services import provider_policy
import httpx
from app.core.outbound import error_detail, guarded_async_client
from fastapi import HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

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
