from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api import auth, users, policies, use_cases
from app.api import auth, users, policies, use_cases, requests
from app.api import auth, users, policies, use_cases, requests, approvals
from app.api import auth, users, policies, use_cases, requests, approvals, incidents
from app.api import providers
from app.api import audit
from app.api import overrides
from app.api import shadow_ai
from app.api import ingestion_sources
from app.api import domain_catalog
from app.api import discovery
from app.api import devices
from app.api import agents
from app.api import notification_channels
from app.api import dashboard
from app.api import inventory
from app.api import breaker
from app.api import tool_registry
from app.api import behavior
from app.api import injection
from app.api import code_exec
from app.api import memory
from app.api import a2a
from app.api import enrollment as enrollment_api
from app.api import teams as teams_api
from app.api import attestation as attestation_api
from app.api import policy_layers as policy_layers_api
from app.api import kill_switch as kill_switch_api
from app.api import pii as pii_api
from app.api import blocked_terms as blocked_terms_api
from app.api import agent_identity
from app.api import gateway
from app.api import queue_ttl
from app.api import byok
from app.api import compliance
from app.api import observability
from app.api import system


_is_prod = settings.ENVIRONMENT == "production"

app = FastAPI(
    title=settings.PROJECT_NAME,
    # OpenAPI schema and the interactive /docs are disabled in production
    # so the API surface is not publicly enumerable.
    openapi_url=None if _is_prod else f"{settings.API_V1_STR}/openapi.json",
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
)

# CORS - origins come from settings so production can lock this down
# without a code change. Wildcard + credentials is intentionally avoided:
# browsers reject that combination, and it would let any site issue
# authenticated requests as the logged-in user.
_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Include routers
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(users.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(policies.router, prefix=f"{settings.API_V1_STR}/policies", tags=["policies"])
app.include_router(use_cases.router, prefix=f"{settings.API_V1_STR}/use-cases", tags=["use-cases"])
app.include_router(requests.router, prefix=f"{settings.API_V1_STR}/requests", tags=["requests"])
app.include_router(approvals.router, prefix=f"{settings.API_V1_STR}/approvals", tags=["approvals"])
app.include_router(incidents.router, prefix=f"{settings.API_V1_STR}/incidents", tags=["incidents"])
app.include_router(providers.router, prefix=f"{settings.API_V1_STR}/providers", tags=["providers"])
app.include_router(audit.router, prefix=f"{settings.API_V1_STR}/audit-logs", tags=["audit"])
app.include_router(overrides.router, prefix=f"{settings.API_V1_STR}/overrides", tags=["overrides"])
app.include_router(shadow_ai.router, prefix=f"{settings.API_V1_STR}/shadow-ai", tags=["shadow-ai"])
app.include_router(ingestion_sources.router, prefix=f"{settings.API_V1_STR}/ingestion-sources", tags=["shadow-ai"])
app.include_router(domain_catalog.router, prefix=f"{settings.API_V1_STR}/domain-catalog", tags=["shadow-ai"])
app.include_router(discovery.router, prefix=f"{settings.API_V1_STR}/discovery", tags=["discovery"])
app.include_router(devices.devices_router, prefix=f"{settings.API_V1_STR}/devices", tags=["discovery"])
app.include_router(devices.found_router, prefix=f"{settings.API_V1_STR}/agents-found", tags=["discovery"])
app.include_router(agents.router, prefix=f"{settings.API_V1_STR}/agents", tags=["agent-governance"])
app.include_router(notification_channels.router, prefix=f"{settings.API_V1_STR}/notification-channels", tags=["notifications"])
app.include_router(dashboard.router, prefix=f"{settings.API_V1_STR}/dashboard", tags=["dashboard"])
app.include_router(inventory.router, prefix=f"{settings.API_V1_STR}/inventory", tags=["inventory"])
app.include_router(breaker.router, prefix=f"{settings.API_V1_STR}/agent-breaker", tags=["agent-governance"])
app.include_router(tool_registry.router, prefix=f"{settings.API_V1_STR}/tool-registry", tags=["agent-governance"])
app.include_router(behavior.router, prefix=f"{settings.API_V1_STR}/agent-behavior", tags=["agent-governance"])
app.include_router(injection.router, prefix=f"{settings.API_V1_STR}/injection", tags=["agent-governance"])
app.include_router(code_exec.router, prefix=f"{settings.API_V1_STR}/code-exec", tags=["agent-governance"])
app.include_router(memory.router, prefix=f"{settings.API_V1_STR}/memory", tags=["agent-governance"])
app.include_router(a2a.router, prefix=f"{settings.API_V1_STR}/a2a", tags=["agent-governance"])
app.include_router(agent_identity.router, prefix=f"{settings.API_V1_STR}/agent-identity", tags=["agent-governance"])
app.include_router(enrollment_api.router, prefix=f"{settings.API_V1_STR}/agent-enrollment", tags=["agent-governance"])
app.include_router(teams_api.router, prefix=f"{settings.API_V1_STR}/teams", tags=["agent-governance"])
app.include_router(attestation_api.router, prefix=f"{settings.API_V1_STR}/attestation", tags=["agent-governance"])
app.include_router(policy_layers_api.router, prefix=f"{settings.API_V1_STR}/policy-layers", tags=["policies"])
app.include_router(kill_switch_api.router, prefix=f"{settings.API_V1_STR}/kill-switch", tags=["agent-governance"])
app.include_router(pii_api.router, prefix=f"{settings.API_V1_STR}/pii", tags=["policies"])
app.include_router(blocked_terms_api.router, prefix=f"{settings.API_V1_STR}/blocked-terms", tags=["policies"])
app.include_router(gateway.router, prefix=f"{settings.API_V1_STR}/gateway", tags=["gateway"])
app.include_router(queue_ttl.router, prefix=f"{settings.API_V1_STR}/queue", tags=["requests"])
app.include_router(byok.router, prefix=f"{settings.API_V1_STR}/byok", tags=["security"])
app.include_router(compliance.router, prefix=f"{settings.API_V1_STR}/compliance", tags=["compliance"])
app.include_router(observability.router, prefix=f"{settings.API_V1_STR}/observability", tags=["agents"])
app.include_router(system.router, prefix=f"{settings.API_V1_STR}/system", tags=["system"])



@app.get("/health")
async def health_check():
    return {"status": "ok"}


