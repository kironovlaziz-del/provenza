# Tables of removed features stay mapped: datasets, training_jobs,
# model_deployments, prediction_logs (MLOps) and document_collections,
# rag_documents, document_chunks, rag_query_logs (RAG). Their rows are kept,
# ai_systems / ai_system_data_links still reference them by foreign key, and
# leaving them out would make Alembic autogenerate propose dropping them.
# No application code reads or writes them any more.
from app.models.organization import Organization
from app.models.user import User, UserRole
from app.models.ai_provider import AIProvider
from app.models.ai_policy import AIPolicy, AIPolicyVersion
from app.models.ai_use_case import AIUseCase
from app.models.ai_request import AIRequest
from app.models.ai_response import AIResponse
from app.models.ai_action import AIAction
from app.models.ai_approval import AIApproval
from app.models.ai_incident import AIIncident
from app.models.audit_log import (AIAuditLog, AuditCheckpoint, AuditKeyHandover, AuditKeyRotation,
                                  AuditKeyRotationApproval, AuditSigningKey)
from app.models.ai_override import AIOverride
from app.models.shadow_ai_sighting import ShadowAISighting
from app.models.dataset import Dataset
from app.models.training_job import TrainingJob
from app.models.notification_channel import NotificationChannel
from app.models.model_deployment import ModelDeployment
from app.models.prediction_log import PredictionLog
from app.models.ingestion_source import IngestionSource
from app.models.ai_domain_catalog import AIDomainCatalog
from app.models.ai_telemetry_event import AITelemetryEvent
from app.models.document_collection import DocumentCollection
from app.models.rag_document import Document
from app.models.document_chunk import DocumentChunk
from app.models.discovered_service import DiscoveredService
from app.models.service_connection import ServiceConnection
from app.models.agent import Agent, AgentKeyRevocation, AgentPolicy, AgentSigningKey
from app.models.delegation import DelegationChain, DelegationHop, DelegationNonce
from app.models.agent_action import AgentAction, AgentIncident, ActionCheck
from app.models.ai_system import AISystem, AISystemDataLink
from app.models.breaker import AgentBreakerSettings
from app.models.tool_registry import SupplyChainSettings, ToolRegistryEntry
from app.models.approval import AgentActionApproval
from app.models.behavior import AgentAnomaly, AgentBaseline, BehaviorSettings
from app.models.injection import InjectionDetection, InjectionSettings
from app.models.code_exec import CodeExecDetection, CodeExecSettings
from app.models.memory import MemoryEntry, MemorySettings
from app.models.a2a import A2AChannel, A2AMessage, A2ASettings
from app.models.agent_identity import AgentIdentitySettings
from app.models.gateway import GatewayCall, GatewayRoute, GatewaySettings
from app.models.queue_ttl import QueueSettings, QueueSweep
from app.models.org_key import ByokJob, OrgKey
from app.models.rag_query_log import RagQueryLog
from app.models.compliance import ComplianceAttestation, ComplianceReport
from app.models.endpoint_device import DiscoveredAgent, EndpointDevice
from app.models.enrollment import AgentEnrollment
from app.models.team import RoleTemplate, Team
from app.models.attestation import AgentAttestation, AttestationPolicy
from app.models.policy_layer import PolicyLayer
from app.models.kill_switch import KillSwitchEvent
from app.models.pii import PiiRule, PiiSettings
from app.models.blocked_term import BlockedTerm, BlockedTermCategory

__all__ = [
    "Organization",
    "User",
    "UserRole",
    "AIProvider",
    "AIPolicy",
    "AIPolicyVersion",
    "AIUseCase",
    "AIRequest",
    "AIResponse",
    "AIAction",
    "AIApproval",
    "AIIncident",
    "AIAuditLog",
    "AuditCheckpoint",
    "AuditSigningKey",
    "AuditKeyRotation",
    "AuditKeyRotationApproval",
    "AuditKeyHandover",
    "AIOverride",
    "ShadowAISighting",
    "Dataset",
    "TrainingJob",
    "NotificationChannel",
    "ModelDeployment",
    "PredictionLog",
    "IngestionSource",
    "AIDomainCatalog",
    "AITelemetryEvent",
    "DocumentCollection",
    "Document",
    "DocumentChunk",
    "DiscoveredService",
    "ServiceConnection",
    "Agent",
    "AgentPolicy",
    "AgentSigningKey",
    "AgentKeyRevocation",
    "AgentEnrollment",
    "Team",
    "RoleTemplate",
    "DelegationChain",
    "DelegationHop",
    "AgentAction",
    "AgentIncident",
    "EndpointDevice",
    "DiscoveredAgent",
]

# live agent events (after-commit session hook)
import app.core.obs_hooks  # noqa: E402,F401
