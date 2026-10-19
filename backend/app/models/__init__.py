# Tables of removed features stay mapped: datasets, training_jobs,
# model_deployments, prediction_logs (MLOps) and document_collections,
# rag_documents, document_chunks, rag_query_logs (RAG). Their rows are kept,
# ai_systems / ai_system_data_links still reference them by foreign key, and
# leaving them out would make Alembic autogenerate propose dropping them.
# No application code reads or writes them any more.
from app.models.organization import Organization
from app.models.user import User, UserRole
from app.models.ai_provider import AIProvider
from app.models.ai_use_case import AIUseCase
from app.models.ai_incident import AIIncident
from app.models.audit_log import (AIAuditLog, AuditCheckpoint, AuditKeyHandover, AuditKeyRotation,
                                  AuditKeyRotationApproval, AuditSigningKey, AuditCheckpointTimestamp,
                                  AuditTsaSettings)
from app.models.shadow_ai_sighting import ShadowAISighting
from app.models.dataset import Dataset
from app.models.training_job import TrainingJob
from app.models.notification_channel import NotificationChannel
from app.models.model_deployment import ModelDeployment
from app.models.prediction_log import PredictionLog
from app.models.ingestion_source import IngestionSource
from app.models.export_key import ExportKey
from app.models.impact_assessment import ImpactAssessment
from app.models.assurance import AssuranceRecord
from app.models.ai_domain_catalog import AIDomainCatalog
from app.models.ai_telemetry_event import AITelemetryEvent
from app.models.document_collection import DocumentCollection
from app.models.rag_document import Document
from app.models.document_chunk import DocumentChunk
from app.models.discovered_service import DiscoveredService
from app.models.service_connection import ServiceConnection
from app.models.agent import Agent, AgentKeyRevocation, AgentPolicy, AgentSigningKey
from app.models.delegation import ActionNonce, DelegationChain, DelegationHop, DelegationNonce
from app.models.agent_action import AgentAction, AgentIncident, ActionCheck, PermitSigningKey
from app.models.ai_system import AISystem, AISystemDataLink
from app.models.breaker import AgentBreakerSettings
from app.models.tool_registry import SupplyChainSettings, ToolRegistryEntry
from app.models.approval import AgentActionApproval
from app.models.behavior import AgentAnomaly, AgentBaseline, BehaviorSettings
from app.models.agent_identity import AgentIdentitySettings
from app.models.gateway import GatewayCall, GatewayRoute, GatewaySettings
from app.models.retention import RetentionRun, RetentionSettings
from app.models.org_key import ByokJob, OrgKey
from app.models.rag_query_log import RagQueryLog
from app.models.compliance import ComplianceAttestation, ComplianceReport
from app.models.endpoint_device import DiscoveredAgent, EndpointDevice
from app.models.enrollment import AgentEnrollment
from app.models.team import RoleTemplate, Team
from app.models.attestation import AgentAttestation, AttestationPolicy
from app.models.policy_layer import PolicyLayer
from app.models.kill_switch import KillSwitchEvent
from app.models.pvp_guard import PVPGuardLog
from app.models.mcp import MCPServer, MCPTool
from app.models.http_tool import HttpTool
from app.models.scim import OidcSettings, ScimSettings
from app.models.egress_check import AgentEgressCheck
from app.models.a2a_gateway import A2APeer, A2ATask
from app.models.pvp_seal import PVPActionSeal
from app.models.egress_proxy import EgressProxy, EgressRedemption, EgressRoute
from app.models.egress_sensor import (EgressPolicyRevision, EgressPolicySettings, EgressSensor,
                                    EgressSensorWorkload, EgressViolation, EgressWorkload)

__all__ = [
    "Organization",
    "User",
    "UserRole",
    "AIProvider",
    "AIUseCase",
    "AIIncident",
    "AIAuditLog",
    "AuditCheckpoint",
    "AuditSigningKey",
    "AuditKeyRotation",
    "AuditKeyRotationApproval",
    "AuditKeyHandover",
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
    "EgressSensor",
    "EgressWorkload",
    "EgressPolicyRevision",
    "EgressPolicySettings",
    "EgressViolation",
]

# live agent events (after-commit session hook)
import app.core.obs_hooks  # noqa: E402,F401
