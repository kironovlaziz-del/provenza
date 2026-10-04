export type RiskLevel = "low" | "medium" | "high" | "critical";

export type UserRole = "admin" | "approver" | "user";

export interface User {
  id: number;
  org_id: number;
  email: string;
  name: string;
  role: "admin" | "approver" | "user";
  status: string;
  created_at: string;
}

export interface Policy {
  id: number;
  org_id: number;
  name: string;
  description?: string | null;
  status: string;
  created_at: string;
}

export interface PolicyVersion {
  id: number;
  policy_id: number;
  version: number;
  rules_json: Record<string, unknown>;
  created_by?: number | null;
  created_at: string;
  approved_by?: number | null;
  approved_at?: string | null;
}

export interface Provider {
  id: number;
  org_id: number;
  name: string;
  type: string;
  status: string;
  sla?: string | null;
  risk_score: number;
  base_url?: string | null;
  default_model?: string | null;
  has_credentials: boolean;
  created_at: string;
  updated_at?: string | null;
}

export interface UseCase {
  id: number;
  org_id: number;
  name: string;
  owner_user_id?: number | null;
  risk_level: RiskLevel;
  allowed_providers_json?: Record<string, unknown> | null;
  approved_policy_version_id?: number | null;
  status: string;
  created_at: string;
}

export interface AIRequest {
  id: number;
  org_id: number;
  use_case_id?: number | null;
  user_id?: number | null;
  provider_id?: number | null;
  // Raw prompt is not exposed - the backend only returns the masked
  // version produced by the Prompt Firewall.
  masked_input_text?: string | null;
  purpose?: string | null;
  risk_level: RiskLevel;
  status: string;
  firewall_flags?: string[] | null;
  created_at: string;
}

export interface AIResponse {
  id: number;
  request_id: number;
  provider_response_json?: Record<string, unknown> | null;
  response_text?: string | null;
  confidence_score?: number | null;
  created_at: string;
}

export interface Approval {
  id: number;
  request_id: number;
  approver_user_id?: number | null;
  decision?: string | null;
  reason?: string | null;
  created_at: string;
}

export interface Incident {
  id: number;
  org_id: number;
  request_id?: number | null;
  severity: RiskLevel;
  category: string;
  summary: string;
  impact?: string | null;
  root_cause?: string | null;
  status: string;
  created_at: string;
  resolved_at?: string | null;
}

export interface AuditLog {
  id: number;
  org_id: number;
  actor_user_id?: number | null;
  entity_type: string;
  entity_id?: number | null;
  action: string;
  metadata_json?: Record<string, unknown> | null;
  created_at: string;
}

export type OverrideType = "stop" | "edit" | "rollback";

export interface Override {
  id: number;
  request_id: number;
  override_type: OverrideType;
  override_payload_json?: Record<string, unknown> | null;
  operator_user_id?: number | null;
  created_at: string;
}

export type ShadowSightingStatus =
  | "new"
  | "reviewing"
  | "confirmed_shadow"
  | "dismissed"
  | "registered";

export interface ServiceConnection {
  id: number;
  org_id: number;
  discovered_service_id: number;
  service_type: string;
  host: string;
  port?: number | null;
  bind_dn?: string | null;
  base_dn?: string | null;
  username?: string | null;
  info?: Record<string, unknown> | null;
  last_verified_at?: string | null;
  last_error?: string | null;
  created_at: string;
  updated_at?: string | null;
}

export interface DiscoveredService {
  id: number;
  org_id: number;
  service_type: string;
  host: string;
  port?: number | null;
  discovered_via: string;
  details?: Record<string, unknown> | null;
  connect_status: string;
  connect_error?: string | null;
  connected_ref_type?: string | null;
  connected_ref_id?: number | null;
  first_seen_at: string;
  last_seen_at: string;
  connected_at?: string | null;
}

export interface ShadowSighting {
  id: number;
  org_id: number;
  tool_name: string;
  domain?: string | null;
  detected_via: string;
  user_hint?: string | null;
  notes?: string | null;
  status: ShadowSightingStatus;
  reported_by?: number | null;
  registered_provider_id?: number | null;
  display_meta?: Record<string, unknown> | null;
  seen_count?: number;
  last_seen_at?: string | null;
  created_at: string;
  resolved_at?: string | null;
}

export type NotificationChannelType = "email" | "webhook";

export interface NotificationChannel {
  id: number;
  org_id: number;
  channel_type: NotificationChannelType;
  target: string;
  events_json: string[];
  enabled: boolean;
  created_by?: number | null;
  created_at: string;
}

// ---- Shadow AI Monitor: telemetry ingestion (stage 1) ----

export type IngestionSourceType = "gateway" | "endpoint" | "browser_extension";

export interface IngestionSource {
  id: number;
  org_id: number;
  name: string;
  source_type: IngestionSourceType;
  enabled: boolean;
  last_seen_at?: string | null;
  created_at: string;
}

export interface IngestionSourceCreated extends IngestionSource {
  api_key: string;
}

export type DomainPolicyStatus = "allowed" | "blocked" | "unknown";

export interface DomainCatalogEntry {
  id: number;
  org_id: number;
  domain: string;
  tool_name?: string | null;
  category?: string | null;
  policy_status: DomainPolicyStatus;
  source?: string | null;
  created_at: string;
  updated_at?: string | null;
}

export interface SeedDomainHint {
  domain: string;
  tool_name: string;
  category: string;
}



