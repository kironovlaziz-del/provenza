export type RiskLevel = "low" | "medium" | "high" | "critical";

export type UserRole = "admin" | "approver" | "user" | "auditor" | "compliance";

/** Read everything admins and approvers read (backend deps.require_role);
 *  an auditor changes nothing, a compliance officer confirms compliance. */
export const OVERSIGHT_ROLES: string[] = ["auditor", "compliance"];

export interface User {
  id: number;
  org_id: number;
  email: string;
  name: string;
  role: UserRole;
  status: string;
  created_at: string;
  totp_enabled?: boolean;
  /** provisioned by the identity provider (SCIM) */
  scim_managed?: boolean;
  /** an administrator of the organization that runs the installation
   *  (only /users/me says): sees installation-wide monitoring */
  is_operator?: boolean;
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
  credential_source?: "none" | "sealed" | "local";
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
  status: string;
  created_at: string;
}

export interface Incident {
  id: number;
  org_id: number;
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
  /** Position in the organization's hash chain (docs/audit-proofs.md). */
  seq?: number | null;
  prev_hash?: string | null;
  record_hash?: string | null;
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



