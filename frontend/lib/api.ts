import axios from "axios";
import type {
  User,
  Policy,
  PolicyVersion,
  Provider,
  UseCase,
  AIRequest,
  AIResponse,
  Approval,
  Incident,
  AuditLog,
  Override,
  OverrideType,
  ShadowSighting,
  NotificationChannel,
  NotificationChannelType,
  RiskLevel,
  IngestionSource,
  IngestionSourceCreated,
  IngestionSourceType,
  DomainCatalogEntry,
  DomainPolicyStatus,
  SeedDomainHint,
  DiscoveredService,
  ServiceConnection,
} from "./types";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export interface Page<T> {
  items: T[];
  total: number;
  skip: number;
  limit: number;
}

/**
 * The backend now returns list endpoints as `{items, total, skip, limit}`.
 * Most call sites only care about `items`, so this helper unwraps the
 * envelope. Screens that need `total` should call the corresponding
 * `...Page()` function instead.
 */
function unwrap<T>(p: Page<T>): T[] {
  return p.items;
}

export const api = axios.create({
  baseURL: API_BASE_URL,
});

const TOKEN_KEY = "ai_ct_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  window.localStorage.removeItem(TOKEN_KEY);
}

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (
      typeof window !== "undefined" &&
      error?.response?.status === 401 &&
      window.location.pathname !== "/login"
    ) {
      clearToken();
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

// ---- Auth ----
export async function login(orgSlug: string, email: string, password: string) {
  const { data } = await api.post<{ access_token: string; token_type: string }>(
    "/auth/login",
    { org_slug: orgSlug, email, password }
  );
  return data;
}

/** Public: what the sign-in screens may offer (self-service sign-up is off by default). */
export async function getAuthConfig(): Promise<{ signup_enabled: boolean }> {
  const { data } = await api.get<{ signup_enabled: boolean }>("/auth/config");
  return data;
}

export async function register(payload: {
  email: string;
  password: string;
  name: string;
  org_name: string;
  org_slug: string;
}) {
  const { data } = await api.post<User>("/users/register", payload);
  return data;
}

export async function getMe() {
  const { data } = await api.get<User>("/users/me");
  return data;
}


// ---- Users (admin-only management) ----
export async function listUsers() {
  const { data } = await api.get<Page<User>>("/users/");
  return unwrap(data);
}

export async function inviteUser(payload: {
  email: string;
  name: string;
  role: "admin" | "approver" | "user";
  password: string;
}) {
  const { data } = await api.post<User>("/users/invite", payload);
  return data;
}

export async function updateUserRole(id: number, role: "admin" | "approver" | "user") {
  const { data } = await api.put<User>(`/users/${id}/role`, { role });
  return data;
}

export async function updateUserStatus(id: number, status: "active" | "disabled") {
  const { data } = await api.put<User>(`/users/${id}/status`, { status });
  return data;
}

// ---- Policies (Policy Center) ----
export async function listPolicies() {
  const { data } = await api.get<Page<Policy>>("/policies/");
  return unwrap(data);
}

export async function listPoliciesPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<Policy>>("/policies/", { params: { skip, limit } });
  return data;
}

export async function getPolicy(id: number) {
  const { data } = await api.get<Policy>(`/policies/${id}`);
  return data;
}

export async function createPolicy(payload: { name: string; description?: string }) {
  const { data } = await api.post<Policy>("/policies/", payload);
  return data;
}

export async function listPolicyVersions(policyId: number) {
  const { data } = await api.get<PolicyVersion[]>(`/policies/${policyId}/versions`);
  return data;
}

export async function createPolicyVersion(
  policyId: number,
  rulesJson: Record<string, unknown>
) {
  const { data } = await api.post<PolicyVersion>(`/policies/${policyId}/versions`, {
    rules_json: rulesJson,
  });
  return data;
}

export async function archivePolicy(id: number) {
  const { data } = await api.post(`/policies/${id}/archive`);
  return data;
}

export async function activatePolicy(id: number) {
  const { data } = await api.post(`/policies/${id}/activate`);
  return data;
}


export async function approvePolicyVersion(policyId: number, versionId: number) {
  const { data } = await api.post<PolicyVersion>(
    `/policies/${policyId}/versions/${versionId}/approve`
  );
  return data;
}

// ---- Providers (Vendor Risk Desk) ----
export interface ProviderChatResult {
  answer: string;
  masked: boolean;
  flags: string[];
  blocked: boolean;
  blocked_reason?: string | null;
}

export async function listProviderModels(providerId: number) {
  const { data } = await api.get<{ models: string[]; note?: string }>(`/providers/${providerId}/models`);
  return data;
}

export async function providerChat(providerId: number, message: string, systemPrompt?: string, model?: string) {
  const { data } = await api.post<ProviderChatResult>(`/providers/${providerId}/chat`, {
    message,
    system_prompt: systemPrompt,
    model,
  });
  return data;
}

export async function listProviders() {
  const { data } = await api.get<Page<Provider>>("/providers/");
  return unwrap(data);
}

export async function listProvidersPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<Provider>>("/providers/", { params: { skip, limit } });
  return data;
}

export async function createProvider(payload: {
  name: string;
  type: string;
  status?: string;
  sla?: string;
  risk_score?: number;
  base_url?: string;
  default_model?: string;
  api_key?: string;
}) {
  const { data } = await api.post<Provider>("/providers/", payload);
  return data;
}

export async function updateProvider(
  id: number,
  payload: Partial<{
    name: string;
    type: string;
    status: string;
    sla: string;
    risk_score: number;
    base_url: string;
    default_model: string;
    api_key: string;
  }>
) {
  const { data } = await api.put<Provider>(`/providers/${id}`, payload);
  return data;
}

// ---- Use cases ----
export async function listUseCases() {
  const { data } = await api.get<Page<UseCase>>("/use-cases/");
  return unwrap(data);
}

export async function listUseCasesPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<UseCase>>("/use-cases/", { params: { skip, limit } });
  return data;
}

export async function getUseCase(id: number) {
  const { data } = await api.get<UseCase>(`/use-cases/${id}`);
  return data;
}

export async function createUseCase(payload: {
  name: string;
  risk_level: RiskLevel;
  owner_user_id?: number;
  approved_policy_version_id?: number;
}) {
  const { data } = await api.post<UseCase>("/use-cases/", payload);
  return data;
}

export async function updateUseCase(
  id: number,
  payload: Partial<{
    name: string;
    risk_level: RiskLevel;
    status: string;
    approved_policy_version_id: number;
  }>
) {
  const { data } = await api.put<UseCase>(`/use-cases/${id}`, payload);
  return data;
}

// ---- Requests (Usage Registry / Action Trace) ----
export async function listRequests() {
  const { data } = await api.get<Page<AIRequest>>("/requests/");
  return unwrap(data);
}

export async function listRequestsPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<AIRequest>>("/requests/", { params: { skip, limit } });
  return data;
}

export async function getRequest(id: number) {
  const { data } = await api.get<AIRequest>(`/requests/${id}`);
  return data;
}

export async function getRequestResponse(id: number) {
  const { data } = await api.get<AIResponse | null>(`/requests/${id}/response`);
  return data;
}

export async function createRequest(payload: {
  use_case_id: number;
  provider_id: number;
  input_text: string;
  purpose: string;
}) {
  const { data } = await api.post<AIRequest>("/requests/", payload);
  return data;
}

// ---- Approvals ----
export async function listApprovals() {
  const { data } = await api.get<Page<Approval>>("/approvals/");
  return unwrap(data);
}

export async function listApprovalsPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<Approval>>("/approvals/", { params: { skip, limit } });
  return data;
}

export async function createApproval(payload: { request_id: number }) {
  const { data } = await api.post<Approval>("/approvals/", payload);
  return data;
}

export async function decideApproval(
  id: number,
  payload: { decision: "approved" | "rejected"; reason?: string }
) {
  const { data } = await api.post<Approval>(`/approvals/${id}/decision`, payload);
  return data;
}

// ---- Incidents ----
export async function listIncidents() {
  const { data } = await api.get<Page<Incident>>("/incidents/");
  return unwrap(data);
}

export async function listIncidentsPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<Incident>>("/incidents/", { params: { skip, limit } });
  return data;
}

export async function getIncident(id: number) {
  const { data } = await api.get<Incident>(`/incidents/${id}`);
  return data;
}

export async function createIncident(payload: {
  request_id?: number;
  severity: RiskLevel;
  category: string;
  summary: string;
  impact?: string;
}) {
  const { data } = await api.post<Incident>("/incidents/", payload);
  return data;
}

export async function updateIncident(
  id: number,
  payload: Partial<{
    severity: RiskLevel;
    category: string;
    summary: string;
    impact: string;
    root_cause: string;
    status: string;
  }>
) {
  const { data } = await api.put<Incident>(`/incidents/${id}`, payload);
  return data;
}

// ---- Audit & Reporting ----
export async function listAuditLogs(filters?: {
  entity_type?: string;
  entity_id?: number;
  actor_user_id?: number;
  skip?: number;
  limit?: number;
}) {
  const params = new URLSearchParams();
  if (filters?.skip) params.set("skip", String(filters.skip));
  if (filters?.limit) params.set("limit", String(filters.limit));
  if (filters?.entity_type) params.set("entity_type", filters.entity_type);
  if (filters?.entity_id != null) params.set("entity_id", String(filters.entity_id));
  if (filters?.actor_user_id != null)
    params.set("actor_user_id", String(filters.actor_user_id));
  const qs = params.toString();
  const { data } = await api.get<Page<AuditLog>>(`/audit-logs/${qs ? `?${qs}` : ""}`);
  return unwrap(data);
}

// ---- Override Console ----
export async function listOverrides(requestId: number) {
  const { data } = await api.get<Page<Override>>("/overrides/", {
    params: { request_id: requestId },
  });
  return unwrap(data);
}

export async function createOverride(payload: {
  request_id: number;
  override_type: OverrideType;
  override_payload_json?: Record<string, unknown>;
}) {
  const { data } = await api.post<Override>("/overrides/", payload);
  return data;
}

// ---- Shadow AI Monitor ----
export async function listShadowSightings(statusFilter?: string) {
  const { data } = await api.get<Page<ShadowSighting>>("/shadow-ai/", {
    params: statusFilter ? { status_filter: statusFilter } : undefined,
  });
  return unwrap(data);
}

export async function createShadowSighting(payload: {
  tool_name: string;
  domain?: string;
  detected_via?: string;
  user_hint?: string;
  notes?: string;
}) {
  const { data } = await api.post<ShadowSighting>("/shadow-ai/", payload);
  return data;
}

export async function updateShadowSighting(
  id: number,
  payload: { status?: string; notes?: string }
) {
  const { data } = await api.put<ShadowSighting>(`/shadow-ai/${id}`, payload);
  return data;
}

export async function registerShadowSighting(
  id: number,
  payload?: { provider_type?: string; provider_sla?: string }
) {
  const { data } = await api.post<ShadowSighting>(`/shadow-ai/${id}/register`, payload || {});
  return data;
}

// ---- Notification Service ----
export async function listNotificationChannels() {
  const { data } = await api.get<Page<NotificationChannel>>("/notification-channels/");
  return unwrap(data);
}

export async function listNotificationChannelsPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<NotificationChannel>>("/notification-channels/", { params: { skip, limit } });
  return data;
}

export async function getNotificationEventTypes() {
  const { data } = await api.get<{ event_types: string[] }>(
    "/notification-channels/event-types"
  );
  return data.event_types;
}

export async function createNotificationChannel(payload: {
  channel_type: NotificationChannelType;
  target: string;
  events: string[];
  enabled?: boolean;
}) {
  const { data } = await api.post<NotificationChannel>("/notification-channels/", payload);
  return data;
}

export async function updateNotificationChannel(
  id: number,
  payload: Partial<{ target: string; events: string[]; enabled: boolean }>
) {
  const { data } = await api.put<NotificationChannel>(`/notification-channels/${id}`, payload);
  return data;
}

export async function deleteNotificationChannel(id: number) {
  await api.delete(`/notification-channels/${id}`);
}

export async function testNotificationChannel(id: number) {
  await api.post(`/notification-channels/${id}/test`);
}

// ---- Dashboard stats ----
export interface DayBucket {
  date: string;
  total: number;
  completed: number;
  blocked: number;
  failed: number;
}

export interface DashboardStats {
  window_days: number;
  requests_by_day: DayBucket[];
  requests_by_status: Record<string, number>;
  incidents_by_severity: Record<string, number>;
  total_requests: number;
  total_incidents: number;
  pending_approvals: number;
  total_policies: number;
}

export async function fetchDashboardStats(days = 7): Promise<DashboardStats> {
  const { data } = await api.get<DashboardStats>("/dashboard/stats", {
    params: { days },
  });
  return data;
}

// ---- Shadow AI Monitor: ingestion sources ----

export async function listIngestionSources() {
  const { data } = await api.get<Page<IngestionSource>>("/ingestion-sources/");
  return unwrap(data);
}

export async function createIngestionSource(payload: {
  name: string;
  source_type: IngestionSourceType;
}) {
  const { data } = await api.post<IngestionSourceCreated>("/ingestion-sources/", payload);
  return data;
}

export async function updateIngestionSource(
  id: number,
  payload: Partial<{ name: string; enabled: boolean }>
) {
  const { data } = await api.put<IngestionSource>(`/ingestion-sources/${id}`, payload);
  return data;
}

export async function revokeIngestionSource(id: number) {
  const { data } = await api.delete<IngestionSource>(`/ingestion-sources/${id}`);
  return data;
}

// ---- Shadow AI Monitor: AI domain catalog ----

export async function importKnownDomains() {
  const { data } = await api.post<{ added: number; skipped: number; total_seed: number }>(
    "/domain-catalog/import-known"
  );
  return data;
}

export async function listDomainCatalog() {
  const { data } = await api.get<Page<DomainCatalogEntry>>("/domain-catalog/");
  return unwrap(data);
}

export async function getDomainCatalogSeedSuggestions() {
  const { data } = await api.get<{ suggestions: SeedDomainHint[] }>(
    "/domain-catalog/seed-suggestions"
  );
  return data.suggestions;
}

export async function createDomainCatalogEntry(payload: {
  domain: string;
  tool_name?: string;
  category?: string;
  policy_status: DomainPolicyStatus;
}) {
  const { data } = await api.post<DomainCatalogEntry>("/domain-catalog/", payload);
  return data;
}

export async function updateDomainCatalogEntry(
  id: number,
  payload: Partial<{ tool_name: string; category: string; policy_status: DomainPolicyStatus }>
) {
  const { data } = await api.put<DomainCatalogEntry>(`/domain-catalog/${id}`, payload);
  return data;
}

export async function deleteDomainCatalogEntry(id: number) {
  await api.delete(`/domain-catalog/${id}`);
}

// ---- Shadow AI Monitor: summary counts ----
export async function getShadowAISummary() {
  const { data } = await api.get<Record<string, number>>("/shadow-ai/summary");
  return data;
}

// ---- Incidents: simple status-only update wrapper ----
export async function updateIncidentStatus(id: number, status: string) {
  const { data } = await api.put<Incident>(`/incidents/${id}`, { status });
  return data;
}

// ---- Network discovery (explicit-connect wizard) ----
export async function listDiscoveredServices() {
  const { data } = await api.get<Page<DiscoveredService>>("/discovery/");
  return unwrap(data);
}

export async function connectDiscoveredService(
  id: number,
  creds: {
    username?: string;
    password?: string;
    bind_dn?: string;
    base_dn?: string;
    api_token?: string;
    extra?: Record<string, unknown>;
    /** The host/port shown to the admin; the server refuses if the record changed. */
    expected_host?: string;
    expected_port?: number | null;
    /** LDAP/AD: PEM of an in-house CA that issued the directory's certificate. */
    tls_ca_pem?: string;
  }
) {
  const { data } = await api.post<DiscoveredService>(`/discovery/${id}/connect`, creds);
  return data;
}

export async function ignoreDiscoveredService(id: number, reason?: string) {
  const { data } = await api.post<DiscoveredService>(`/discovery/${id}/ignore`, { reason });
  return data;
}


// ---- Browser extension self-service download ----
export async function downloadBrowserExtension() {
  const response = await api.get("/shadow-ai/extension/download", {
    responseType: "blob",
  });
  const blob = new Blob([response.data], { type: "application/zip" });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "shadow-ai-extension.zip";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}


// ---- Discovered service connection details ----
export async function getServiceConnection(serviceId: number) {
  const { data } = await api.get<ServiceConnection | null>(
    `/discovery/${serviceId}/connection`
  );
  return data;
}


export async function reverifyServiceConnection(serviceId: number) {
  const { data } = await api.post<ServiceConnection | null>(
    `/discovery/${serviceId}/reverify`
  );
  return data;
}
