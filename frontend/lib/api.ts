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
  Dataset,
  ComputeStatus,
  TrainingJob,
  TrainingTaskType,
  TrainingAlgorithm,
  AllowedModelsResponse,
  ModelDeployment,
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
}) {
  const params = new URLSearchParams();
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

// ---- MLOps: Compute Detector ----
export async function getComputeStatus() {
  const { data } = await api.get<ComputeStatus>("/compute/status");
  return data;
}

// ---- MLOps: Dataset Manager ----
export async function listDatasets() {
  const { data } = await api.get<Page<Dataset>>("/datasets/");
  return unwrap(data);
}

export async function listDatasetsPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<Dataset>>("/datasets/", { params: { skip, limit } });
  return data;
}

export async function uploadDataset(payload: {
  name: string;
  description?: string;
  task_type: string;
  file: File;
}) {
  const form = new FormData();
  form.append("name", payload.name);
  if (payload.description) form.append("description", payload.description);
  form.append("task_type", payload.task_type);
  form.append("file", payload.file);
  const { data } = await api.post<Dataset>("/datasets/", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function deleteDataset(id: number) {
  await api.delete(`/datasets/${id}`);
}

// ---- MLOps: Training Service ----
export async function listTrainingJobs() {
  const { data } = await api.get<Page<TrainingJob>>("/training-jobs/");
  return unwrap(data);
}

export async function listTrainingJobsPage(skip = 0, limit = 50) {
  const { data } = await api.get<Page<TrainingJob>>("/training-jobs/", { params: { skip, limit } });
  return data;
}

export async function getTrainingJob(id: number) {
  const { data } = await api.get<TrainingJob>(`/training-jobs/${id}`);
  return data;
}

export async function createTrainingJob(payload: {
  dataset_id: number;
  name: string;
  task_type: TrainingTaskType;
  target_column?: string;
  // Algorithm ids now come from the backend registry (fetchAlgorithms),
  // so this is a plain string rather than a hardcoded union type.
  algorithm?: string;
  base_model?: string;
  hyperparameters?: Record<string, unknown>;
  // Optuna auto-tune - runs a hyperparameter search before
  // training the final model.
  auto_tune?: boolean;
  auto_tune_trials?: number;
}) {
  const { data } = await api.post<TrainingJob>("/training-jobs/", payload);
  return data;
}

export async function getAllowedModels(taskType: string = "transformer_text_classification") {
  const { data } = await api.get<AllowedModelsResponse>("/compute/allowed-models", {
    params: { task_type: taskType },
  });
  return data;
}

export async function cancelTrainingJob(id: number) {
  const { data } = await api.post<TrainingJob>(`/training-jobs/${id}/cancel`);
  return data;
}

export async function retryTrainingJob(id: number) {
  const { data } = await api.post<TrainingJob>(`/training-jobs/${id}/retry`);
  return data;
}

/**
 * Trigger a streaming download of a training job's model artifact.
 *
 * The backend issues a short-lived, single-purpose token via POST
 * /training-jobs/{id}/download-token, then the browser navigates directly
 * to the streaming download URL. This keeps large model files out of
 * JavaScript memory - a 1 GB model would otherwise be buffered twice
 * (once in axios, once in the resulting Blob).
 */
export async function downloadTrainingJobModel(id: number, filenameHint: string) {
  const { data } = await api.post<{ token: string; expires_in: number }>(
    `/training-jobs/${id}/download-token`
  );
  const url = `${API_BASE_URL}/training-jobs/${id}/download?token=${encodeURIComponent(data.token)}`;

  // Native navigation so the browser streams the response to disk.
  const link = document.createElement("a");
  link.href = url;
  link.download = filenameHint;
  document.body.appendChild(link);
  link.click();
  link.remove();
}

export async function predictWithTrainingJob(
  id: number,
  features: Record<string, unknown>
) {
  const { data } = await api.post<{ prediction: unknown }>(
    `/training-jobs/${id}/predict`,
    { features }
  );
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

// ---- Training algorithms registry ----
export interface AlgorithmHyperparam {
  name: string;
  label_key: string;
  type: "int" | "float" | "select";
  default: number | string | null;
  min?: number;
  max?: number;
  options?: { value: string; label_key: string }[];
}

export interface AlgorithmInfo {
  id: string;
  label_key: string;
  task_types: string[];
  hyperparameters: AlgorithmHyperparam[];
}

export async function fetchAlgorithms(taskType?: string) {
  const { data } = await api.get<{ algorithms: AlgorithmInfo[] }>(
    "/training-jobs/algorithms",
    { params: taskType ? { task_type: taskType } : undefined },
  );
  return data.algorithms;
}

// ---- Deployment Manager ----
export async function listDeployments() {
  const { data } = await api.get<Page<ModelDeployment>>("/deployments/");
  return unwrap(data);
}

export async function createDeployment(payload: {
  training_job_id: number;
  name: string;
  description?: string;
  version?: number;
  traffic_weight?: number;
}) {
  const { data } = await api.post<ModelDeployment>("/deployments/", payload);
  return data;
}

export async function getDeployment(id: number) {
  const { data } = await api.get<ModelDeployment>(`/deployments/${id}`);
  return data;
}

export async function updateDeployment(
  id: number,
  payload: Partial<{
    description: string;
    status: "active" | "inactive" | "archived";
    traffic_weight: number;
  }>,
) {
  const { data } = await api.put<ModelDeployment>(`/deployments/${id}`, payload);
  return data;
}

export async function deleteDeployment(id: number) {
  await api.delete(`/deployments/${id}`);
}

export async function predictViaDeployment(
  id: number,
  features: Record<string, unknown>,
) {
  const { data } = await api.post<{
    deployment_id: number;
    version: number;
    prediction: unknown;
  }>(`/deployments/${id}/predict`, { features });
  return data;
}

// ---- Playground chat ----
export interface DeploymentChatResponse {
  deployment_id: number;
  version: number;
  model_type: string;
  response: string;
  latency_ms: number;
  raw: unknown;
}

export async function chatWithDeployment(
  id: number,
  message: string,
): Promise<DeploymentChatResponse> {
  const { data } = await api.post<DeploymentChatResponse>(
    `/deployments/${id}/chat`,
    { message },
  );
  return data;
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
  training_by_status: Record<string, number>;
  deployments_by_status: Record<string, number>;
  total_requests: number;
  total_incidents: number;
  total_training_jobs: number;
  total_deployments: number;
  active_deployments: number;
  pending_approvals: number;
  total_datasets: number;
  total_policies: number;
}

export async function fetchDashboardStats(days = 7): Promise<DashboardStats> {
  const { data } = await api.get<DashboardStats>("/dashboard/stats", {
    params: { days },
  });
  return data;
}

// ---- Deployment Monitoring ----
export interface MonitoringDay {
  date: string;
  count: number;
}

export interface DeploymentMonitoring {
  deployment_id: number;
  deployment_name: string;
  deployment_version: number;
  window_days: number;
  total_predictions: number;
  predictions_by_day: MonitoringDay[];
  predictions_by_class: Record<string, number>;
  latency_ms: { min: number | null; avg: number | null; max: number | null };
  feedback: Record<string, number>;
  recent_predictions: Array<{
    id: number;
    prediction: string | null;
    latency_ms: number | null;
    features: Record<string, unknown> | null;
    created_at: string;
  }>;
}

export async function fetchDeploymentMonitoring(
  id: number,
  days = 7,
): Promise<DeploymentMonitoring> {
  const { data } = await api.get<DeploymentMonitoring>(
    `/deployments/${id}/monitoring`,
    { params: { days } },
  );
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

// ---- Personal UI mode preference (Simple Mode wizard entry point) ----
export async function updateMyUIMode(uiMode: "simple" | "advanced") {
  const { data } = await api.put<User>("/users/me/ui-mode", { ui_mode: uiMode });
  return data;
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

// ---- Simple Mode wizard ----
export interface ParsedQAPair {
  question: string;
  answer: string;
}

export interface ParseUploadResponse {
  qa_pairs: ParsedQAPair[];
  error_row_count: number;
  has_unstructured_text: boolean;
  detected_columns: string[] | null;
  preview_text: string | null;
  recommended_approach: string;
  recommended_reason: string;
}

export async function parseWizardUpload(file: File, taskType: string) {
  const form = new FormData();
  form.append("file", file);
  form.append("task_type", taskType);
  const { data } = await api.post<ParseUploadResponse>("/simple-mode/parse-upload", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function previewWizardChat(payload: {
  message: string;
  system_prompt?: string;
  provider_id: number;
}) {
  const { data } = await api.post<{ answer: string }>("/simple-mode/preview-chat", payload);
  return data;
}

export async function recommendApproach(payload: {
  task_type: string;
  has_documents: boolean;
  qa_pair_count: number;
}) {
  const { data } = await api.post<{ approach: string; reason: string }>(
    "/rag/recommend-approach",
    payload
  );
  return data;
}

export async function finalizeWizardRAG(payload: {
  name: string;
  systemPrompt: string;
  qaPairs: { question: string; answer: string }[];
  files: File[];
}) {
  const form = new FormData();
  form.append("name", payload.name);
  form.append("system_prompt", payload.systemPrompt);
  form.append("qa_pairs_json", JSON.stringify(payload.qaPairs));
  for (const f of payload.files) form.append("files", f);
  const { data } = await api.post<{ collection_id: number; document_statuses: string[] }>(
    "/simple-mode/finalize-rag",
    form,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  return data;
}

export interface RagCollectionInfo {
  id: number;
  name: string;
  document_count: number;
  chunk_count: number;
}

export async function getRagCollection(id: number) {
  const { data } = await api.get<RagCollectionInfo>(`/rag/collections/${id}`);
  return data;
}

export async function chatWithRagCollection(
  collectionId: number,
  message: string,
  providerId: number
) {
  const { data } = await api.post<{
    answer: string;
    sources: { chunk_id: number; document_id: number; text: string; score: number }[];
  }>(`/rag/collections/${collectionId}/chat`, { message, provider_id: providerId });
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
