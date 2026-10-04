// AI Inventory API calls. Reuses the shared axios instance and Page<T>
// convention from api.ts.
import { api, Page } from "./api";
import type {
  AISystemT,
  DataRelation,
  InventoryMeta,
  InventorySummary,
  LifecycleStage,
  RiskTier,
  SystemKind,
  SystemMetrics,
} from "./inventory_types";

export interface InventoryFilters {
  kind?: string;
  stage?: string;
  tier?: string;
  review_status?: string;
  q?: string;
}

export async function listSystems(filters: InventoryFilters = {}, skip = 0, limit = 100) {
  const params: Record<string, string | number> = { skip, limit };
  for (const [key, value] of Object.entries(filters)) {
    if (value) params[key] = value;
  }
  const { data } = await api.get<Page<AISystemT>>("/inventory/", { params });
  return data;
}

export async function getSystem(id: number) {
  const { data } = await api.get<AISystemT>(`/inventory/${id}`);
  return data;
}

export async function createSystem(payload: {
  name: string;
  kind: SystemKind;
  domain: string;
  lifecycle_stage: "idea" | "development" | "validation";
  description?: string;
  risk_flags?: string[];
}) {
  const { data } = await api.post<AISystemT>("/inventory/", payload);
  return data;
}

export async function updateSystem(
  id: number,
  payload: Partial<{
    name: string;
    description: string | null;
    business_owner: string | null;
    domain: string;
    risk_flags: string[];
  }>,
) {
  const { data } = await api.patch<AISystemT>(`/inventory/${id}`, payload);
  return data;
}

export async function changeStage(id: number, stage: LifecycleStage) {
  const { data } = await api.post<AISystemT>(`/inventory/${id}/stage`, { stage });
  return data;
}

export async function confirmRisk(id: number, tier: RiskTier, justification?: string) {
  const { data } = await api.post<AISystemT>(`/inventory/${id}/confirm-risk`, {
    tier,
    justification: justification || null,
  });
  return data;
}

export async function addDataLink(
  id: number,
  payload: {
    relation: DataRelation;
    external_name: string;
    contains_pii: boolean;
  },
) {
  const { data } = await api.post<AISystemT>(`/inventory/${id}/data-links`, payload);
  return data;
}

export async function removeDataLink(id: number, linkId: number) {
  const { data } = await api.delete<AISystemT>(`/inventory/${id}/data-links/${linkId}`);
  return data;
}

export async function getSystemMetrics(id: number, days = 30) {
  const { data } = await api.get<SystemMetrics>(`/inventory/${id}/metrics`, { params: { days } });
  return data;
}

export async function getInventorySummary() {
  const { data } = await api.get<InventorySummary>("/inventory/summary");
  return data;
}

export async function getInventoryMeta() {
  const { data } = await api.get<InventoryMeta>("/inventory/meta");
  return data;
}

export async function syncInventory() {
  const { data } = await api.post<{ created: number }>("/inventory/sync");
  return data;
}

export function apiErrorMessage(err: unknown, fallback: string): string {
  const detail = (err as any)?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg);
  return fallback;
}
