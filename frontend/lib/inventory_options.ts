// AI Inventory: option lists for the system page pickers and the reference
// fields that live outside updateSystem() (owner, use case).
import { api } from "./api";
import type { AISystemT } from "./inventory_types";

export interface Option {
  id: number;
  name: string;
}

function rows(data: any): any[] {
  return Array.isArray(data) ? data : data?.items ?? [];
}

export async function listUserOptions(): Promise<Option[]> {
  const { data } = await api.get("/users/", { params: { limit: 200 } });
  return rows(data).map((u) => ({ id: u.id, name: u.full_name || u.name || u.email || `#${u.id}` }));
}

export async function listUseCaseOptions(): Promise<Option[]> {
  const { data } = await api.get("/use-cases/", { params: { limit: 200 } });
  return rows(data).map((u) => ({ id: u.id, name: u.name || u.title || `#${u.id}` }));
}

export async function updateSystemRefs(
  id: number,
  payload: { owner_user_id?: number | null; use_case_id?: number | null },
) {
  const { data } = await api.patch<AISystemT>(`/inventory/${id}`, payload);
  return data;
}
