// AI Inventory types - mirror backend/app/schemas/ai_system.py

export type RiskTier = "unacceptable" | "high" | "limited" | "minimal";
export type LifecycleStage = "idea" | "development" | "validation" | "production" | "retired";
export type SystemKind = "agent" | "llm_provider" | "model" | "rag_app" | "shadow" | "other";
export type DataRelation = "trained_on" | "accesses";

export const RISK_TIERS: RiskTier[] = ["unacceptable", "high", "limited", "minimal"];
export const LIFECYCLE_STAGES: LifecycleStage[] = ["idea", "development", "validation", "production", "retired"];
export const SYSTEM_KINDS: SystemKind[] = ["agent", "llm_provider", "model", "rag_app", "shadow", "other"];

export interface DataLinkT {
  id: number;
  relation: DataRelation;
  dataset_id?: number | null;
  collection_id?: number | null;
  external_name?: string | null;
  contains_pii: boolean;
  notes?: string | null;
  created_at?: string | null;
}

export interface RiskRationaleItem {
  tier: RiskTier;
  reference: string;
}

export interface RiskAssessment {
  tier: RiskTier;
  rationale: RiskRationaleItem[];
  notes: string[];
  engine_version?: string;
}

export interface AISystemT {
  id: number;
  org_id: number;
  name: string;
  description?: string | null;
  kind: SystemKind;
  source_key?: string | null;
  agent_id?: number | null;
  provider_id?: number | null;
  deployment_id?: number | null;
  use_case_id?: number | null;
  shadow_tool?: string | null;
  owner_user_id?: number | null;
  business_owner?: string | null;
  lifecycle_stage: LifecycleStage;
  review_status: "unreviewed" | "reviewed";
  domain: string;
  risk_flags: string[];
  suggested_risk_tier?: RiskTier | null;
  risk_assessment?: RiskAssessment | null;
  confirmed_risk_tier?: RiskTier | null;
  risk_justification?: string | null;
  risk_confirmed_by?: number | null;
  risk_confirmed_at?: string | null;
  effective_risk_tier?: RiskTier | null;
  attention: string[];
  data_protection_notes: string[];
  data_links: DataLinkT[];
  created_at?: string | null;
  updated_at?: string | null;
}

export interface InventorySummary {
  total: number;
  by_tier: Record<string, number>;
  by_stage: Record<string, number>;
  unreviewed: number;
  in_production_without_confirmed_risk: number;
}

export interface InventoryDomain {
  id: string;
  label: string;
  annex_iii: string | null;
}

export interface InventoryMeta {
  domains: InventoryDomain[];
  flags: {
    prohibited: Record<string, string>;
    safety: Record<string, string>;
    transparency: Record<string, string>;
    modifiers: Record<string, string>;
  };
  tiers: RiskTier[];
  stages: LifecycleStage[];
  kinds: SystemKind[];
}

export interface SystemMetrics {
  window_days: number;
  source: string | null;
  counts: Record<string, number>;
  rates: Record<string, number>;
  last_activity_at: string | null;
  signals: string[];
}
