// What the endpoint agent learned about a local model port (agent/collectors/modelapi.go),
// as the backend keeps it in a finding's display_meta: whether a model API answered there,
// which one, and its model names. Older agents say nothing about it: null.

export const SHOWN_MODELS = 5;

export interface PortSignal {
  confirmed: boolean;
  api: string | null;
  models: string[]; // the first SHOWN_MODELS
  more: number; // how many more there are
}

export function portSignal(meta: Record<string, unknown> | null | undefined): PortSignal | null {
  if (!meta || meta.kind !== "network" || typeof meta.confirmed !== "boolean") return null;
  const all = Array.isArray(meta.models) ? meta.models.filter((m): m is string => typeof m === "string") : [];
  return {
    confirmed: meta.confirmed,
    api: meta.confirmed && typeof meta.api === "string" ? meta.api : null,
    models: all.slice(0, SHOWN_MODELS),
    more: Math.max(0, all.length - SHOWN_MODELS),
  };
}
