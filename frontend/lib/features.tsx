"use client";

// App-wide feature flags, fetched once on mount.
//
// The backend exposes the active set at /api/v1/auth/config under
// `features` (a small, public payload — it renders before auth).
// Pages and nav entries gate on a single key: content_safety hides the
// prompt firewall, PII masking, blocked terms, intent guardrail, and
// the injection / memory / code-exec guards when the operator has not
// opted into the content-safety add-on. Everything else is governance
// and is always on.

import React, { createContext, useContext, useEffect, useState } from "react";
import { getAuthConfig, type AppFeatures } from "./api";

const DEFAULT_FEATURES: AppFeatures = {
  content_safety: false,
};

interface FeaturesContextValue {
  features: AppFeatures;
  loading: boolean;
}

const Ctx = createContext<FeaturesContextValue>({
  features: DEFAULT_FEATURES,
  loading: true,
});

export function FeaturesProvider({ children }: { children: React.ReactNode }) {
  const [features, setFeatures] = useState<AppFeatures>(DEFAULT_FEATURES);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getAuthConfig()
      .then((c) => {
        if (cancelled) return;
        setFeatures(c.features ?? DEFAULT_FEATURES);
      })
      .catch(() => {
        if (cancelled) return;
        setFeatures(DEFAULT_FEATURES);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return <Ctx.Provider value={{ features, loading }}>{children}</Ctx.Provider>;
}

export function useFeatures(): FeaturesContextValue {
  return useContext(Ctx);
}
