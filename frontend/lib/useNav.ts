"use client";

import { useMemo } from "react";
import { useFeatures } from "./features";
import { visibleNav, type NavGroup, type Role } from "./navigation";

export function useVisibleNav(role: Role, operator = false): NavGroup[] {
  const { features } = useFeatures();
  return useMemo(() => visibleNav(role, features, operator), [role, features, operator]);
}
