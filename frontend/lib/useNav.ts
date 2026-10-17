"use client";

import { useMemo } from "react";
import { useFeatures } from "./features";
import { visibleNav, type NavGroup, type Role } from "./navigation";

export function useVisibleNav(role: Role): NavGroup[] {
  const { features } = useFeatures();
  return useMemo(() => visibleNav(role, features), [role, features]);
}
