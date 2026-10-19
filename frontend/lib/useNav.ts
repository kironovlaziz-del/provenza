"use client";

import { useMemo } from "react";
import { visibleNav, type NavGroup, type Role } from "./navigation";

export function useVisibleNav(role: Role, operator = false): NavGroup[] {
  return useMemo(() => visibleNav(role, operator), [role, operator]);
}
