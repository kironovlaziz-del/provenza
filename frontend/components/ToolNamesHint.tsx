// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

"use client";

import React from "react";
import { useTranslation } from "react-i18next";
import type { GatewayTool } from "@/lib/agent_api";
import { toolNameProblems } from "@/lib/tool_names";

/** Under an "Allowed tools" field: the names the agent's gateways will not show it. */
export function ToolNamesHint({ names, known }: { names: string[]; known: GatewayTool[] | null }) {
  const { t } = useTranslation();
  const { unknown, notApproved } = toolNameProblems(names, known);
  if (!unknown.length && !notApproved.length) return null;
  return (
    <div className="hint-text tool-names-hint" role="status">
      {unknown.length > 0 && <p className="warn-text">{t("agents.tool_unknown", { names: unknown.join(", ") })}</p>}
      {notApproved.length > 0 && <p className="warn-text">{t("agents.tool_not_approved", { names: notApproved.join(", ") })}</p>}
    </div>
  );
}
