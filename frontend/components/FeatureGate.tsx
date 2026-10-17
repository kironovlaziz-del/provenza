"use client";

import React from "react";
import { useFeatures } from "@/lib/features";

interface FeatureGateProps {
  name: "content_safety";
  children: React.ReactNode;
}

export function FeatureGate({ name, children }: FeatureGateProps) {
  const { features, loading } = useFeatures();

  if (loading) {
    return (
      <div className="content">
        <div className="hint-text" style={{ padding: 40 }}>Loading…</div>
      </div>
    );
  }

  if (!features[name]) {
    return (
      <div className="content">
        <div className="panel">
          <div className="panel-body">Not Found</div>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
