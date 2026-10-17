"use client";

import React from "react";
import { FeatureGate } from "@/components/FeatureGate";

// Content-safety add-on: hide the page entirely when
// CONTENT_SAFETY_ENABLED is off. A direct URL visit shows "Not Found".
export default function Layout({ children }: { children: React.ReactNode }) {
  return <FeatureGate name="content_safety">{children}</FeatureGate>;
}
