"use client";

// The old dashboard's address: its content now lives in the Inbox (summary
// beside the decisions). Sends each role to its start page.

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useAuth } from "@/lib/auth";
import { homeFor } from "@/lib/navigation";

export default function DashboardRedirect() {
  const { user } = useAuth();
  const router = useRouter();
  useEffect(() => {
    if (user) router.replace(homeFor(user.role));
  }, [user, router]);
  return null;
}
