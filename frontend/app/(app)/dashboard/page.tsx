"use client";

// The old dashboard's address: its content now lives in the Inbox (summary
// beside the decisions). Sends each role to its start page in the console's mode.

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useAuth } from "@/lib/auth";
import { useConsoleMode } from "@/lib/console_mode";
import { homeFor } from "@/lib/navigation";

export default function DashboardRedirect() {
  const { user } = useAuth();
  const router = useRouter();
  const [mode] = useConsoleMode();
  useEffect(() => {
    if (user) router.replace(homeFor(user.role, mode));
  }, [user, router, mode]);
  return null;
}
