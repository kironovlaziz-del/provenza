"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { useRouter } from "next/navigation";
import { clearToken, getMe, getToken, login as loginRequest, loginMfa, logoutRequest, setToken } from "./api";
import type { User } from "./types";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  /** Resolves with an mfaToken when a second factor is due (then call completeMfa). */
  login: (orgSlug: string, email: string, password: string) => Promise<{ mfaToken?: string }>;
  completeMfa: (mfaToken: string, code: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  const loadUser = useCallback(async () => {
    const token = getToken();
    if (!token) {
      setLoading(false);
      return;
    }
    try {
      const me = await getMe();
      setUser(me);
    } catch {
      clearToken();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUser();
  }, [loadUser]);

  const enter = useCallback(
    async (accessToken: string) => {
      setToken(accessToken);
      const me = await getMe();
      setUser(me);
      // Login always lands in the main app.
      router.push("/dashboard");
    },
    [router]
  );

  const login = useCallback(
    async (orgSlug: string, email: string, password: string) => {
      const result = await loginRequest(orgSlug, email, password);
      if (result.mfa_required && result.mfa_token) return { mfaToken: result.mfa_token };
      await enter(result.access_token as string);
      return {};
    },
    [enter]
  );

  const completeMfa = useCallback(
    async (mfaToken: string, code: string) => {
      const { access_token } = await loginMfa(mfaToken, code);
      await enter(access_token);
    },
    [enter]
  );

  const logout = useCallback(() => {
    const token = getToken();
    clearToken(); // forgotten here at once; the server revokes it in the background
    void logoutRequest(token);
    setUser(null);
    router.push("/login");
  }, [router]);

  return (
    <AuthContext.Provider value={{ user, loading, login, completeMfa, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}


