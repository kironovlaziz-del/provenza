"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { useRouter } from "next/navigation";
import { clearToken, getMe, getToken, login as loginRequest, loginMfa, logoutRequest, setToken, ssoExchange } from "./api";
import { certifySession, getSession, revocation, type SessionState } from "./signing";
import type { User } from "./types";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  /** Resolves with an mfaToken when a second factor is due (then call completeMfa). */
  login: (orgSlug: string, email: string, password: string) => Promise<{ mfaToken?: string }>;
  completeMfa: (mfaToken: string, code: string) => Promise<void>;
  /** The one-time code single sign-on hands back (/login/sso). */
  completeSso: (code: string) => Promise<void>;
  logout: () => void;
  /** This sign-in, for a person who signs (administrator, approver); null otherwise. */
  session: SessionState | null;
  /** Re-read the session (and, once it is let in, the user). */
  refreshSession: () => Promise<SessionState | null>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [session, setSession] = useState<SessionState | null>(null);
  const router = useRouter();

  const loadUser = useCallback(async () => {
    const token = getToken();
    if (!token) {
      setLoading(false);
      return;
    }
    try {
      const s = await getSession();
      setSession(s);
      // a blocked sign-in has no user yet: it waits on the sign-in page
      setUser(s.status === "blocked" ? null : await getMe());
    } catch {
      clearToken();
      setUser(null);
      setSession(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshSession = useCallback(async () => {
    try {
      const s = await getSession();
      setSession(s);
      if (s.status === "active" && !user) setUser(await getMe());
      return s;
    } catch (err) {
      // the session ended meanwhile (refused, taken over, expired): start over
      if ((err as { response?: { status?: number } })?.response?.status === 401) {
        clearToken();
        setUser(null);
        setSession(null);
        if (typeof window !== "undefined") window.location.href = "/login?ended=1";
      }
      return null;
    }
  }, [user]);

  useEffect(() => {
    loadUser();
  }, [loadUser]);

  const enter = useCallback(
    async (accessToken: string) => {
      setToken(accessToken);
      const s = await getSession();
      setSession(s);
      if (s.status === "blocked") return; // the sign-in page shows the wait
      const me = await getMe();
      setUser(me);
      // one PIN prompt per sign-in; if it is cancelled, the app offers it again
      if (s.signing && s.has_passkey && !s.certified) {
        try {
          await certifySession(s);
          setSession(await getSession());
        } catch {
          // not now: the banner in the app asks again
        }
      }
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

  const completeSso = useCallback(
    async (code: string) => {
      const { access_token } = await ssoExchange(code);
      await enter(access_token);
    },
    [enter]
  );

  const logout = useCallback(() => {
    const token = getToken();
    const sid = session?.session_id ?? null;
    clearToken(); // forgotten here at once; the server revokes it in the background
    // the session key signs its own revocation and is deleted from this browser
    void revocation(sid).then((r) => logoutRequest(token, r));
    setUser(null);
    setSession(null);
    router.push("/login");
  }, [router, session]);

  return (
    <AuthContext.Provider value={{ user, loading, login, completeMfa, completeSso, logout, session, refreshSession }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}


