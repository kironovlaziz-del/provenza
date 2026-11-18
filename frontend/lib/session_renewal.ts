// Renewing the sign-in while its person works (backend POST /auth/session/renew).
// A token lives ACCESS_TOKEN_EXPIRE_MINUTES (30 by default); shortly before it
// runs out, the console asks for a new one - but only if there was activity
// (a key, a click, a scroll, a touch) since the token was issued. Left idle for
// a token's lifetime, the sign-in ends; it ends SESSION_MAX_HOURS (8) after it
// began in any case: the server refuses to renew past that.

import { useEffect } from "react";
import { api, getToken, setToken } from "./api";

export interface TokenTimes { iat: number; exp: number }

/** iat and exp of a JWT (seconds), read without checking it: the server checks it. */
export function tokenTimes(token: string | null): TokenTimes | null {
  try {
    const part = (token ?? "").split(".")[1];
    if (!part) return null;
    const json = JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=")));
    return typeof json.iat === "number" && typeof json.exp === "number" ? { iat: json.iat, exp: json.exp } : null;
  } catch {
    return null;
  }
}

/** Time to ask for a new token: the person was active since this one was issued,
 * and it runs out within a third of its lifetime (at most 10 minutes, at least 1). */
export function shouldRenew(t: TokenTimes, lastActivityMs: number, nowMs: number): boolean {
  const left = t.exp * 1000 - nowMs;
  if (left <= 0 || lastActivityMs < t.iat * 1000) return false;
  const lifetime = (t.exp - t.iat) * 1000;
  return left <= Math.max(60_000, Math.min(10 * 60_000, lifetime / 3));
}

const ACTIVITY = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
const CHECK_MS = 30_000;

/** Keeps the sign-in alive while the person works (on while `enabled`). */
export function useSessionRenewal(enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    let last = Date.now();
    let busy = false;
    let over = false;              // the sign-in reached its maximum: let it end
    const seen = () => { last = Date.now(); };
    for (const e of ACTIVITY) window.addEventListener(e, seen, { passive: true });

    const tick = async () => {
      const token = getToken();
      const t = tokenTimes(token);
      if (busy || over || !t || !shouldRenew(t, last, Date.now())) return;
      busy = true;
      try {
        const { data } = await api.post<{ access_token: string }>("/auth/session/renew");
        if (getToken() === token) setToken(data.access_token);   // not signed out meanwhile
      } catch (err) {
        if ((err as { response?: { status?: number } })?.response?.status === 409) over = true;
      } finally {
        busy = false;
      }
    };
    const id = window.setInterval(() => void tick(), CHECK_MS);
    return () => {
      window.clearInterval(id);
      for (const e of ACTIVITY) window.removeEventListener(e, seen);
    };
  }, [enabled]);
}
