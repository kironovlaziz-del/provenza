import { describe, expect, it } from "vitest";
import { shouldRenew, tokenTimes } from "@/lib/session_renewal";

const b64url = (o: object) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const jwt = (claims: object) => `${b64url({ alg: "HS256" })}.${b64url(claims)}.sig`;

describe("tokenTimes", () => {
  it("reads iat and exp, and nothing from a broken token", () => {
    expect(tokenTimes(jwt({ sub: "1", iat: 1000.5, exp: 2800, n: "ü?>" }))).toEqual({ iat: 1000.5, exp: 2800 });
    expect(tokenTimes("x.y.z")).toBeNull();
    expect(tokenTimes(null)).toBeNull();
    expect(tokenTimes(jwt({ sub: "1" }))).toBeNull();
  });
});

describe("shouldRenew", () => {
  const t = { iat: 1000, exp: 1000 + 30 * 60 };            // a 30-minute token
  const at = (minute: number) => (t.iat + minute * 60) * 1000;
  it("renews in the last 10 minutes after activity since the token was issued", () => {
    expect(shouldRenew(t, at(5), at(21))).toBe(true);
    expect(shouldRenew(t, at(5), at(19))).toBe(false);     // not yet
  });
  it("lets an idle sign-in run out", () => {
    expect(shouldRenew(t, at(-1), at(25))).toBe(false);    // no activity since the token
    expect(shouldRenew(t, at(5), at(31))).toBe(false);     // already over
  });
  it("renews a short token a third before its end, at least a minute", () => {
    const short = { iat: 0, exp: 120 };
    expect(shouldRenew(short, 1, 70_000)).toBe(true);
    expect(shouldRenew(short, 1, 50_000)).toBe(false);
  });
});
