import type { NextConfig } from "next";

// Security headers for every page. The API sets its own (backend
// app/core/security_headers.py). Next.js puts small inline scripts in each
// page to hydrate it, so script-src needs 'unsafe-inline'; what CSP still
// gives here: no other origin's scripts, no framing (clickjacking), no plugins,
// no <base> or form hijacking, and API calls only to this site or the
// configured API origin.
const isProd = process.env.NODE_ENV === "production";

function apiOrigin(): string {
  const url = process.env.NEXT_PUBLIC_API_URL || "";
  try {
    return url.startsWith("http") ? new URL(url).origin : "";
  } catch {
    return "";
  }
}

const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isProd ? "" : " 'unsafe-eval'"}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self' ${apiOrigin()}`.trim(),
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  ...(isProd ? [{ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" }] : []),
];

const nextConfig: NextConfig = {
  agentRules: false,
  poweredByHeader: false,
  // pages merged into tabbed ones: old links land on the right tab
  async redirects() {
    return [
      { source: "/agent-incidents", destination: "/incidents?tab=agents", permanent: false },
      { source: "/agent-approvals", destination: "/approvals?tab=agents", permanent: false },
    ];
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
