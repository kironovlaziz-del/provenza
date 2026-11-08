import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";
import { I18nProvider } from "@/components/I18nProvider";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://stickstock.lol"),
  title: { default: "Provenza — open-source AI governance for AI agents", template: "%s · Provenza" },
  description:
    "Provenza is open-source, self-hosted AI governance: find shadow AI, keep a registry of AI agents, check every agent action against policy before it runs, and keep a signed, tamper-evident audit log.",
  applicationName: "Provenza",
  keywords: ["AI governance", "AI agent governance", "shadow AI detection", "MCP gateway", "AI audit log", "open source", "self-hosted"],
  openGraph: {
    title: "Provenza — open-source AI governance for AI agents",
    description: "Provenance for every AI action — self-hosted governance with verifiable accountability, from shadow AI to autonomous agents.",
    type: "website",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "Provenza" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "Provenza — open-source AI governance for AI agents",
    description: "Provenance for every AI action — verifiable, self-hosted AI governance.",
    images: ["/og-image.png"],
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <body>
        <I18nProvider>
          <AuthProvider>{children}</AuthProvider>
        </I18nProvider>
      </body>
    </html>
  );
}