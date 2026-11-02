// The browser extension's domain matching (extension/shared/domains.js).
import { createRequire } from "node:module";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const { lookupDomain, isPlainDomain, BUILTIN_DOMAINS } = require(join(__dirname, "..", "..", "extension", "shared", "domains.js"));

const catalog = [
  { domain: "openai.com", name: "OpenAI", category: "api_provider", status: "allowed" },
  { domain: "chat.openai.com", name: "ChatGPT", category: "general_assistant", status: "blocked" },
  { domain: "claude.ai", name: "Claude", category: "general_assistant", status: "allowed" },
];

describe("extension domain matching", () => {
  it("prefers the exact entry, then the most specific parent", () => {
    expect(lookupDomain("chat.openai.com", catalog).status).toBe("blocked");
    expect(lookupDomain("eu.chat.openai.com", catalog).status).toBe("blocked");
    expect(lookupDomain("platform.openai.com", catalog).name).toBe("OpenAI");
    expect(lookupDomain("CLAUDE.AI.", catalog).name).toBe("Claude");
  });

  it("does not match a look-alike", () => {
    expect(lookupDomain("notclaude.ai", catalog)).toBeNull();
    expect(lookupDomain("claude.ai.evil.example", catalog)).toBeNull();
    expect(lookupDomain("", catalog)).toBeNull();
  });

  it("falls back to the built-in list until the server answered", () => {
    expect(lookupDomain("chatgpt.com", []).name).toBe("ChatGPT");
    expect(BUILTIN_DOMAINS.every((d: { domain: string }) => isPlainDomain(d.domain))).toBe(true);
  });

  it("puts only plain host names into rules and match patterns", () => {
    expect(isPlainDomain("chat.deepseek.com")).toBe(true);
    expect(isPlainDomain("x.ai")).toBe(true);
    expect(isPlainDomain("github.com/copilot")).toBe(false);
    expect(isPlainDomain("*.example.com")).toBe(false);
    expect(isPlainDomain("localhost:8080")).toBe(false);
  });
});
