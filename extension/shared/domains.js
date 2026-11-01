// The AI services the extension watches.
//
// The list comes from the organization's Provenza server
// (GET /shadow-ai/extension/catalog, refreshed hourly): every domain of the
// organization's AI domain catalog with its decision - allowed, blocked or
// unknown - plus the built-in AI services nobody classified yet. BUILTIN
// below is only the first-run fallback, until the server has answered once.

const BUILTIN_DOMAINS = [
  ["chatgpt.com", "ChatGPT", "general_assistant"],
  ["chat.openai.com", "ChatGPT", "general_assistant"],
  ["claude.ai", "Claude", "general_assistant"],
  ["gemini.google.com", "Gemini", "general_assistant"],
  ["copilot.microsoft.com", "Microsoft Copilot", "general_assistant"],
  ["perplexity.ai", "Perplexity", "search_assistant"],
  ["chat.deepseek.com", "DeepSeek Chat", "general_assistant"],
  ["grok.com", "Grok", "general_assistant"],
  ["chat.mistral.ai", "Le Chat (Mistral)", "general_assistant"],
  ["chat.qwen.ai", "Qwen Chat", "general_assistant"],
  ["character.ai", "Character.AI", "general_assistant"],
  ["poe.com", "Poe", "general_assistant"],
  ["meta.ai", "Meta AI", "general_assistant"],
  ["notebooklm.google.com", "NotebookLM", "productivity"],
  ["huggingface.co", "Hugging Face", "model_hub"],
  ["midjourney.com", "Midjourney", "image_generation"],
  ["v0.dev", "v0 by Vercel", "coding_assistant"],
  ["cursor.com", "Cursor", "coding_assistant"]
].map(([domain, name, category]) => ({ domain, name, category, status: "unknown" }));

// lookupDomain: the catalog entry for a host - an exact entry first, then the
// most specific parent domain ("foo.claude.ai" matches "claude.ai").
function lookupDomain(hostname, domains) {
  const host = (hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host) return null;
  const list = domains && domains.length ? domains : BUILTIN_DOMAINS;
  let best = null;
  for (const entry of list) {
    if (host === entry.domain) return entry;
    if (host.endsWith("." + entry.domain) && (!best || entry.domain.length > best.domain.length)) best = entry;
  }
  return best;
}

// A domain that is safe to put into a match pattern or a network rule.
function isPlainDomain(domain) {
  return /^[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,63}$/.test(domain || "");
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { BUILTIN_DOMAINS, lookupDomain, isPlainDomain };
}
