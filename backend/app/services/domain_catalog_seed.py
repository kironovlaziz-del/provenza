"""
Built-in seed catalog of well-known AI-service domains.

This is a *hint* source only: it never sets an organization's
policy_status automatically (that stays an explicit admin decision in
AIDomainCatalog). It's used to pre-fill tool_name/category when an org
hasn't classified a domain yet, so a first-time "unknown" match still
shows something more useful than the bare domain string.

A plain in-code registry, not a DB table, because it changes with code releases, not per-org
configuration.
"""
from typing import Optional, TypedDict


class SeedDomainHint(TypedDict):
    domain: str
    tool_name: str
    category: str


SEED_DOMAINS: list[SeedDomainHint] = [
    {"domain": "chatgpt.com", "tool_name": "ChatGPT", "category": "general_assistant"},
    {"domain": "chat.openai.com", "tool_name": "ChatGPT", "category": "general_assistant"},
    {"domain": "openai.com", "tool_name": "OpenAI API", "category": "api_provider"},
    {"domain": "claude.ai", "tool_name": "Claude", "category": "general_assistant"},
    {"domain": "anthropic.com", "tool_name": "Anthropic API", "category": "api_provider"},
    {"domain": "gemini.google.com", "tool_name": "Gemini", "category": "general_assistant"},
    {"domain": "bard.google.com", "tool_name": "Gemini (Bard)", "category": "general_assistant"},
    {"domain": "copilot.microsoft.com", "tool_name": "Microsoft Copilot", "category": "general_assistant"},
    {"domain": "perplexity.ai", "tool_name": "Perplexity", "category": "search_assistant"},
    {"domain": "character.ai", "tool_name": "Character.AI", "category": "general_assistant"},
    {"domain": "chat.deepseek.com", "tool_name": "DeepSeek Chat", "category": "general_assistant"},
    {"domain": "grok.com", "tool_name": "Grok", "category": "general_assistant"},
    {"domain": "chat.mistral.ai", "tool_name": "Le Chat (Mistral)", "category": "general_assistant"},
    {"domain": "chat.qwen.ai", "tool_name": "Qwen Chat", "category": "general_assistant"},
    {"domain": "kimi.com", "tool_name": "Kimi", "category": "general_assistant"},
    {"domain": "meta.ai", "tool_name": "Meta AI", "category": "general_assistant"},
    {"domain": "pi.ai", "tool_name": "Pi", "category": "general_assistant"},
    {"domain": "you.com", "tool_name": "You.com", "category": "search_assistant"},
    {"domain": "phind.com", "tool_name": "Phind", "category": "search_assistant"},
    {"domain": "notebooklm.google.com", "tool_name": "NotebookLM", "category": "productivity"},
    {"domain": "aistudio.google.com", "tool_name": "Google AI Studio", "category": "general_assistant"},
    {"domain": "gamma.app", "tool_name": "Gamma", "category": "productivity"},
    {"domain": "ideogram.ai", "tool_name": "Ideogram", "category": "image_generation"},
    {"domain": "leonardo.ai", "tool_name": "Leonardo.Ai", "category": "image_generation"},
    {"domain": "suno.com", "tool_name": "Suno", "category": "audio_generation"},
    {"domain": "poe.com", "tool_name": "Poe", "category": "general_assistant"},
    {"domain": "huggingface.co", "tool_name": "Hugging Face", "category": "model_hub"},
    {"domain": "replicate.com", "tool_name": "Replicate", "category": "api_provider"},
    {"domain": "cohere.com", "tool_name": "Cohere", "category": "api_provider"},
    {"domain": "mistral.ai", "tool_name": "Mistral", "category": "api_provider"},
    {"domain": "midjourney.com", "tool_name": "Midjourney", "category": "image_generation"},
    {"domain": "stability.ai", "tool_name": "Stability AI", "category": "image_generation"},
    {"domain": "runwayml.com", "tool_name": "Runway", "category": "video_generation"},
    {"domain": "elevenlabs.io", "tool_name": "ElevenLabs", "category": "voice_generation"},
    {"domain": "github.com/copilot", "tool_name": "GitHub Copilot", "category": "coding_assistant"},
    {"domain": "cursor.com", "tool_name": "Cursor", "category": "coding_assistant"},
    {"domain": "cursor.sh", "tool_name": "Cursor", "category": "coding_assistant"},
    {"domain": "windsurf.com", "tool_name": "Windsurf", "category": "coding_assistant"},
    {"domain": "tabnine.com", "tool_name": "Tabnine", "category": "coding_assistant"},
    {"domain": "v0.dev", "tool_name": "v0 by Vercel", "category": "coding_assistant"},
    {"domain": "v0.app", "tool_name": "v0 by Vercel", "category": "coding_assistant"},
    {"domain": "bolt.new", "tool_name": "Bolt", "category": "coding_assistant"},
    {"domain": "lovable.dev", "tool_name": "Lovable", "category": "coding_assistant"},
    {"domain": "codeium.com", "tool_name": "Codeium", "category": "coding_assistant"},
    {"domain": "notion.so", "tool_name": "Notion AI", "category": "productivity"},
    {"domain": "grammarly.com", "tool_name": "Grammarly", "category": "writing_assistant"},
    {"domain": "jasper.ai", "tool_name": "Jasper", "category": "writing_assistant"},
    {"domain": "otter.ai", "tool_name": "Otter.ai", "category": "transcription"},
    # API hosts agents call directly (provenza.auto in the SDK intercepts these)
    {"domain": "generativelanguage.googleapis.com", "tool_name": "Gemini API", "category": "api_provider"},
    {"domain": "aiplatform.googleapis.com", "tool_name": "Vertex AI", "category": "api_provider"},
    {"domain": "openai.azure.com", "tool_name": "Azure OpenAI", "category": "api_provider"},
    {"domain": "bedrock-runtime.amazonaws.com", "tool_name": "Amazon Bedrock", "category": "api_provider"},
    {"domain": "deepseek.com", "tool_name": "DeepSeek", "category": "api_provider"},
    {"domain": "x.ai", "tool_name": "xAI Grok", "category": "api_provider"},
    {"domain": "groq.com", "tool_name": "Groq", "category": "api_provider"},
    {"domain": "openrouter.ai", "tool_name": "OpenRouter", "category": "api_provider"},
    {"domain": "together.xyz", "tool_name": "Together AI", "category": "api_provider"},
    {"domain": "fireworks.ai", "tool_name": "Fireworks AI", "category": "api_provider"},
]


# What a browser visit means: these categories are APIs that programs call
# (a visit to such a site is reading its documentation, not using AI), and an
# entry with a path cannot be matched by a host name.
BROWSER_SKIPPED_CATEGORIES = {"api_provider"}


def browser_seed() -> list[SeedDomainHint]:
    """The seed entries a browser extension watches for."""
    return [e for e in SEED_DOMAINS if "/" not in e["domain"] and e["category"] not in BROWSER_SKIPPED_CATEGORIES]


def lookup_seed_hint(domain: str) -> Optional[SeedDomainHint]:
    """Suffix match against the seed catalog: "chat.openai.com" matches
    a seed entry for "openai.com" as well as an exact one."""
    domain = domain.lower().strip()
    # Exact match first, so more specific seed entries (e.g.
    # "chat.openai.com") win over a broader one ("openai.com").
    for entry in SEED_DOMAINS:
        if domain == entry["domain"]:
            return entry
    for entry in SEED_DOMAINS:
        if domain.endswith("." + entry["domain"]):
            return entry
    return None
