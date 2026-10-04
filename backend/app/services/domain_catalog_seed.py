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
    {"domain": "chat.openai.com", "tool_name": "ChatGPT", "category": "general_assistant"},
    {"domain": "openai.com", "tool_name": "OpenAI API", "category": "api_provider"},
    {"domain": "claude.ai", "tool_name": "Claude", "category": "general_assistant"},
    {"domain": "anthropic.com", "tool_name": "Anthropic API", "category": "api_provider"},
    {"domain": "gemini.google.com", "tool_name": "Gemini", "category": "general_assistant"},
    {"domain": "bard.google.com", "tool_name": "Gemini (Bard)", "category": "general_assistant"},
    {"domain": "copilot.microsoft.com", "tool_name": "Microsoft Copilot", "category": "general_assistant"},
    {"domain": "perplexity.ai", "tool_name": "Perplexity", "category": "search_assistant"},
    {"domain": "character.ai", "tool_name": "Character.AI", "category": "general_assistant"},
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
    {"domain": "cursor.sh", "tool_name": "Cursor", "category": "coding_assistant"},
    {"domain": "codeium.com", "tool_name": "Codeium", "category": "coding_assistant"},
    {"domain": "notion.so", "tool_name": "Notion AI", "category": "productivity"},
    {"domain": "grammarly.com", "tool_name": "Grammarly", "category": "writing_assistant"},
    {"domain": "jasper.ai", "tool_name": "Jasper", "category": "writing_assistant"},
    {"domain": "otter.ai", "tool_name": "Otter.ai", "category": "transcription"},
]


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
