/**
 * Translate backend error payloads into localised strings.
 *
 * The backend returns `detail` as either a plain string code
 * ("auth.invalid_credentials") or an object with an interpolation context:
 *   {"code": "auth.rate_limited", "context": {"retry_after": 300}}
 *
 * Anything unrecognised (including legacy plain-text messages) is returned
 * as-is so nothing breaks during the migration.
 */
import type { TFunction } from "i18next";

export function translateApiError(
  detail: unknown,
  t: TFunction,
  fallback: string,
): string {
  if (typeof detail === "string") {
    // Only translate if the string looks like a dotted code and has a
    // matching key in i18n. Otherwise return the raw message.
    if (/^[a-z][a-z0-9_]*\.[a-z0-9_.]+$/i.test(detail)) {
      const translated = t(`errors.${detail}`, { defaultValue: "" });
      if (translated) return translated;
    }
    return detail;
  }

  if (detail && typeof detail === "object" && "code" in detail) {
    const obj = detail as { code: string; context?: Record<string, unknown> };
    const translated = t(`errors.${obj.code}`, {
      ...(obj.context ?? {}),
      defaultValue: "",
    });
    if (translated) return translated;
    return obj.code;
  }

  return fallback;
}
