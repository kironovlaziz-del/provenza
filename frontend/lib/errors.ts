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
import i18n from "./i18n";

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

/**
 * The message for a failed API call: a 422's first validation message, a
 * translated error code, or the fallback. One helper for every page.
 */
export function errorMessage(err: unknown, t: TFunction, fallback: string): string {
  const detail = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  if (Array.isArray(detail) && detail[0] && typeof detail[0] === "object" && "msg" in detail[0]) {
    const msg = String((detail[0] as { msg: unknown }).msg);
    return msg.startsWith("Value error, ") ? msg.slice("Value error, ".length) : msg;
  }
  return translateApiError(detail, t, fallback);
}

/** errorMessage with the app's i18n instance - for API helpers that have no `t` at hand. */
export function apiErrorText(err: unknown, fallback: string): string {
  return errorMessage(err, i18n.t.bind(i18n) as TFunction, fallback);
}
