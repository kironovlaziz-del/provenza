// Every test: English UI strings (the real locales/en.json), clean storage,
// and the rendered tree removed.
import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach } from "vitest";
import i18n from "@/lib/i18n";

beforeEach(async () => {
  if (typeof window !== "undefined") window.localStorage.clear();   // node-environment tests have no window
  await i18n.changeLanguage("en");
});

afterEach(() => {
  cleanup();
});
