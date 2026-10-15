import { defineConfig } from "vitest/config";

// Unit and component tests (test/). The app's "@/..." imports resolve as in
// tsconfig.json; components render in jsdom with the real English strings.
export default defineConfig({
  resolve: { alias: { "@": import.meta.dirname } },
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.{ts,tsx}"],
    setupFiles: ["./test/setup.ts"],
    restoreMocks: true,
  },
});
