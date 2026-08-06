import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * Rendering tests, kept separate from the `node:test` suite.
 *
 * That suite asserts against source text: it is fast and locks decisions in
 * place, but it cannot tell whether a component actually renders what the
 * source implies. Every UI bug found during the redesign passed those tests —
 * a stale value read at commit time, a report header describing the wrong
 * object, a CSS rule that crushed a menu. The first two are exactly what
 * rendering the component catches.
 */
export default defineConfig({
  plugins: [react()],
  test: {
    // Only the rendering suite; tests/*.test.ts stays on the node runner.
    include: ["tests/render/**/*.test.tsx"],
    environment: "jsdom",
    globals: true,
    setupFiles: ["tests/render/setup.ts"],
    restoreMocks: true,
  },
});
