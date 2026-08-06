import { defineConfig, devices } from "@playwright/test";

/**
 * Real-browser checks — the third layer, and the only one that does layout.
 *
 * jsdom renders the tree but computes no geometry, so it cannot see a rule that
 * crushes a menu into a single column, a bar that overflows its container, or
 * text clipped by a fixed height. It also cannot judge colour contrast. Those
 * are the failures this layer exists for.
 *
 * Run with `npm run test:browser`. It is deliberately not part of `npm test`:
 * it needs a dev server and a browser binary, which not every environment has.
 */
export default defineConfig({
  testDir: "tests/browser",
  // Layout assertions are deterministic; a retry would only hide flakiness.
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:1420",
    ...devices["Desktop Chrome"],
    viewport: { width: 1440, height: 900 },
  },
  webServer: {
    command: "npm run dev",
    url: "http://127.0.0.1:1420",
    reuseExistingServer: true,
    timeout: 60_000,
  },
  projects: [
    { name: "desktop", use: { viewport: { width: 1440, height: 900 } } },
    // The narrow layout has its own rules; several of them were only ever
    // eyeballed.
    { name: "narrow", use: { viewport: { width: 900, height: 800 } } },
  ],
});
