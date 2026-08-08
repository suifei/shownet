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
  // Kept at zero for that reason. What fails on Windows runners is not an
  // assertion but gotoApp waiting for .app-shell. Raising this budget was the
  // first response and it was the wrong read: the second occurrence sat at the
  // full 90s while its siblings in the same project mounted in ~1.2s, so it is
  // a stall, not slowness, and a larger budget only lengthens the stall. The
  // navigation now retries once inside gotoApp — see the note there. The budget
  // stays at 90s because it has to cover that second attempt.
  timeout: process.env.CI ? 90_000 : 30_000,
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
    // The smallest window the app itself permits — tauri.conf.json sets
    // minWidth 1080 and minHeight 680. Neither dimension was covered: desktop
    // and narrow bracket it without landing on it, and 680 is shorter than
    // either. This is the tightest layout a user can actually produce.
    { name: "minimum", use: { viewport: { width: 1080, height: 680 } } },
  ],
});
