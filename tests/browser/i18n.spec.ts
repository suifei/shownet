import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";

import { lookupMessage, EN_PACK, ZH_PACK } from "../../src/i18n";
import { gotoApp } from "./helpers";

const SCRATCH = process.env.GROK_SCRATCH
  ?? "/var/folders/8r/lc9rk4817v12c8mgj8k_g42h0000gn/T/grok-goal-2ebde9054685/implementer";

test.describe("zh-CN chrome", () => {
  test.use({ locale: "zh-CN" });

  test("Settings rail uses the Chinese pack", async ({ page }) => {
    await gotoApp(page);
    const settings = page.locator("[data-nav='settings']");
    await expect(settings).toHaveText(lookupMessage(ZH_PACK, "nav.settings"));
    await mkdir(SCRATCH, { recursive: true });
    await page.screenshot({ path: `${SCRATCH}/i18n-zh.png` });
  });
});

test.describe("en-US chrome", () => {
  test.use({ locale: "en-US" });

  test("Settings rail uses the English pack", async ({ page }) => {
    await gotoApp(page);
    const settings = page.locator("[data-nav='settings']");
    await expect(settings).toHaveText(lookupMessage(EN_PACK, "nav.settings"));
    await mkdir(SCRATCH, { recursive: true });
    await page.screenshot({ path: `${SCRATCH}/i18n-en.png` });
  });
});
