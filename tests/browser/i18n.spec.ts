import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { lookupMessage, EN_PACK, ZH_PACK } from "../../src/i18n";
import { gotoApp } from "./helpers";

const evidenceDir = join(dirname(fileURLToPath(import.meta.url)), "../../test-results/i18n");

test.describe("zh-CN chrome", () => {
  test.use({ locale: "zh-CN" });

  test("Settings rail uses the Chinese pack", async ({ page }) => {
    await gotoApp(page);
    const settings = page.locator("[data-nav='settings']");
    await expect(settings).toHaveText(lookupMessage(ZH_PACK, "nav.settings"));
    await mkdir(evidenceDir, { recursive: true });
    await page.screenshot({ path: join(evidenceDir, "i18n-zh.png") });
  });
});

test.describe("en-US chrome", () => {
  test.use({ locale: "en-US" });

  test("Settings rail uses the English pack", async ({ page }) => {
    await gotoApp(page);
    const settings = page.locator("[data-nav='settings']");
    await expect(settings).toHaveText(lookupMessage(EN_PACK, "nav.settings"));
    await mkdir(evidenceDir, { recursive: true });
    await page.screenshot({ path: join(evidenceDir, "i18n-en.png") });
  });
});
