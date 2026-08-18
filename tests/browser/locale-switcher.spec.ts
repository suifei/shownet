import { expect, test } from "@playwright/test";

import { gotoApp } from "./helpers";

test.describe("top-bar language switcher", () => {
  test("overrides the host locale and keeps the choice after reload", async ({ page }) => {
    await gotoApp(page);
    await expect(page.locator("[data-nav='traffic']")).toContainText("流量");
    await page.locator("[data-locale-switcher] button").first().click();
    await page.getByRole("option", { name: "English" }).click();
    await expect(page.locator("[data-nav='traffic']")).toContainText("Traffic");
    await expect(page.getByRole("button", { name: "Language" })).toBeVisible();
    await page.reload();
    await gotoApp(page);
    await expect(page.locator("[data-nav='traffic']")).toContainText("Traffic");
  });
});
