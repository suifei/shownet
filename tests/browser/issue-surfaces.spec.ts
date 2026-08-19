import { expect, test } from "@playwright/test";

import { gotoApp, openView, VIEWS } from "./helpers";

test.describe("issue surfaces", () => {
  test("embedded browser and ClientHello settings are reachable", async ({ page }) => {
    await gotoApp(page);
    const browserLabel = VIEWS[1];
    const settingsLabel = VIEWS[VIEWS.length - 1];

    await openView(page, browserLabel);
    await expect(page.locator(".browser-viewport")).toBeVisible();
    if (process.env.SHOWNET_GOAL_SCRATCH) {
      await page.screenshot({ path: `${process.env.SHOWNET_GOAL_SCRATCH}/ime-browser.png` });
    }

    await openView(page, settingsLabel);
    await page.getByRole("button", { name: /抓包与 HTTPS/ }).click();
    await page.locator("summary", { hasText: "出口代理与 TLS 指纹" }).click();
    const presetLabel = page.getByText(/ClientHello 版本预置/);
    await presetLabel.scrollIntoViewIfNeeded();
    await expect(presetLabel).toBeVisible();
    if (process.env.SHOWNET_GOAL_SCRATCH) {
      await page.screenshot({ path: `${process.env.SHOWNET_GOAL_SCRATCH}/clienthello-preset.png` });
    }
  });
});
