import { expect, test } from "@playwright/test";

import { gotoApp } from "./helpers";

test.describe("top-bar language switcher", () => {
  test("overrides the host locale and keeps the choice after reload", async ({ page }) => {
    await gotoApp(page);
    await expect(page.locator("[data-nav='traffic']")).toContainText("流量");
    await page.locator("[data-locale-switcher] button").first().click();
    const english = page.getByRole("option", { name: "English" });
    await expect(english).toBeVisible();
    const box = await english.boundingBox();
    expect(box, "language menu must have a clickable box").toBeTruthy();
    const hit = await page.evaluate(({ x, y }) => {
      const node = document.elementFromPoint(x, y);
      return (node instanceof HTMLElement ? node : node?.parentElement)?.innerText ?? "";
    }, { x: box!.x + box!.width / 2, y: box!.y + box!.height / 2 });
    expect(hit, "language menu must sit above the traffic toolbar").toContain("English");
    await english.click();
    await expect(page.locator("[data-nav='traffic']")).toContainText("Traffic");
    await expect(page.getByRole("button", { name: "Language" })).toBeVisible();
    await page.reload();
    await gotoApp(page);
    await expect(page.locator("[data-nav='traffic']")).toContainText("Traffic");
  });
});
