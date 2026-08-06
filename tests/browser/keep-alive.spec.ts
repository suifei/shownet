import { expect, test } from "@playwright/test";

import { gotoApp, openView } from "./helpers";

/**
 * The embedded browser must survive leaving and returning to its view.
 *
 * Opening a site, clicking into it, going to another view and coming back has
 * to land on the same page in the same state — not a blank surface and not a
 * reload from the start.
 */

test("the browser view is kept mounted while another view is shown", async ({ page }) => {
  await gotoApp(page);
  await openView(page, "浏览器");
  const surface = page.locator(".browser-viewport").first();
  await expect(surface).toBeVisible();

  await openView(page, "流量");
  // Hidden, but still in the DOM: a remount would drop the page entirely.
  await expect(page.locator(".workspace-view-keep-alive")).toHaveCount(1);
  await expect(surface).toBeHidden();

  await openView(page, "浏览器");
  await expect(surface).toBeVisible();
});

test("state inside the browser view survives a round trip", async ({ page }) => {
  await gotoApp(page);
  await openView(page, "浏览器");

  // The address bar is the one piece of state that is always present, in both
  // the CDP path and the preview fallback.
  const address = page.locator(".browser-toolbar input").first();
  await address.fill("https://example.com/deep/page?kept=1");
  const typed = await address.inputValue();

  await openView(page, "实验室");
  await openView(page, "浏览器");

  expect(await address.inputValue(), "地址栏在切走再回来后被重置").toBe(typed);
});

test("the page element is never rebuilt by a react key", async ({ page }) => {
  // `key={currentUrl}` on the iframe made React destroy and recreate the
  // element on every URL change, throwing away everything the page held.
  await gotoApp(page);
  await openView(page, "浏览器");

  const identity = await page.evaluate(() => {
    const frame = document.querySelector("iframe[title='ShowNet embedded browser']");
    if (!frame) return null;
    (frame as HTMLElement).dataset.shownetProbe = "1";
    return true;
  });
  test.skip(identity === null, "预览构建未渲染内嵌页面");

  await openView(page, "流量");
  await openView(page, "浏览器");

  const survived = await page.evaluate(() => {
    const frame = document.querySelector("iframe[title='ShowNet embedded browser']");
    return (frame as HTMLElement | null)?.dataset.shownetProbe === "1";
  });
  expect(survived, "iframe 元素在切换视图后被重建").toBe(true);
});

test("view switching does not tear down the page", async ({ page }) => {
  // The teardown that stops Chrome must fire only on a real unmount. It used to
  // carry a dependency, which would let it run mid-session.
  await gotoApp(page);
  await openView(page, "浏览器");

  const before = await page.locator(".browser-viewport").count();
  for (const view of ["流量", "浏览器", "实验室", "浏览器", "设置", "浏览器"]) {
    await openView(page, view);
  }
  expect(await page.locator(".browser-viewport").count()).toBe(before);
  await expect(page.locator(".browser-viewport").first()).toBeVisible();
});
