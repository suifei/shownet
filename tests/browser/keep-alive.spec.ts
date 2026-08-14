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
  const browserKeepAlive = page.locator(".workspace-view-keep-alive").filter({ has: surface });
  await expect(browserKeepAlive).toHaveCount(1);
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

test("the browser toolbar fits without covering the hook panel", async ({ page }) => {
  await gotoApp(page);
  await openView(page, "浏览器");

  const toolbar = page.locator(".browser-toolbar");
  const assertToolbarFits = async () => {
    const geometry = await toolbar.evaluate((element) => {
      const address = element.querySelector<HTMLInputElement>(".address-bar input");
      return {
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
        addressWidth: address?.getBoundingClientRect().width ?? 0,
      };
    });

    expect(geometry.scrollWidth, "浏览器工具栏越过了自己的面板").toBeLessThanOrEqual(geometry.clientWidth + 1);
    expect(geometry.addressWidth, "地址栏被工具按钮挤到无法操作").toBeGreaterThanOrEqual(96);
  };

  await assertToolbarFits();

  // Labels used to reappear immediately above 1250px and crush the input.
  await page.setViewportSize({ width: 1251, height: 800 });
  await expect(toolbar).toBeVisible();
  await assertToolbarFits();
});

test("viewing another session does not take ownership from the live browser", async ({ page, viewport }) => {
  test.skip((viewport?.width ?? 0) <= 1060, "会话面板在窄布局下整体隐藏");
  await gotoApp(page);
  await openView(page, "浏览器");

  const address = page.locator(".browser-toolbar input").first();
  await address.fill("https://example.com/login?state=still-here");

  await page.getByRole("button", { name: /桌面客户端同步 今天/ }).click();
  await expect(page.getByRole("heading", { name: "实时流量" })).toBeVisible();
  await expect(page.getByText("抓包写入", { exact: true })).toBeVisible();

  await openView(page, "浏览器");
  await expect(address).toHaveValue("https://example.com/login?state=still-here");
  await expect(page.locator(".browser-owner")).toContainText("写入 电商登录链路");
});

test("a session with no browser history starts from the default address", async ({ page }) => {
  await gotoApp(page);
  await page.getByRole("button", { name: "停止抓包" }).click();
  await page.getByTitle("快捷命令").click();
  const palette = page.getByRole("dialog", { name: "快捷命令" });
  await palette.getByRole("textbox").fill("新建会话");
  await palette.getByRole("option", { name: /新建会话/ }).click();
  await openView(page, "浏览器");

  await expect(page.locator(".browser-toolbar input").first()).toHaveValue("about:blank");
});
