import { expect, test } from "@playwright/test";

import { findCrushedText, findOffscreenLayers, gotoApp } from "./helpers";

/**
 * Pointer and wheel behaviour.
 *
 * The audit sweep proves no state is mis-laid-out; this proves the interactions
 * that *produce* those states actually work — dragging a column, spinning the
 * wheel, right-clicking, dismissing a layer by clicking elsewhere.
 */

test.describe("request grid", () => {
  test("the wheel scrolls the grid, not the page", async ({ page }) => {
    await gotoApp(page, { largeList: true });
    const scroller = page.locator(".request-grid-scroll");
    await scroller.hover();

    const before = await scroller.evaluate((node) => node.scrollTop);
    await page.mouse.wheel(0, 400);
    await page.waitForTimeout(200);

    expect(await scroller.evaluate((node) => node.scrollTop)).toBeGreaterThan(before);
    expect(await page.evaluate(() => window.scrollY)).toBe(0);
  });

  test("the header stays put while the rows scroll", async ({ page }) => {
    await gotoApp(page, { largeList: true });
    const header = page.locator(".request-grid-header");
    const top = (await header.boundingBox())!.y;

    await page.locator(".request-grid-scroll").hover();
    await page.mouse.wheel(0, 500);
    await page.waitForTimeout(200);

    expect((await header.boundingBox())!.y).toBeCloseTo(top, 0);
  });

  test("only a window of rows is in the DOM for a large list", async ({ page }) => {
    await gotoApp(page, { largeList: true });
    const rendered = await page.locator(".request-grid-row").count();
    const declared = Number(await page.locator(".request-grid-scroll").getAttribute("aria-rowcount"));

    expect(declared).toBeGreaterThan(1000);
    expect(rendered, "整份列表不应一次性进入 DOM").toBeLessThan(200);
  });

  test("scrolling a long way swaps the rows rather than growing the DOM", async ({ page }) => {
    await gotoApp(page, { largeList: true });
    const scroller = page.locator(".request-grid-scroll");
    const firstBefore = await page.locator(".request-grid-row").first().textContent();
    const countBefore = await page.locator(".request-grid-row").count();

    await scroller.hover();
    await page.mouse.wheel(0, 4000);
    await page.waitForTimeout(400);

    expect(await page.locator(".request-grid-row").first().textContent()).not.toBe(firstBefore);
    expect(await page.locator(".request-grid-row").count()).toBeLessThanOrEqual(countBefore + 20);
    expect(await findCrushedText(page)).toEqual([]);
  });

  test("the order column stays frozen when scrolling sideways", async ({ page }) => {
    await gotoApp(page);
    const orderCell = page.locator(".request-grid-cell--order").first();
    const left = (await orderCell.boundingBox())!.x;

    await page.locator(".request-grid-scroll").hover();
    await page.mouse.wheel(600, 0);
    await page.waitForTimeout(200);

    expect((await orderCell.boundingBox())!.x).toBeCloseTo(left, 0);
    // And its edge has to read as an edge, or the column underneath looks
    // truncated rather than covered.
    const shadow = await orderCell.evaluate((node) => getComputedStyle(node).boxShadow);
    expect(shadow).not.toBe("none");
  });

  test("dragging a column divider resizes that column", async ({ page }) => {
    await gotoApp(page);
    const handle = page.locator(".column-resize-handle").nth(2);
    const cell = page.locator(".request-grid-header-cell").nth(2);
    const before = (await cell.boundingBox())!.width;

    const box = (await handle.boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + 90, box.y + box.height / 2, { steps: 8 });
    await page.mouse.up();
    await page.waitForTimeout(200);

    expect((await cell.boundingBox())!.width).toBeGreaterThan(before + 40);
    expect(await findCrushedText(page)).toEqual([]);
  });

  test("shift-clicking a header adds a secondary sort", async ({ page }) => {
    await gotoApp(page);
    const buttons = page.locator(".request-grid-sort-button");
    await buttons.nth(1).click();
    await page.waitForTimeout(150);
    await buttons.nth(2).click({ modifiers: ["Shift"] });
    await page.waitForTimeout(150);

    const sorted = await page.locator('.request-grid-header-cell[aria-sort]:not([aria-sort="none"])').count();
    expect(sorted, "shift-click 应保留前一个排序条件").toBe(2);
  });

  test("shift-clicking a row selects the range between", async ({ page }) => {
    await gotoApp(page);
    await page.locator(".request-grid-row").nth(1).click();
    await page.locator(".request-grid-row").nth(5).click({ modifiers: ["Shift"] });
    await page.waitForTimeout(200);

    await expect(page.locator(".request-grid-statusbar")).toContainText("已选择 5");
  });

  test("meta-clicking toggles one row without opening the detail", async ({ page }) => {
    await gotoApp(page);
    await page.locator(".request-grid-row").nth(1).click();
    await page.locator(".request-detail__close, [title='关闭详情']").first().click();
    await page.waitForTimeout(150);

    await page.locator(".request-grid-row").nth(3).click({ modifiers: ["Meta"] });
    await page.waitForTimeout(200);
    await expect(page.locator(".request-detail")).toHaveCount(0);
  });
});

test.describe("floating layers", () => {
  test("a context menu opens at the pointer and dismisses on an outside click", async ({ page }) => {
    await gotoApp(page);
    const row = page.locator(".request-grid-row").nth(4);
    const box = (await row.boundingBox())!;
    await row.click({ button: "right", position: { x: 120, y: 10 } });

    const menu = page.locator(".request-context-menu");
    await expect(menu).toBeVisible();
    const menuBox = (await menu.boundingBox())!;
    // Anchored near where the user clicked, not parked in a corner.
    expect(Math.abs(menuBox.x - (box.x + 120))).toBeLessThan(30);
    expect(await findOffscreenLayers(page)).toEqual([]);

    await page.locator(".traffic-summary").click({ position: { x: 10, y: 10 } });
    await expect(menu).toHaveCount(0);
  });

  test("right-clicking near the right edge keeps the menu on screen", async ({ page }) => {
    await gotoApp(page);
    const row = page.locator(".request-grid-row").nth(4);
    const box = (await row.boundingBox())!;
    await row.click({ button: "right", position: { x: box.width - 6, y: 10 } });

    await expect(page.locator(".request-context-menu")).toBeVisible();
    expect(await findOffscreenLayers(page)).toEqual([]);
  });

  test("only one toolbar popover is open at a time", async ({ page }) => {
    await gotoApp(page);
    await page.getByRole("button", { name: /筛选/ }).click();
    await expect(page.locator(".filter-panel")).toBeVisible();

    await page.getByTitle("配置列").click();
    await expect(page.locator(".column-menu")).toBeVisible();
    await expect(page.locator(".filter-panel")).toHaveCount(0);
  });

  test("Escape closes the top layer without disturbing the one beneath", async ({ page }) => {
    await gotoApp(page);
    await page.locator(".request-grid-row").nth(2).click();
    await page.getByRole("button", { name: /更多/ }).first().click();
    await expect(page.locator(".selection-more-menu")).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(page.locator(".selection-more-menu")).toHaveCount(0);
    // The selection itself survives; Escape peels one layer.
    await expect(page.locator(".selection-bar")).toBeVisible();
  });
});

test.describe("view transitions", () => {
  test("moving between views keeps exactly one nav item active", async ({ page }) => {
    await gotoApp(page);
    for (const view of ["实验室", "高级", "AI 分析", "能力", "设置", "流量"]) {
      await page.locator(".nav-rail__item", { hasText: new RegExp(`^${view}$`) }).first().click();
      await page.waitForTimeout(250);
      await expect(page.locator(".nav-rail__item.is-active")).toHaveCount(1);
    }
  });

  test("returning to a view restores its state rather than resetting it", async ({ page }) => {
    await gotoApp(page);
    await page.locator(".request-grid-row").nth(3).click();
    await page.getByTitle("详情置于底部").click();
    await page.waitForTimeout(200);

    await page.locator(".nav-rail__item", { hasText: /^设置$/ }).first().click();
    await page.waitForTimeout(250);
    await page.locator(".nav-rail__item", { hasText: /^流量$/ }).first().click();
    await page.waitForTimeout(300);

    // The inspector layout is a preference, not a per-visit default.
    await expect(page.locator(".traffic-split.layout-bottom")).toBeVisible();
  });

  test("the workbench hides the session rail and gives it back on exit", async ({ page, viewport }) => {
    test.skip((viewport?.width ?? 0) <= 1060, "会话面板在窄布局下本就隐藏");
    await gotoApp(page);
    await expect(page.locator(".sessions-panel")).toBeVisible();

    await page.locator(".nav-rail__item", { hasText: /^实验室$/ }).first().click();
    await page.waitForTimeout(300);
    await expect(page.locator(".sessions-panel")).toBeHidden();

    // "返回流量选择一条请求" also contains this text.
    await page.getByTitle("返回流量", { exact: true }).click();
    await page.waitForTimeout(300);
    await expect(page.locator(".sessions-panel")).toBeVisible();
  });
});
