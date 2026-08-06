import { expect, test } from "@playwright/test";

import { findCrushedText, findHorizontalOverflow, findOffscreenLayers, gotoApp, openView, VIEWS } from "./helpers";

/**
 * Layout invariants. Every one of these corresponds to a failure mode that the
 * jsdom layer is structurally unable to see.
 */
for (const view of VIEWS) {
  test(`${view}: no crushed text`, async ({ page }) => {
    await gotoApp(page);
    await openView(page, view);
    expect(await findCrushedText(page)).toEqual([]);
  });

  test(`${view}: the page does not scroll horizontally`, async ({ page }) => {
    await gotoApp(page);
    await openView(page, view);

    const report = await findHorizontalOverflow(page);
    expect(report.offenders, `${view} has elements past the right edge`).toEqual([]);
    expect(report.pageScrollWidth).toBeLessThanOrEqual(report.pageClientWidth + 1);
  });
}

test("floating layers stay inside the window", async ({ page }) => {
  await gotoApp(page);

  // Selection bar plus its overflow menu, over the grid.
  await page.locator(".request-grid-row").nth(2).click();
  await page.getByRole("button", { name: /更多/ }).first().click();
  expect(await findOffscreenLayers(page)).toEqual([]);
  await page.keyboard.press("Escape");

  await page.getByTitle("快捷命令").click();
  expect(await findOffscreenLayers(page)).toEqual([]);
  await page.keyboard.press("Escape");

  await page.keyboard.press("?");
  expect(await findOffscreenLayers(page)).toEqual([]);
});

test("the collection overflow menu keeps its rows on one line", async ({ page }) => {
  // The regression this whole layer exists for: an icon-sizing rule matched the
  // labelled buttons and wrapped every menu row to one character per line.
  await gotoApp(page);
  await openView(page, "实验室");
  await page.getByRole("button", { name: /请求集合/ }).click();
  await page.locator(".collection-tree-label").first().click();
  await page.getByRole("button", { name: /更多/ }).click();

  const menu = page.locator(".collection-pane-menu");
  await expect(menu).toBeVisible();
  expect(await findCrushedText(page)).toEqual([]);

  // Every row is a single line of text.
  for (const row of await menu.locator("button").all()) {
    const box = await row.boundingBox();
    expect(box, "menu row must have a box").not.toBeNull();
    expect(box!.height).toBeLessThan(46);
  }
});

test("the filter panel fits beside its trigger", async ({ page }) => {
  await gotoApp(page);
  await page.getByRole("button", { name: /筛选/ }).click();
  await expect(page.locator(".filter-panel")).toBeVisible();
  expect(await findOffscreenLayers(page)).toEqual([]);
});

test("long request paths are clipped, not overflowed", async ({ page }) => {
  await gotoApp(page);
  const overflowing = await page.evaluate(() => {
    const bad: string[] = [];
    for (const cell of document.querySelectorAll<HTMLElement>(".request-grid-cell")) {
      // Ellipsis is fine; spilling past the cell is not.
      if (cell.scrollWidth > cell.clientWidth + 1 && getComputedStyle(cell).overflow === "visible") {
        bad.push(cell.className);
      }
    }
    return bad;
  });
  expect(overflowing).toEqual([]);
});

// Below 1060px the session panel is hidden outright, so there is no rail to
// collapse; the check only applies to the desktop layout.
test("the collapsed session rail stays legible", async ({ page, viewport }) => {
  test.skip((viewport?.width ?? 0) <= 1060, "会话面板在窄布局下整体隐藏");
  // Collapsed to 72px, the product name used to overflow and get clipped by
  // the nav rail, and the sessions became indistinguishable dots.
  await gotoApp(page);
  await page.getByTitle("收起会话").click();

  const rail = page.locator(".sessions-panel.is-compact");
  await expect(rail).toBeVisible();
  await expect(page.locator(".sessions-panel.is-compact .product-name")).toBeHidden();

  const railBox = (await rail.boundingBox())!;
  for (const item of await page.locator(".sessions-panel.is-compact .session-item").all()) {
    const box = (await item.boundingBox())!;
    // Every avatar sits inside the rail, and is centred within it.
    expect(box.x).toBeGreaterThanOrEqual(railBox.x);
    expect(box.x + box.width).toBeLessThanOrEqual(railBox.x + railBox.width + 1);
    const offset = (box.x - railBox.x) - (railBox.width - box.width) / 2;
    expect(Math.abs(offset), "avatar is not centred in the rail").toBeLessThan(2);
  }

  // Each session still reads as something, not as a bare dot.
  const initials = await page.locator(".session-item__initial").allTextContents();
  expect(initials.length).toBeGreaterThan(0);
  for (const initial of initials) expect(initial.trim().length).toBeGreaterThan(0);

  expect(await findCrushedText(page)).toEqual([]);
  expect((await findHorizontalOverflow(page)).offenders).toEqual([]);
});

test("the session panel gives way entirely on a narrow window", async ({ page, viewport }) => {
  test.skip((viewport?.width ?? 0) > 1060, "宽布局下面板常驻");
  await gotoApp(page);
  // Hidden rather than squeezed: 72px of rail plus the nav would leave the
  // grid unusable at this width.
  await expect(page.locator(".sessions-panel")).toBeHidden();
});

test("the about dialog fits and stays inside the window", async ({ page }) => {
  await gotoApp(page);
  await page.getByTitle(/关于 ShowNet/).click();
  await expect(page.locator(".about-dialog")).toBeVisible();

  expect(await findCrushedText(page)).toEqual([]);
  const box = (await page.locator(".about-dialog").boundingBox())!;
  const viewport = page.viewportSize()!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.y).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1);
  expect(box.y + box.height).toBeLessThanOrEqual(viewport.height + 1);
});
