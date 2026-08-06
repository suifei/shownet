import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { gotoApp, openView, VIEWS } from "./helpers";

/**
 * The jsdom layer already runs axe, but with `color-contrast` disabled: it has
 * no layout and no resolved colours, so the rule cannot run there at all. This
 * is the only place the app's dark palette is actually measured.
 */
async function contrastViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withRules(["color-contrast"]).analyze();
  return results.violations.flatMap((violation) =>
    violation.nodes.map((node) => ({
      text: (node.html.match(/>([^<]{1,40})</)?.[1] ?? node.html.slice(0, 60)).trim(),
      target: String(node.target[0]).slice(0, 70),
      detail: node.any[0]?.message?.slice(0, 120) ?? "",
    })),
  );
}

for (const view of VIEWS) {
  test(`${view}: text meets contrast minimums`, async ({ page }) => {
    await gotoApp(page);
    await openView(page, view);
    expect(await contrastViolations(page)).toEqual([]);
  });
}

test("dialogs meet contrast minimums", async ({ page }) => {
  await gotoApp(page);

  await page.getByTitle("快捷命令").click();
  expect(await contrastViolations(page), "命令面板").toEqual([]);
  await page.keyboard.press("Escape");

  await page.keyboard.press("?");
  expect(await contrastViolations(page), "快捷操作").toEqual([]);
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: /个来源/ }).click();
  expect(await contrastViolations(page), "流量来源").toEqual([]);
});

test("the selection bar and its menu meet contrast minimums", async ({ page }) => {
  // Both sit on a translucent material over the grid, which is where a
  // borderline foreground colour is most likely to fall short.
  await gotoApp(page);
  await page.locator(".request-grid-row").nth(2).click();
  await page.getByRole("button", { name: /更多/ }).first().click();
  expect(await contrastViolations(page)).toEqual([]);
});

test("focus is always visible on keyboard navigation", async ({ page }) => {
  await gotoApp(page);
  await page.keyboard.press("Tab");

  for (let step = 0; step < 12; step += 1) {
    const visible = await page.evaluate(() => {
      const active = document.activeElement;
      if (!active || active === document.body) return true;
      const style = getComputedStyle(active);
      const hasOutline = style.outlineStyle !== "none" && Number.parseFloat(style.outlineWidth) > 0;
      const hasShadow = style.boxShadow !== "none";
      const describe = `${active.tagName.toLowerCase()}.${String(active.className).split(" ")[0]}`;
      return hasOutline || hasShadow ? true : describe;
    });
    expect(visible, "focused element has no visible focus indicator").toBe(true);
    await page.keyboard.press("Tab");
  }
});
