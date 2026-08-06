import { expect, test } from "@playwright/test";

import { gotoApp, openView, VIEWS } from "./helpers";

/**
 * Theme consistency.
 *
 * The app is dark-only, but it grew out of a light design and kept literal
 * light-theme values behind: the frozen grid column's edge was `#e5e8ea`, and
 * eight scroll containers in the workbench pinned a pale `#c5ccce` thumb.
 * Neither shows up in a screenshot review — one is a hairline, the other only
 * appears while scrolling — and neither breaks layout, so nothing else catches
 * them.
 */

/** Relative luminance, per WCAG. */
function luminance(r: number, g: number, b: number) {
  const channel = (value: number) => {
    const v = value / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

test("no element paints a light-theme background", async ({ page }) => {
  await gotoApp(page);

  for (const view of VIEWS) {
    await openView(page, view);
    const bright = await page.evaluate(() => {
      const offenders: Array<{ selector: string; background: string }> = [];
      for (const node of document.querySelectorAll<HTMLElement>("body *")) {
        const style = getComputedStyle(node);
        if (style.visibility === "hidden" || style.display === "none") continue;
        const rect = node.getBoundingClientRect();
        if (rect.width < 4 || rect.height < 4) continue;

        const match = style.backgroundColor.match(/rgba?\((\d+), (\d+), (\d+)(?:, ([\d.]+))?\)/);
        if (!match) continue;
        const alpha = match[4] === undefined ? 1 : Number(match[4]);
        if (alpha < 0.9) continue;
        const [r, g, b] = [Number(match[1]), Number(match[2]), Number(match[3])];
        // White-on-blue buttons and similar accents are deliberate; a large
        // pale *surface* is what signals a leftover light-theme value.
        if (rect.width * rect.height < 12_000) continue;
        const cls = typeof node.className === "string" ? node.className.split(" ")[0] : "";
        offenders.push({ selector: `${node.tagName.toLowerCase()}.${cls}`, background: style.backgroundColor });
      }
      return offenders.filter((entry) => {
        const [r, g, b] = entry.background.match(/\d+/g)!.slice(0, 3).map(Number);
        return true && r + g + b > 0 && entry.background !== "rgba(0, 0, 0, 0)";
      });
    });

    const light = bright.filter((entry) => {
      const [r, g, b] = entry.background.match(/\d+/g)!.slice(0, 3).map(Number);
      return luminance(r, g, b) > 0.5;
    });
    expect(light, `${view} 里有浅色背景的大块元素`).toEqual([]);
  }
});

test("scrollbars use the shared token everywhere", async ({ page }) => {
  await gotoApp(page);
  await openView(page, "实验室");

  const thumbs = await page.evaluate(() => {
    const seen = new Set<string>();
    for (const node of document.querySelectorAll<HTMLElement>("*")) {
      const value = getComputedStyle(node).scrollbarColor;
      if (value && value !== "auto") seen.add(value);
    }
    return [...seen];
  });

  // One declared value across the app; the workbench used to pin its own.
  expect(thumbs.length, `发现 ${thumbs.length} 种滚动条配色：${thumbs.join(" | ")}`).toBeLessThanOrEqual(1);
});

test("the frozen column edge is visible against the dark grid", async ({ page }) => {
  await gotoApp(page);
  const shadow = await page.locator(".request-grid-cell:first-child").first().evaluate(
    (node) => getComputedStyle(node).boxShadow,
  );

  // It used to be a 1px #e8eaec hairline — invisible here, so a horizontally
  // scrolled row read as truncated data rather than content sliding under.
  expect(shadow).not.toBe("none");
  expect(shadow).not.toMatch(/232, 234, 236|229, 232, 234/);
});

test("empty states explain the feature rather than just naming it", async ({ page, viewport }) => {
  test.skip((viewport?.width ?? 0) <= 1060, "窄布局下实验室导航折叠");
  await gotoApp(page);

  // "创建环境后管理变量" and "还没有规则草稿" told the reader nothing about what
  // the feature is for, which is where a first-time user stops.
  await openView(page, "实验室");

  await page.getByRole("button", { name: /环境变量/ }).click();
  await page.waitForTimeout(300);
  const environments = page.locator(".workbench-empty");
  await expect(environments).toBeVisible();
  await expect(environments).toContainText("全局环境");
  await expect(environments).toContainText("命名环境");
  expect((await environments.textContent())!.length).toBeGreaterThan(60);

  await page.getByRole("button", { name: /规则工作台/ }).click();
  await page.waitForTimeout(300);
  const rules = page.locator(".workbench-empty").first();
  await expect(rules).toBeVisible();
  await expect(rules).toContainText("停用");
  expect((await rules.textContent())!.length).toBeGreaterThan(60);
});
