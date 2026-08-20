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

test("declares the dark color scheme so native UI matches", async ({ page }) => {
  await page.goto("/");
  // Scrollbars, form controls and focus rings are drawn by the engine, not by
  // our CSS. Without this declaration it draws them light, which on a dark app
  // reads as near-white bars — and no `::-webkit-scrollbar` rule can override
  // it, because those elements never enter the CSS path at all.
  const scheme = await page.evaluate(
    () => getComputedStyle(document.documentElement).colorScheme,
  );
  expect(scheme).toContain("dark");
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("dark");

  // The custom thumb must stay dim enough to read as chrome rather than content.
  const thumb = await page.evaluate(() =>
    getComputedStyle(document.documentElement).getPropertyValue("--scrollbar-thumb").trim(),
  );
  const channels = thumb.replace("#", "").match(/../g)!.map((pair) => parseInt(pair, 16));
  const brightest = Math.max(...channels);
  expect(brightest, `scrollbar thumb ${thumb} is too bright for a dark surface`).toBeLessThan(140);
});

test("light preference swaps the semantic ramp and native color scheme", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("shownet.ui.theme", "light"));
  await page.goto("/");
  await page.waitForSelector(".app-shell");

  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("light");
  const scheme = await page.evaluate(
    () => getComputedStyle(document.documentElement).colorScheme,
  );
  expect(scheme).toContain("light");

  const pageBg = await page.evaluate(() =>
    getComputedStyle(document.documentElement).getPropertyValue("--surface-page").trim(),
  );
  const text = await page.evaluate(() =>
    getComputedStyle(document.documentElement).getPropertyValue("--text-primary").trim(),
  );
  expect(pageBg.toLowerCase()).toBe("#e9edf3");
  expect(text.toLowerCase()).toBe("#1d1d1f");

  const canvas = await page.locator(".app-shell").evaluate((node) => {
    const color = getComputedStyle(node).backgroundColor;
    const match = color.match(/rgba?\((\d+), (\d+), (\d+)/);
    return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : [0, 0, 0];
  });
  expect(canvas[0] + canvas[1] + canvas[2], `light canvas stayed dark: ${canvas.join(",")}`).toBeGreaterThan(400);
});

test("the topbar appearance menu switches light and dark without a reload", async ({ page }) => {
  await gotoApp(page);
  await page.getByRole("button", { name: "外观" }).click();
  await page.getByRole("option", { name: "浅色" }).click();
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("light");
  expect(await page.evaluate(() => localStorage.getItem("shownet.ui.theme"))).toBe("light");

  await page.getByRole("button", { name: "外观" }).click();
  await page.getByRole("option", { name: "跟随系统" }).click();
  expect(await page.evaluate(() => localStorage.getItem("shownet.ui.theme"))).toBe("system");

  await page.getByRole("button", { name: "外观" }).click();
  await page.getByRole("option", { name: "深色" }).click();
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("dark");
  expect(await page.evaluate(() => localStorage.getItem("shownet.ui.theme"))).toBe("dark");
});

test("settings appearance radios apply the same preference", async ({ page, viewport }) => {
  test.skip((viewport?.width ?? 0) <= 1060, "窄布局下设置导航折叠");
  await gotoApp(page);
  await openView(page, "设置");
  await page.locator("[data-settings-tab=data]").click();
  const light = page.getByRole("radio", { name: "浅色" });
  await expect(light).toBeVisible();
  await light.click();
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("light");
  await page.getByRole("radio", { name: "深色" }).click();
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("dark");
});

test("floating surfaces read as glass with thickness", async ({ page }) => {
  await page.goto("/");
  await page.getByTitle("快捷命令").click();
  const palette = page.locator(".command-palette");
  await expect(palette).toBeVisible();

  const shadow = await palette.evaluate((el) => getComputedStyle(el).boxShadow);
  // Glass catches light on its whole rim, not just along the top. A single
  // inset line is a drawn border; three layers — perimeter, lit top, and a
  // short inner falloff — is what makes the edge look like it has depth.
  const insets = shadow.split(/,(?![^(]*\))/).filter((part) => part.includes("inset"));
  expect(insets.length, `expected a layered rim, got: ${shadow}`).toBeGreaterThanOrEqual(3);

  // Bright enough to see. An earlier attempt sat at ~1% brightness difference,
  // which measured as "applied" and looked like nothing at all.
  const brightest = Math.max(
    ...[...shadow.matchAll(/rgba?\(([^)]+)\)/g)].map((match) => {
      // The default has to be a number like its siblings: `.map(parseFloat)`
      // yields numbers, so a string default only survives because parseFloat
      // coerces it back. Drop the outer parseFloat and it silently compares a
      // string instead.
      const [r, g, b, a = 1] = match[1].split(",").map((v) => parseFloat(v));
      return Math.max(r, g, b) > 200 ? a : 0;
    }),
  );
  expect(brightest, `rim highlight is too faint to notice: ${shadow}`).toBeGreaterThan(0.1);
});

test("the dense interface keeps its flat chrome", async ({ page }) => {
  await page.goto("/");
  // The rim belongs to surfaces that float over content. Putting it on the grid
  // or the rails would outline every panel in the app.
  for (const selector of [".request-grid", ".nav-rail", ".sessions-panel"]) {
    const element = page.locator(selector).first();
    if ((await element.count()) === 0) continue;
    const shadow = await element.evaluate((el) => getComputedStyle(el).boxShadow);
    const insets = shadow.split(/,(?![^(]*\))/).filter((part) => part.includes("inset"));
    expect(insets.length, `${selector} picked up the floating-surface rim`).toBeLessThan(3);
  }
});
