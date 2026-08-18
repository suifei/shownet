import { expect, test } from "@playwright/test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { gotoApp, openView } from "./helpers";

const root = join(dirname(fileURLToPath(import.meta.url)), "../..");
const evidenceDir = join(root, "test-results", "settings-switches");

function parseRgb(value: string): { r: number; g: number; b: number } | null {
  const match = value.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
  if (!match) return null;
  return { r: Number(match[1]), g: Number(match[2]), b: Number(match[3]) };
}

function key(value: string): string {
  const rgb = parseRgb(value);
  return rgb ? `${rgb.r},${rgb.g},${rgb.b}` : value;
}

test("shipped switch CSS keeps off / on / knob off the settings panel", async ({ page }) => {
  const css = await readFile(join(root, "src/styles.css"), "utf8");
  await page.setContent(`<!doctype html><html><body>
    <section class="settings-panel" style="padding:24px">
      <label class="settings-switch-row"><span><strong>接管系统代理</strong></span><input type="checkbox" /><i></i></label>
      <label class="settings-switch-row"><span><strong>流式输出</strong></span><input type="checkbox" checked /><i></i></label>
      <label class="compact-switch" title="启用 Agent 工具"><input type="checkbox" /><i></i></label>
      <label class="compact-switch" title="停用 Agent 工具"><input type="checkbox" checked /><i></i></label>
    </section>
  </body></html>`);
  await page.addStyleTag({ content: css });
  await page.addStyleTag({ content: ".settings-switch-row i, .compact-switch i { transition: none !important; }" });
  await page.waitForFunction(() => {
    const track = document.querySelector(".settings-switch-row i");
    if (!track) return false;
    const color = getComputedStyle(track).backgroundColor;
    return color.startsWith("rgb(") || /rgba\([^)]+,\s*(0\.[2-9]|[1-9])/.test(color);
  });

  const measured = await page.evaluate(() => {
    const panel = getComputedStyle(document.querySelector(".settings-panel")!).backgroundColor;
    const read = (row: Element) => {
      const track = row.querySelector("i")!;
      return {
        label: row.querySelector("strong")?.textContent ?? (row as HTMLElement).title,
        panel,
        track: getComputedStyle(track).backgroundColor,
        knob: getComputedStyle(track, "::after").backgroundColor,
        checked: row.querySelector("input")!.checked,
      };
    };
    return {
      settingsOff: read(document.querySelectorAll(".settings-switch-row")[0]),
      settingsOn: read(document.querySelectorAll(".settings-switch-row")[1]),
      compactOff: read(document.querySelectorAll(".compact-switch")[0]),
      compactOn: read(document.querySelectorAll(".compact-switch")[1]),
    };
  });

  for (const [name, off, on] of [
    ["settings-switch-row", measured.settingsOff, measured.settingsOn],
    ["compact-switch", measured.compactOff, measured.compactOn],
  ] as const) {
    expect(key(off.track), `${name} off vs panel`).not.toBe(key(off.panel));
    expect(key(on.track), `${name} on vs panel`).not.toBe(key(on.panel));
    expect(key(off.track), `${name} off vs on`).not.toBe(key(on.track));
    expect(key(off.knob), `${name} knob vs off`).not.toBe(key(off.track));
    expect(key(on.knob), `${name} knob vs on`).not.toBe(key(on.track));
  }

  await mkdir(evidenceDir, { recursive: true });
  await page.screenshot({ path: join(evidenceDir, "fixture.png") });
  await writeFile(join(evidenceDir, "fixture.json"), `${JSON.stringify(measured, null, 2)}\n`);
});

test("Settings view still mounts the named switch rows", async ({ page }) => {
  await gotoApp(page);
  await openView(page, "设置");
  const takeover = page.locator(".settings-switch-row", { hasText: "接管系统代理" });
  await expect(takeover).toBeVisible();
  const lan = page.locator(".settings-switch-row", { hasText: "允许局域网设备接入" });
  if (!(await lan.isVisible())) {
    await page.getByRole("heading", { name: /设备接入/ }).click();
  }
  await expect(lan).toBeVisible();
  await mkdir(evidenceDir, { recursive: true });
  await page.screenshot({ path: join(evidenceDir, "settings-app.png") });
});
