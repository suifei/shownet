import { expect, test, type Browser, type Page } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { EN_PACK, ZH_PACK, lookupMessage, type LanguagePack } from "../../src/i18n";
import { NAV_VIEWS, chromeLabel, chromeTitle } from "../../src/navChrome";
import { gotoApp } from "./helpers";

const evidenceDir = join(dirname(fileURLToPath(import.meta.url)), "../../test-results/i18n-coverage");
const CJK = /[\u3400-\u9FFF\uF900-\uFAFF]/;

const SURFACES = [
  { id: "traffic", nav: "traffic" as const },
  { id: "browser", nav: "browser" as const },
  { id: "lab", nav: "lab" as const },
  { id: "advanced", nav: "advanced" as const },
  { id: "analysis", nav: "analysis" as const },
  { id: "skills", nav: "skills" as const },
  { id: "settings-capture", nav: "settings" as const, tab: "capture" },
  { id: "settings-ai", nav: "settings" as const, tab: "ai" },
  { id: "settings-data", nav: "settings" as const, tab: "data" },
  { id: "settings-mcp", nav: "settings" as const, tab: "mcp" },
] as const;

interface SurfaceScan {
  id: string;
  strings: string[];
  cjk: string[];
}

function packLabel(pack: LanguagePack, view: (typeof NAV_VIEWS)[number]) {
  return chromeLabel((key) => lookupMessage(pack, key), view);
}

function packTitle(pack: LanguagePack, view: (typeof NAV_VIEWS)[number]) {
  return chromeTitle((key) => lookupMessage(pack, key), view);
}

async function openLocale(browser: Browser, locale: string): Promise<Page> {
  const context = await browser.newContext({
    locale,
    viewport: { width: 1440, height: 900 },
    baseURL: "http://127.0.0.1:1420",
  });
  const page = await context.newPage();
  await gotoApp(page);
  return page;
}

async function collectVisibleCopy(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const hidden = (node: Element | null) => {
      for (let current = node; current; current = current.parentElement) {
        const style = getComputedStyle(current);
        if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return true;
      }
      return false;
    };

    const texts = new Set<string>();
    const add = (raw: string | null | undefined) => {
      const text = (raw ?? "").replace(/\s+/g, " ").trim();
      if (text.length >= 2) texts.add(text);
    };

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      const parent = node.parentElement;
      if (!parent || parent.closest("script, style, noscript")) continue;
      if (hidden(parent)) continue;
      const box = parent.getBoundingClientRect();
      if (box.width < 1 || box.height < 1) continue;
      add(node.textContent);
    }

    for (const node of document.querySelectorAll<HTMLElement>("[placeholder], [title], [aria-label], [aria-placeholder]")) {
      if (hidden(node)) continue;
      add(node.getAttribute("placeholder"));
      add(node.getAttribute("title"));
      add(node.getAttribute("aria-label"));
      add(node.getAttribute("aria-placeholder"));
    }
    return [...texts];
  });
}

async function dismissBlockingOverlays(page: Page) {
  const setup = page.locator(".setup-guide");
  if (await setup.isVisible().catch(() => false)) {
    await page.keyboard.press("Escape").catch(() => undefined);
    if (await setup.isVisible().catch(() => false)) {
      await page.locator(".modal-backdrop").first().click({ position: { x: 8, y: 8 } }).catch(() => undefined);
    }
  }
}

async function openSurface(page: Page, surface: (typeof SURFACES)[number]) {
  await page.locator(`[data-nav='${surface.nav}']`).first().click();
  await expect(page.locator(`[data-nav='${surface.nav}']`).first()).toHaveClass(/is-active/);
  if ("tab" in surface && surface.tab) {
    const tab = page.locator(`[data-settings-tab='${surface.tab}']`);
    await tab.click();
    await expect(tab).toHaveClass(/is-active/);
  }
  await page.waitForTimeout(200);
}

async function scanSurface(page: Page, locale: string, surface: (typeof SURFACES)[number]): Promise<SurfaceScan> {
  await openSurface(page, surface);
  await mkdir(evidenceDir, { recursive: true });
  await page.screenshot({ path: join(evidenceDir, `${locale}-${surface.id}.png`), fullPage: true });
  const strings = await collectVisibleCopy(page);
  return { id: surface.id, strings, cjk: strings.filter((text) => CJK.test(text)) };
}

async function scanOverlay(page: Page, locale: string, id: string, open: () => Promise<void>, root: string): Promise<SurfaceScan> {
  await open();
  const host = page.locator(root).first();
  await expect(host).toBeVisible();
  await mkdir(evidenceDir, { recursive: true });
  await page.screenshot({ path: join(evidenceDir, `${locale}-${id}.png`) });
  const strings = await collectVisibleCopy(page);
  const scan = { id, strings, cjk: strings.filter((text) => CJK.test(text)) };
  await page.keyboard.press("Escape").catch(() => undefined);
  if (await host.isVisible().catch(() => false)) {
    await page.locator(".modal-backdrop").first().click({ position: { x: 8, y: 8 } }).catch(() => undefined);
  }
  await expect(host).toBeHidden({ timeout: 3_000 }).catch(() => undefined);
  return scan;
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right, "zh"));
}

const FIXTURE_MARKERS = [
  "电商登录链路",
  "桌面客户端同步",
  "OAuth 回调排查",
  "设备心跳协议",
  "今天 14:32",
  "今天 11:08",
  "昨天 18:44",
  "7月28日",
];

function isFixtureCopy(text: string): boolean {
  return FIXTURE_MARKERS.some((marker) => text.includes(marker));
}

function renderReport(input: {
  chrome: Array<{ key: string; zh: string; en: string; zhSeen: string; enSeen: string; ok: boolean }>;
  leftover: Array<{ surface: string; strings: string[] }>;
  uniqueChrome: string[];
  uniqueFixture: string[];
  palette: Array<{ id: string; zh: string; en: string; switched: boolean }>;
  zhCjk: number;
  enCjk: number;
}): string {
  const leftoverCount = input.leftover.reduce((sum, row) => sum + row.strings.length, 0);
  const lines = [
    "# UI i18n e2e coverage",
    "",
    `English leftover CJK occurrences: **${leftoverCount}** across ${input.leftover.length} surfaces.`,
    `Distinct leftover UI strings (fixture data removed): **${input.uniqueChrome.length}**.`,
    `Distinct leftover fixture/demo strings: **${input.uniqueFixture.length}**.`,
    `Raw CJK string counts: zh-CN ${input.zhCjk}, en-US ${input.enCjk}.`,
    "",
    "## Pack-backed chrome (must switch)",
    "",
    "| key | zh pack | en pack | zh seen | en seen | ok |",
    "| --- | --- | --- | --- | --- | --- |",
    ...input.chrome.map((row) =>
      `| ${row.key} | ${row.zh} | ${row.en} | ${row.zhSeen} | ${row.enSeen} | ${row.ok ? "yes" : "NO"} |`,
    ),
    "",
    "## Command palette navigate titles",
    "",
    "| id | zh | en | switched |",
    "| --- | --- | --- | --- |",
    ...input.palette.map((row) => `| ${row.id} | ${row.zh} | ${row.en} | ${row.switched ? "yes" : "NO"} |`),
    "",
    "## Distinct leftover UI strings on en-US",
    "",
    "These stay Chinese after the English pack is active. They are the real i18n gap.",
    "",
    ...input.uniqueChrome.map((text) => `- ${text}`),
    "",
    "## Fixture / demo data still in Chinese",
    "",
    "Preview sessions ship preformatted Chinese names and clocks. Not language-pack keys.",
    "",
    ...input.uniqueFixture.slice(0, 40).map((text) => `- ${text}`),
    ...(input.uniqueFixture.length > 40 ? [`- … ${input.uniqueFixture.length - 40} more`] : []),
    "",
    "## Leftover Chinese by surface",
    "",
  ];
  for (const row of input.leftover) {
    lines.push(`### ${row.surface}`, "");
    for (const text of row.strings.slice(0, 80)) lines.push(`- ${text}`);
    if (row.strings.length > 80) lines.push(`- … ${row.strings.length - 80} more`);
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

test.describe("i18n coverage", () => {
  test.describe.configure({ timeout: 120_000 });

  test.beforeEach(({ viewport }) => {
    test.skip((viewport?.width ?? 0) !== 1440, "full-surface scan is desktop-only");
  });

  test("visible UI text is not fully multilingual — pack chrome switches, page bodies stay Chinese", async ({ browser }) => {
    const zhPage = await openLocale(browser, "zh-CN");
    const enPage = await openLocale(browser, "en-US");

    try {
      const zhScans: SurfaceScan[] = [];
      const enScans: SurfaceScan[] = [];
      if (await zhPage.locator(".setup-guide").isVisible().catch(() => false)) {
        const strings = await collectVisibleCopy(zhPage);
        zhScans.push({ id: "setup-guide", strings, cjk: strings.filter((text) => CJK.test(text)) });
        await mkdir(evidenceDir, { recursive: true });
        await zhPage.screenshot({ path: join(evidenceDir, "zh-CN-setup-guide.png") });
      }
      if (await enPage.locator(".setup-guide").isVisible().catch(() => false)) {
        const strings = await collectVisibleCopy(enPage);
        enScans.push({ id: "setup-guide", strings, cjk: strings.filter((text) => CJK.test(text)) });
        await mkdir(evidenceDir, { recursive: true });
        await enPage.screenshot({ path: join(evidenceDir, "en-US-setup-guide.png") });
      }
      await dismissBlockingOverlays(zhPage);
      await dismissBlockingOverlays(enPage);

      const chrome: Array<{ key: string; zh: string; en: string; zhSeen: string; enSeen: string; ok: boolean }> = [];
      for (const view of NAV_VIEWS) {
        const zhExpected = packLabel(ZH_PACK, view);
        const enExpected = packLabel(EN_PACK, view);
        const zhButton = zhPage.locator(`[data-nav='${view}']`).first();
        const enButton = enPage.locator(`[data-nav='${view}']`).first();
        await expect(zhButton).toHaveText(zhExpected);
        await expect(enButton).toHaveText(enExpected);
        const zhSeen = ((await zhButton.innerText()) ?? "").trim();
        const enSeen = ((await enButton.innerText()) ?? "").trim();
        chrome.push({
          key: `nav.${view}`,
          zh: zhExpected,
          en: enExpected,
          zhSeen,
          enSeen,
          ok: zhSeen === zhExpected && enSeen === enExpected && zhExpected !== enExpected,
        });
      }

      for (const group of ["navGroup.capture", "navGroup.tools", "navGroup.intelligence"] as const) {
        const zhExpected = lookupMessage(ZH_PACK, group);
        const enExpected = lookupMessage(EN_PACK, group);
        const zhGroup = zhPage.locator(`.nav-rail__group[aria-label='${zhExpected}']`);
        const enGroup = enPage.locator(`.nav-rail__group[aria-label='${enExpected}']`);
        await expect(zhGroup).toHaveCount(1);
        await expect(enGroup).toHaveCount(1);
        chrome.push({
          key: group,
          zh: zhExpected,
          en: enExpected,
          zhSeen: zhExpected,
          enSeen: enExpected,
          ok: zhExpected !== enExpected,
        });
      }

      for (const surface of SURFACES) {
        zhScans.push(await scanSurface(zhPage, "zh-CN", surface));
        enScans.push(await scanSurface(enPage, "en-US", surface));
        const view = surface.nav;
        const zhTitle = packTitle(ZH_PACK, view);
        const enTitle = packTitle(EN_PACK, view);
        const zhH1 = ((await zhPage.locator(".topbar h1").innerText()) ?? "").trim();
        const enH1 = ((await enPage.locator(".topbar h1").innerText()) ?? "").trim();
        const key = `view.${view}`;
        if (!chrome.some((row) => row.key === key)) {
          chrome.push({
            key,
            zh: zhTitle,
            en: enTitle,
            zhSeen: zhH1,
            enSeen: enH1,
            ok: zhH1 === zhTitle && enH1 === enTitle && zhTitle !== enTitle,
          });
        }
        expect(zhH1, `${surface.id} zh title`).toBe(zhTitle);
        expect(enH1, `${surface.id} en title`).toBe(enTitle);
      }

      const overlaySpecs: Array<{ id: string; root: string; open: (page: Page) => Promise<void> }> = [
        {
          id: "command-palette",
          root: ".command-palette",
          open: async (page) => {
            await page.locator(".command-button").click();
          },
        },
        {
          id: "about",
          root: ".about-dialog",
          open: async (page) => {
            await page.locator(".brand-mark").click();
          },
        },
        {
          id: "shortcuts",
          root: ".shortcuts-sheet",
          open: async (page) => {
            await page.locator(".workspace").click({ position: { x: 24, y: 24 } });
            await page.keyboard.press("?");
          },
        },
        {
          id: "session-menu",
          root: ".session-tools-menu",
          open: async (page) => {
            await page.locator(".sessions-label .icon-button").click();
          },
        },
      ];

      for (const overlay of overlaySpecs) {
        zhScans.push(await scanOverlay(zhPage, "zh-CN", overlay.id, () => overlay.open(zhPage), overlay.root));
        enScans.push(await scanOverlay(enPage, "en-US", overlay.id, () => overlay.open(enPage), overlay.root));
      }

      const zhPalette = zhScans.find((scan) => scan.id === "command-palette");
      const enPalette = enScans.find((scan) => scan.id === "command-palette");
      const palette = NAV_VIEWS.map((view) => {
        const zh = packLabel(ZH_PACK, view);
        const en = packLabel(EN_PACK, view);
        return {
          id: `go-${view}`,
          zh,
          en,
          switched: Boolean(zhPalette?.strings.includes(zh) && enPalette?.strings.includes(en) && zh !== en),
        };
      });
      for (const row of palette) {
        expect(zhPalette?.strings, `palette zh ${row.id}`).toContain(row.zh);
        expect(enPalette?.strings, `palette en ${row.id}`).toContain(row.en);
      }

      const leftover = enScans
        .map((scan) => ({ surface: scan.id, strings: unique(scan.cjk) }))
        .filter((row) => row.strings.length > 0);
      const leftoverCount = leftover.reduce((sum, row) => sum + row.strings.length, 0);
      const zhCjk = unique(zhScans.flatMap((scan) => scan.cjk)).length;
      const enCjk = unique(enScans.flatMap((scan) => scan.cjk)).length;
      const allLeftover = unique(enScans.flatMap((scan) => scan.cjk));
      const uniqueFixture = allLeftover.filter((text) => isFixtureCopy(text));
      const uniqueChrome = allLeftover.filter((text) => !isFixtureCopy(text));

      const report = renderReport({
        chrome,
        leftover,
        uniqueChrome,
        uniqueFixture,
        palette,
        zhCjk,
        enCjk,
      });
      await mkdir(evidenceDir, { recursive: true });
      await writeFile(join(evidenceDir, "report.md"), report);
      await writeFile(
        join(evidenceDir, "scan.json"),
        JSON.stringify({
          chrome,
          palette,
          leftoverCount,
          uniqueChromeCount: uniqueChrome.length,
          uniqueFixtureCount: uniqueFixture.length,
          zhCjk,
          enCjk,
          uniqueChrome,
          leftover,
        }, null, 2),
      );
      await test.info().attach("i18n-coverage-report", { body: report, contentType: "text/markdown" });

      expect(chrome.every((row) => row.ok), "every pack-backed chrome string must switch").toBe(true);
      expect(palette.every((row) => row.switched), "palette navigate titles must switch").toBe(true);
      await expect(enPage.locator(".command-button")).toHaveText(lookupMessage(EN_PACK, "shell.command"));
      await expect(zhPage.locator(".command-button")).toHaveText(lookupMessage(ZH_PACK, "shell.command"));
      await expect(enPage.locator(".sessions-label span").first()).toHaveText(lookupMessage(EN_PACK, "shell.sessions"));
      await expect(zhPage.locator(".sessions-label span").first()).toHaveText(lookupMessage(ZH_PACK, "shell.sessions"));

      // Inventory only — a zero leftover count would mean page bodies are
      // actually packed. The report lists every leftover CJK string.
      expect(leftoverCount, `en-US leftover CJK count; see ${join(evidenceDir, "report.md")}`).toBeGreaterThan(0);
    } finally {
      await zhPage.context().close();
      await enPage.context().close();
    }
  });
});
