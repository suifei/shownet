import type { Page } from "@playwright/test";

/** Nav rail labels, in the order they appear. */
export const VIEWS = ["流量", "浏览器", "实验室", "高级", "AI 分析", "能力", "设置"] as const;

export interface GotoOptions {
  /**
   * Load the 100k-request fixture. The preview seed is 15 rows, which fit on
   * screen — so scrolling and virtualization cannot be exercised without it.
   */
  largeList?: boolean;
}

export async function gotoApp(page: Page, options: GotoOptions = {}) {
  await page.goto(options.largeList ? "/?fixture=request-window-100k" : "/");
  try {
    await page.waitForSelector(".app-shell", { timeout: 20_000 });
  } catch {
    // Observed once on a Windows runner: goto resolved, then .app-shell never
    // appeared inside 90s while sibling tests in the same project mounted in
    // ~1.2s. The page arrived and React did not mount — in dev Vite serves the
    // module graph unbundled, hundreds of requests per navigation, and one of
    // them stalling looks exactly like this. A reload refetches what is missing.
    //
    // Deliberately narrow: this retries the navigation only. Assertions still
    // get a single attempt, so a real layout regression cannot retry its way to
    // green. Serving a production build instead would remove the problem at the
    // root, but the 100k-row fixture is gated on import.meta.env.DEV, so the
    // largeList tests would quietly fall back to the 15-row seed and still pass.
    await page.reload();
    await page.waitForSelector(".app-shell", { timeout: 30_000 });
  }
  // The request list and its detail pane settle asynchronously.
  await page.waitForSelector(".request-grid-body");
}

export async function openView(page: Page, label: string) {
  await page.locator(".nav-rail__item", { hasText: new RegExp(`^${label}$`) }).first().click();
  await page.waitForTimeout(250);
}

export interface CrushedElement {
  selector: string;
  text: string;
  lines: number;
  charsPerLine: number;
}

/**
 * Text wrapped into many nearly-empty lines.
 *
 * This is the signature of the worst layout bug found during the redesign: a
 * `width: 28px` icon rule matched labelled buttons, so every menu row wrapped
 * to roughly one character per line. Nothing in the DOM was wrong — only the
 * geometry.
 *
 * Lines are counted from the rendered line boxes of the text itself, not from
 * the element's height. An icon or an input inside a control adds height while
 * contributing no text, and measuring the box instead flags those as crushed.
 */
export async function findCrushedText(page: Page): Promise<CrushedElement[]> {
  return page.evaluate(() => {
    const describe = (node: Element) => {
      const cls = node.className && typeof node.className === "string"
        ? `.${node.className.trim().split(/\s+/).slice(0, 2).join(".")}`
        : "";
      return `${node.tagName.toLowerCase()}${cls}`;
    };

    /** Distinct rendered text lines, and how many characters they hold. */
    const measureText = (node: Element) => {
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT);
      const range = document.createRange();
      // Line boxes are bucketed by their top edge; text of different sizes on
      // one visual line differs by a few pixels, real lines by far more.
      const tops = new Set<number>();
      let chars = 0;
      while (walker.nextNode()) {
        const textNode = walker.currentNode;
        const text = (textNode.textContent ?? "").replace(/\s+/g, " ").trim();
        if (!text) continue;
        chars += text.length;
        range.selectNodeContents(textNode);
        for (const rect of range.getClientRects()) {
          if (rect.width > 0 && rect.height > 0) tops.add(Math.round(rect.top / 6));
        }
      }
      return { lines: tops.size, chars };
    };

    const crushed: Array<{ selector: string; text: string; lines: number; charsPerLine: number }> = [];
    // Controls with a visible label are what the bug class applies to.
    const selector = 'button, a, summary, [role="menuitem"], [role="tab"], [role="option"]';
    for (const node of document.querySelectorAll<HTMLElement>(selector)) {
      const style = getComputedStyle(node);
      if (style.visibility === "hidden" || style.display === "none") continue;
      if (style.writingMode.startsWith("vertical")) continue;

      const rect = node.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;

      const { lines, chars } = measureText(node);
      if (lines < 3 || chars < 4) continue;

      const charsPerLine = chars / lines;
      // Three or more lines averaging under four characters cannot be a real
      // label; the box is too narrow for its own text.
      if (charsPerLine < 4) {
        const text = (node.textContent ?? "").replace(/\s+/g, " ").trim();
        crushed.push({
          selector: describe(node),
          text: text.slice(0, 40),
          lines,
          charsPerLine: Math.round(charsPerLine * 10) / 10,
        });
      }
    }
    return crushed;
  });
}

export interface OverflowReport {
  pageScrollWidth: number;
  pageClientWidth: number;
  offenders: Array<{ selector: string; right: number; viewportWidth: number }>;
}

/**
 * The page body must never scroll horizontally, and nothing may stick out of it.
 *
 * Content wider than the window is fine *inside* a scroll container — the
 * request grid is exactly that. Exemption has to be checked all the way up the
 * ancestor chain, not just at the immediate parent, because the wide elements
 * are cells nested several levels below the scrolling element.
 */
export async function findHorizontalOverflow(page: Page): Promise<OverflowReport> {
  return page.evaluate(() => {
    const describe = (node: Element) => {
      const cls = node.className && typeof node.className === "string"
        ? `.${node.className.trim().split(/\s+/).slice(0, 2).join(".")}`
        : "";
      return `${node.tagName.toLowerCase()}${cls}`;
    };

    const insideScroller = (node: Element) => {
      for (let parent = node.parentElement; parent && parent !== document.body; parent = parent.parentElement) {
        const style = getComputedStyle(parent);
        if (/(auto|scroll|hidden)/.test(style.overflowX) || /(auto|scroll|hidden)/.test(style.overflow)) return true;
      }
      return false;
    };

    const viewportWidth = document.documentElement.clientWidth;
    const offenders: Array<{ selector: string; right: number; viewportWidth: number }> = [];
    for (const node of document.querySelectorAll<HTMLElement>("body *")) {
      const style = getComputedStyle(node);
      if (style.visibility === "hidden" || style.display === "none") continue;
      const rect = node.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) continue;
      if (rect.right > viewportWidth + 1 && !insideScroller(node)) {
        offenders.push({ selector: describe(node), right: Math.round(rect.right), viewportWidth });
      }
    }
    return {
      pageScrollWidth: document.documentElement.scrollWidth,
      pageClientWidth: viewportWidth,
      offenders: offenders.slice(0, 8),
    };
  });
}

/** Overlays and popovers must stay inside the window. */
export async function findOffscreenLayers(page: Page) {
  return page.evaluate(() => {
    const selectors = [
      ".selection-bar", ".selection-more-menu", ".collection-pane-menu", ".lab-curl-menu",
      ".traffic-popover", ".session-tools-menu", ".request-context-menu", ".command-palette",
      ".confirm-dialog", ".shortcuts-sheet", ".setup-guide",
    ];
    const width = document.documentElement.clientWidth;
    const height = document.documentElement.clientHeight;
    const bad: Array<{ selector: string; box: string }> = [];
    for (const selector of selectors) {
      for (const node of document.querySelectorAll<HTMLElement>(selector)) {
        const rect = node.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) continue;
        if (rect.left < -1 || rect.top < -1 || rect.right > width + 1 || rect.bottom > height + 1) {
          bad.push({
            selector,
            box: `${Math.round(rect.left)},${Math.round(rect.top)} → ${Math.round(rect.right)},${Math.round(rect.bottom)} in ${width}x${height}`,
          });
        }
      }
    }
    return bad;
  });
}
