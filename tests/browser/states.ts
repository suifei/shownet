import type { Page } from "@playwright/test";

/**
 * Every UI state the audit walks through.
 *
 * The point is coverage of *reachable* states, not of components: a popover
 * that only opens after two clicks, a context menu that only exists on
 * right-click, a pane that only appears once something is selected. Those are
 * exactly the places a layout rule goes unnoticed.
 */
export interface UiState {
  id: string;
  /** Views this state belongs to, for reporting. */
  area: string;
  /** Drive the app into the state. Throws or returns false if unreachable. */
  enter: (page: Page) => Promise<boolean | void>;
  /**
   * Narrowest viewport this state exists at. The session panel is hidden
   * outright below 1060px, so everything inside it is simply unreachable there
   * — not broken.
   */
  minWidth?: number;
}

const settle = (page: Page, ms = 260) => page.waitForTimeout(ms);

async function goView(page: Page, label: string) {
  await page.locator(".nav-rail__item", { hasText: new RegExp(`^${label}$`) }).first().click();
  await settle(page, 350);
}

/** Click the first match if it exists; returns false when the affordance is absent. */
async function clickIfPresent(page: Page, selector: string) {
  const target = page.locator(selector).first();
  if (!(await target.count()) || !(await target.isVisible())) return false;
  await target.click();
  await settle(page);
  return true;
}

export const STATES: UiState[] = [
  { id: "traffic.default", area: "流量", enter: (p) => goView(p, "流量") },

  {
    id: "traffic.row-context-menu",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-row").nth(3).click({ button: "right" });
      await settle(page);
    },
  },
  {
    id: "traffic.header-context-menu",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-header-cell").nth(2).click({ button: "right" });
      await settle(page);
    },
  },
  {
    id: "traffic.multi-select-context-menu",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-row").nth(1).click();
      await page.locator(".request-grid-row").nth(4).click({ modifiers: ["Shift"] });
      await page.locator(".request-grid-row").nth(4).click({ button: "right" });
      await settle(page);
    },
  },
  {
    id: "traffic.selection-overflow",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-row").nth(2).click();
      await page.getByRole("button", { name: /更多/ }).first().click();
      await settle(page);
    },
  },
  {
    id: "traffic.filter-quick",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.getByRole("button", { name: /筛选/ }).click();
      await settle(page);
    },
  },
  {
    id: "traffic.filter-builder",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.getByRole("button", { name: /筛选/ }).click();
      await page.getByRole("tab", { name: "条件" }).click();
      await settle(page);
    },
  },
  {
    id: "traffic.filter-views",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.getByRole("button", { name: /筛选/ }).click();
      await page.getByRole("tab", { name: "视图" }).click();
      await settle(page);
    },
  },
  {
    id: "traffic.column-menu",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.getByTitle("配置列").click();
      await settle(page);
    },
  },
  {
    id: "traffic.live-popover",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.getByTitle("实时刷新设置").click();
      await settle(page);
    },
  },
  {
    id: "traffic.facet-sidebar-closed",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await clickIfPresent(page, "[title='收起统计侧栏']");
    },
  },
  {
    id: "traffic.detail-bottom",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-row").nth(1).click();
      await page.getByTitle("详情置于底部").click();
      await settle(page);
    },
  },
  {
    id: "traffic.detail-maximized",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-row").nth(1).click();
      await page.getByTitle("最大化详情").click();
      await settle(page);
    },
  },
  {
    id: "traffic.code-dialog",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-row").nth(1).click();
      await page.getByTitle("生成请求代码").click();
      await settle(page);
    },
  },
  {
    id: "traffic.scrolled",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-scroll").hover();
      await page.mouse.wheel(0, 600);
      await settle(page);
    },
  },
  {
    id: "traffic.scrolled-horizontally",
    area: "流量",
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".request-grid-scroll").hover();
      await page.mouse.wheel(700, 0);
      await settle(page);
    },
  },
  {
    id: "session.tools-menu",
    area: "会话",
    minWidth: 1061,
    enter: async (page) => {
      await goView(page, "流量");
      await page.getByTitle("会话菜单").click();
      await settle(page);
    },
  },
  {
    id: "session.rename",
    area: "会话",
    minWidth: 1061,
    enter: async (page) => {
      await goView(page, "流量");
      await page.locator(".session-rename-button").first().click();
      await settle(page);
    },
  },
  {
    id: "session.export-dialog",
    area: "会话",
    minWidth: 1061,
    enter: async (page) => {
      await goView(page, "流量");
      await page.getByTitle("会话菜单").click();
      await page.getByRole("button", { name: /导出为其他格式/ }).click();
      await settle(page);
    },
  },
  {
    id: "session.compact-rail",
    area: "会话",
    minWidth: 1061,
    enter: async (page) => {
      await goView(page, "流量");
      return clickIfPresent(page, "[title='收起会话']");
    },
  },

  { id: "connect.browser", area: "连接", enter: async (page) => { await page.getByRole("button", { name: /个来源/ }).click(); await settle(page); } },
  {
    id: "connect.terminal",
    area: "连接",
    enter: async (page) => {
      await page.getByRole("button", { name: /个来源/ }).click();
      await page.locator(".source-option", { hasText: "终端" }).first().click();
      await settle(page);
    },
  },
  {
    id: "connect.mobile",
    area: "连接",
    enter: async (page) => {
      await page.getByRole("button", { name: /个来源/ }).click();
      await page.locator(".source-option", { hasText: "移动设备" }).first().click();
      await settle(page);
    },
  },
  {
    id: "connect.reverse",
    area: "连接",
    enter: async (page) => {
      await page.getByRole("button", { name: /个来源/ }).click();
      await page.locator(".source-option--wide").first().click();
      await settle(page);
    },
  },
  {
    id: "connect.script",
    area: "连接",
    enter: async (page) => {
      await page.getByRole("button", { name: /个来源/ }).click();
      await page.locator(".source-option", { hasText: "脚本" }).first().click();
      await settle(page);
    },
  },

  { id: "overlay.command-palette", area: "浮层", enter: async (page) => { await page.getByTitle("快捷命令").click(); await settle(page); } },
  {
    id: "overlay.command-palette-query",
    area: "浮层",
    enter: async (page) => {
      await page.getByTitle("快捷命令").click();
      await page.locator(".command-search input").fill("ca");
      await settle(page);
    },
  },
  { id: "overlay.shortcuts", area: "浮层", enter: async (page) => { await page.keyboard.press("?"); await settle(page); } },
  { id: "overlay.about", area: "浮层", enter: async (page) => { await page.getByTitle(/关于 ShowNet/).click(); await settle(page); } },

  { id: "lab.start", area: "实验室", enter: (p) => goView(p, "实验室") },
  {
    id: "lab.draft",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /空白请求/ }).click();
      await settle(page, 400);
    },
  },
  {
    id: "lab.draft-body",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /空白请求/ }).click();
      await page.getByRole("button", { name: /请求体/ }).click();
      await settle(page);
    },
  },
  {
    id: "lab.draft-auth",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /空白请求/ }).click();
      await page.getByRole("button", { name: /^认证/ }).click();
      await settle(page);
    },
  },
  {
    id: "lab.draft-settings",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /空白请求/ }).click();
      await page.getByRole("button", { name: /发送设置/ }).click();
      await settle(page);
    },
  },
  {
    id: "lab.curl-menu",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /空白请求/ }).click();
      await page.getByTitle("cURL 导入与导出").click();
      await settle(page);
    },
  },
  {
    id: "lab.code-panel",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /空白请求/ }).click();
      await page.getByTitle("生成代码").click();
      await settle(page);
    },
  },
  {
    id: "lab.collections",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /请求集合/ }).click();
      await settle(page, 400);
    },
  },
  {
    id: "lab.collection-selected",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /请求集合/ }).click();
      await page.locator(".collection-tree-label").first().click();
      await settle(page);
    },
  },
  {
    id: "lab.collection-menu",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /请求集合/ }).click();
      await page.locator(".collection-tree-label").first().click();
      await page.getByRole("button", { name: /更多/ }).click();
      await settle(page);
    },
  },
  {
    id: "lab.environment",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /环境变量/ }).click();
      await settle(page, 400);
    },
  },
  {
    id: "lab.rules",
    area: "实验室",
    enter: async (page) => {
      await goView(page, "实验室");
      await page.getByRole("button", { name: /规则工作台/ }).click();
      await settle(page, 400);
    },
  },

  ...["总览", "捕获", "Hook", "规则", "指纹", "PX 证据", "reCAPTCHA", "配置"].map((tab) => ({
    id: `advanced.${tab}`,
    area: "高级",
    enter: async (page: Page) => {
      await goView(page, "高级");
      await page.locator(".advanced-console-tabs button", { hasText: tab }).first().click();
      await settle(page);
    },
  })),

  { id: "analysis.default", area: "AI 分析", enter: (p) => goView(p, "AI 分析") },
  ...["安全审计", "性能分析", "JS 加密逆向"].map((mode) => ({
    id: `analysis.mode-${mode}`,
    area: "AI 分析",
    enter: async (page: Page) => {
      await goView(page, "AI 分析");
      await page.locator(".analysis-mode-list button", { hasText: mode }).first().click();
      await settle(page);
    },
  })),
  {
    id: "analysis.history-open",
    area: "AI 分析",
    enter: async (page) => {
      await goView(page, "AI 分析");
      await clickIfPresent(page, ".analysis-graph-runtime details summary");
    },
  },

  ...["内置 Skills", "MCP 服务", "Agent 编排"].map((tab) => ({
    id: `skills.${tab}`,
    area: "能力",
    enter: async (page: Page) => {
      await goView(page, "能力");
      await page.locator(".capabilities-tabs button", { hasText: tab }).first().click();
      await settle(page);
    },
  })),

  ...["抓包与 HTTPS", "AI 模型", "数据与存储", "MCP 服务"].map((tab) => ({
    id: `settings.${tab}`,
    area: "设置",
    enter: async (page: Page) => {
      await goView(page, "设置");
      await page.locator(".settings-nav > button", { hasText: tab }).first().click();
      await settle(page);
    },
  })),
  {
    id: "settings.all-sections-open",
    area: "设置",
    enter: async (page) => {
      await goView(page, "设置");
      // Clicking changes the set, so re-query rather than iterating a snapshot.
      const summaries = page.locator(".settings-section > summary");
      for (let index = 0; index < await summaries.count(); index += 1) {
        const section = page.locator(".settings-section").nth(index);
        if (await section.getAttribute("open") === null) await summaries.nth(index).click();
      }
      await settle(page, 400);
    },
  },
  {
    id: "settings.search",
    area: "设置",
    enter: async (page) => {
      await goView(page, "设置");
      await page.locator(".settings-search input").fill("证书");
      await settle(page);
    },
  },
  {
    id: "settings.dirty",
    area: "设置",
    enter: async (page) => {
      await goView(page, "设置");
      const field = page.locator(".settings-text-field input").first();
      if (!(await field.count())) return false;
      await field.fill("example.com");
      await settle(page);
    },
  },
  {
    id: "settings.update-dialog",
    area: "设置",
    enter: async (page) => {
      await goView(page, "设置");
      await page.getByRole("button", { name: /检查更新/ }).click();
      await settle(page, 500);
    },
  },

  { id: "browser.default", area: "浏览器", enter: (p) => goView(p, "浏览器") },
];
