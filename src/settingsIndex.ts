/**
 * A searchable index of every settings section.
 *
 * Settings is four tabs of collapsible sections, which means the honest answer
 * to "where do I turn on X" used to be "open all thirteen and read". This index
 * lets one search box answer it directly, and it is also what orders the
 * sections inside a tab — most-needed first, power-user knobs last.
 */

export type SettingsTabId = "capture" | "ai" | "data" | "mcp";

export interface SettingsSectionEntry {
  /** Stable id; also the persistence key for the section's open state. */
  id: string;
  tab: SettingsTabId;
  title: string;
  /** Shown in search results and under a collapsed heading. */
  summary: string;
  /** Lowercase aliases: English terms, symptoms, and the names of inner controls. */
  keywords: string[];
}

export const SETTINGS_TAB_LABELS: Record<SettingsTabId, string> = {
  capture: "抓包与 HTTPS",
  ai: "AI 模型",
  data: "数据与存储",
  mcp: "MCP 服务",
};

/**
 * Order within a tab is the render order. `capture` deliberately leads with the
 * certificate: installing the CA is the single most common thing a new user
 * comes to Settings for, and it used to sit third, collapsed, below the longest
 * section on the page.
 */
export const SETTINGS_INDEX: SettingsSectionEntry[] = [
  {
    id: "capture.https",
    tab: "capture",
    title: "HTTPS 解密",
    summary: "安装 Root CA、选择解密范围、绕过指定域名",
    keywords: ["ca", "cert", "certificate", "root", "https", "tls", "decrypt", "trust", "install", "证书", "解密", "信任", "绕过", "图裂"],
  },
  {
    id: "capture.routing",
    tab: "capture",
    title: "流量路由",
    summary: "监听地址与端口、接管系统代理、绕过域名",
    keywords: ["proxy", "port", "listen", "system", "transparent", "tun", "bypass", "8888", "端口", "系统代理", "透明"],
  },
  {
    id: "capture.devices",
    tab: "capture",
    title: "设备接入",
    summary: "局域网开关、访问范围、手机扫码与 Android 一键配置",
    keywords: ["lan", "device", "mobile", "phone", "android", "ios", "qr", "wifi", "手机", "扫码", "局域网", "设备"],
  },
  {
    id: "capture.upstream",
    tab: "capture",
    title: "出口代理与 TLS 指纹",
    summary: "二级代理、ClientHello 预置、JA3/JA4 自动选档",
    keywords: ["upstream", "socks5", "http_proxy", "ja3", "ja4", "clienthello", "fingerprint", "502", "timeout", "出口", "上游", "指纹", "超时"],
  },
  {
    id: "ai.runtime",
    tab: "ai",
    title: "Agent 运行时",
    summary: "探测或安装 Grok，并配置 ShowNet 进程内的端点、Skill、MCP 与可选出口代理",
    keywords: ["agent", "grok", "runtime", "install", "path", "proxy", "安装", "运行时", "代理"],
  },
  {
    id: "ai.provider",
    tab: "ai",
    title: "分析提供商",
    summary: "API Base URL、API Key、模型选择",
    keywords: ["ai", "api key", "model", "openai", "provider", "base url", "local", "密钥", "模型"],
  },
  {
    id: "ai.strategy",
    tab: "ai",
    title: "分析策略",
    summary: "最大轮次、两阶段分析、MCP 工具调用、流式输出",
    keywords: ["agent", "rounds", "two phase", "mcp tools", "stream", "轮次", "两阶段", "流式"],
  },
  {
    id: "ai.support",
    tab: "ai",
    title: "服务与支持",
    summary: "QQ 群与免费额度申请",
    keywords: ["qq", "support", "free", "quota", "群", "额度"],
  },
  {
    id: "data.database",
    tab: "data",
    title: "会话数据库",
    summary: "存储位置、占用统计、自动清理与保留天数",
    keywords: ["storage", "database", "sqlite", "disk", "retention", "cleanup", "存储", "清理", "占用"],
  },
  {
    id: "data.danger",
    tab: "data",
    title: "危险操作",
    summary: "清除所有会话数据",
    keywords: ["clear", "delete", "reset", "wipe", "清除", "删除"],
  },
  {
    id: "mcp.clients",
    tab: "mcp",
    title: "连接 AI 客户端",
    summary: "Claude Code、Cursor、Codex、VS Code 的接入配置",
    keywords: ["claude", "cursor", "codex", "vscode", "client", "config", "接入", "客户端"],
  },
  {
    id: "mcp.server",
    tab: "mcp",
    title: "ShowNet MCP Server",
    summary: "监听端口、随应用启动、写入型工具开关",
    keywords: ["mcp", "server", "port", "streamable", "http", "tools", "服务", "端口"],
  },
  {
    id: "mcp.auth",
    tab: "mcp",
    title: "认证",
    summary: "访问令牌的查看、复制与轮换",
    keywords: ["token", "auth", "bearer", "rotate", "secret", "令牌", "认证"],
  },
  {
    id: "mcp.external",
    tab: "mcp",
    title: "外部 MCP Servers",
    summary: "接入第三方 Streamable HTTP MCP 服务",
    keywords: ["external", "third party", "remote", "外部", "第三方"],
  },
];

export interface SettingsSearchHit extends SettingsSectionEntry {
  tabLabel: string;
}

/**
 * Match a query against titles, summaries and aliases across every tab, so the
 * user never has to guess which tab owns a setting.
 */
export function searchSettings(query: string): SettingsSearchHit[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  return SETTINGS_INDEX
    .map((entry) => {
      const title = entry.title.toLowerCase();
      let score = -1;
      if (title.includes(needle)) score = title.startsWith(needle) ? 100 : 80;
      else if (entry.keywords.some((keyword) => keyword.includes(needle))) score = 60;
      else if (entry.summary.toLowerCase().includes(needle)) score = 40;
      return { entry, score };
    })
    .filter((hit) => hit.score >= 0)
    .sort((left, right) => right.score - left.score)
    .map((hit) => ({ ...hit.entry, tabLabel: SETTINGS_TAB_LABELS[hit.entry.tab] }));
}

/** Sections belonging to a tab, in render order. */
export function sectionsForTab(tab: SettingsTabId): SettingsSectionEntry[] {
  return SETTINGS_INDEX.filter((entry) => entry.tab === tab);
}

export const SETTINGS_OPEN_SECTIONS_KEY = "shownet.settings.open-sections.v1";

/**
 * Sections a tab opens with when the user has no saved preference. Everything
 * a beginner needs is open; the long power-user sections stay folded.
 */
export const DEFAULT_OPEN_SECTIONS = ["capture.https", "capture.routing", "ai.runtime", "ai.provider", "data.database", "mcp.clients"];

export function parseOpenSections(raw: string | null | undefined): string[] {
  if (!raw) return DEFAULT_OPEN_SECTIONS;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return DEFAULT_OPEN_SECTIONS;
    return parsed.filter((entry): entry is string => typeof entry === "string");
  } catch {
    return DEFAULT_OPEN_SECTIONS;
  }
}
